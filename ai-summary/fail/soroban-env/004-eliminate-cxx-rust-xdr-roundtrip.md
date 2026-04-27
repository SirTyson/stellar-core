# H004: Eliminate Redundant C++↔Rust XDR Roundtrip for Per-Invoke Auth/HostFn/Source/Resources

**Date**: 2026-04-27
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing duplicate XDR serialize-then-deserialize work for inputs that already exist as parsed XDR on the C++ side
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The Soroban host inputs `hostFunction`, `sorobanAuthorizationEntries`, and
the source `AccountId` already exist as parsed xdrpp typed values on the
C++ side (they are members of the parsed transaction envelope). Crossing
the bridge into Rust should not re-serialize them on the C++ side and then
re-deserialize them on the Rust side once per invocation. For a soroswap
apply ledger, where ~4,000 invocations occur, the bridge should pass each
of these inputs once in a form that avoids the per-call XDR roundtrip
(e.g., by exposing the original on-the-wire byte slice from the tx
envelope, by passing a stable arena-allocated byte buffer, or by marshaling
the parsed XDR fields directly through cxx).

## Mechanism

`InvokeHostFunctionOpFrame::invokeHostFunction` calls
`toCxxBuf(mOpFrame.mInvokeHostFunction.hostFunction)`,
`toCxxBuf(mOpFrame.getSourceID())`, and `toCxxBuf(authEntry)` for every
auth entry on every invocation. Each `toCxxBuf` performs
`xdr::xdr_to_opaque(t)` (a recursive XDR write into a fresh
`std::vector<uint8_t>`) and wraps the vector in a `std::unique_ptr`. The
Rust side then performs `metered_from_xdr::<HostFunction>`,
`metered_from_xdr::<AccountId>`, and
`metered_from_xdr::<SorobanAuthorizationEntry>` for each entry —
recursively walking the same fields and reconstructing the typed XDR
values. The two sides use the same wire-format XDR (validated by
`check_xdr_version_identities`), so the byte stream is bit-identical
both before and after the roundtrip; the work is purely redundant.

For soroswap (4,000 invocations per ledger × ≥3 such buffers per
invocation) this amounts to ≥12,000 redundant write+read XDR cycles
per ledger, plus the corresponding allocations.

## Trigger

Run the current `soroswap, TX=4000, T=8` apply-load benchmark from
`ai-summary/CURRENT_STATE.md`. Each invoke-host-function operation
serializes its `hostFunction`, source `AccountId`, and auth entries
into fresh `CxxBuf`s on the C++ side, then `invoke_host_function` on
the Rust side decodes them via `metered_from_xdr`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:560-584` —
  `invokeHostFunction` calls `toCxxBuf(...)` on the parsed
  hostFunction, source account, and every auth entry per invocation.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` performs
  `xdr_to_opaque` plus a `std::make_unique<std::vector<uint8_t>>`
  allocation per call.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:457-459` —
  Rust decodes `host_function`, `source_account`, and auth entries
  via `metered_from_xdr` per invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1056-1065` —
  `build_auth_entries_from_xdr` iterates the encoded auth entries and
  calls `metered_from_xdr::<SorobanAuthorizationEntry>` per entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:41-77` —
  `read xdr` / `read xdr with budget` zones charge `ValDeser` for each
  decode; the trace shows 29,578 calls accounting for ~42 ms self-time
  inside `applyLedger`.

## Evidence

- `read xdr with budget` (`metered_xdr.rs:77`) reports 42,078,593 ns
  self-time across 29,578 calls in the soroswap baseline trace —
  evidence that per-invoke XDR decoding inside Rust is real apply-path
  work, not setup.
- `write xdr` (`metered_xdr.rs:61`) reports 388,067,513 ns self-time
  across 61,830 calls; while H002 already targets the `get_ledger_changes`
  share of these writes, the C++ side `xdr_to_opaque` writes contribute
  separate but symmetric work that is not captured in any apply-path
  Tracy zone.
- `invoke_host_function` (e2e, `e2e_invoke.rs:424`) reports 186,583,657 ns
  self-time across 1,562 calls — about 4% of `applyLedger` time spent in
  the e2e wrapper outside of named child zones. The auth-entry,
  hostFunction, and source-account decode work is in this self-time
  bucket.
- `check_xdr_version_identities` (`src/rust/src/common.rs`) confirms the
  C++ and Rust XDR definitions hash-match, so the roundtripped bytes
  are guaranteed bit-identical and there is no semantic reason to decode
  them twice.

## Anti-Evidence

- The per-call buffers are small (hostFunction / source / auth entries
  are typically <1 KB each), so the per-invocation savings are likely
  in the low microseconds. Reaching the Medium 3% bar (~15 ms per
  soroswap ledger close) requires multiplying small per-call savings
  across 4,000 invocations — plausible but tight.
- xdrpp (C++) and `stellar-xdr` (Rust) have different in-memory layouts
  even though the wire format matches, so the parsed types cannot be
  shared across the bridge by reference. Eliminating the roundtrip
  therefore requires either (a) exposing the original on-the-wire byte
  slice from the tx envelope to avoid the C++ re-serialization, or (b)
  caching parsed forms across calls at one end of the bridge. Both are
  non-trivial structural changes.
- Auth-entry XDR also has an integrity story: stellar-core may rely on
  re-serialization to canonicalize its representation. Any optimization
  must preserve the exact bytes that the host hashes for nonce/auth
  bookkeeping.
- The per-invocation `metered_from_xdr` calls also charge `ValDeser`
  budget; eliminating them changes protocol-visible budget consumption
  unless equivalent charges are inserted at the new code path.

PoC must verify that the optimization (a) preserves all observable
budget consumption and (b) actually removes ≥3% of soroswap apply
time across multiple `run_apply_load_matrix.py` runs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The apply path does serialize per-invocation Soroban inputs on the C++ side: `InvokeHostFunctionOpFrame::doApply` calls `invokeHostFunction`, which wraps auth entries, the host function, resources, and source account in fresh `CxxBuf` byte vectors before crossing the Rust bridge. Rust forwards those buffers through the protocol dispatch layer and the p26 e2e host decodes them into Rust XDR types before invoking the host. However, the proposed optimization conflates removable C++ reserialization with Rust decoding that is still required by the host API and by protocol-visible `ValDeser` metering, and the evidence over-attributes broad XDR profile time to this narrow subset. The real removable work is therefore smaller than the Medium objective threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1000` — `doApply` executes `addFootprint`, `invokeHostFunction`, then storage/effects processing on the apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:560-584` — per invocation, auth entries are serialized with `toCxxBuf`, and host function, resources, and source account are serialized again for `rust_bridge::invoke_host_function`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` constructs a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque(t)`, confirming the C++ write/allocation exists.
- `src/rust/src/bridge.rs:1-15,193-208` — the cxx bridge type for C++ to Rust data is only `CxxBuf { UniquePtr<CxxVector<u8>> }`; there is no typed XDR bridge for `HostFunction`, `AccountId`, `SorobanResources`, or auth entries.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-448` — Rust dispatch preserves the byte-buffer interface through protocol selection and into the protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-459` — resources are decoded with `metered_from_xdr_with_budget`, while auth entries, host function, and source account are decoded with `Host::metered_from_xdr`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-986` — the same `read xdr with budget` zone also decodes each ledger entry and TTL entry, so the cited 29,578 calls / 42 ms are not specific to host function/source/auth and include storage-map construction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1055-1065` — auth entries are decoded one-by-one with `metered_from_xdr::<SorobanAuthorizationEntry>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:40-45,73-81` — `read xdr` and `read xdr with budget` are distinct Tracy zones; the hypothesis cites the latter for work that mostly belongs to resources/ledger entries, not host function/source/auth.
- `src/simulation/ApplyLoad.cpp:760-762,3381-3505` — soroswap has one swap per transaction envelope, each swap builds one source-account auth entry plus a small invoke-contract host function and a footprint of five read-only and five read-write keys.
- `ai-summary/CURRENT_STATE.md:25-33` — the baseline soroswap median apply time is 620.996 ms, so the objective's Medium floor is roughly 18.6 ms per ledger.

### Why It Failed

The hot-path bridge inefficiency is real, but the claimed Medium optimization is not supported. Supplying original transaction byte slices would remove the C++ `xdr_to_opaque`/allocation side only; Rust would still need to decode `HostFunction`, `AccountId`, `SorobanResources`, and `SorobanAuthorizationEntry` into its own XDR types and still needs equivalent `ValDeser` budget charging. Avoiding the Rust decode would require a new typed cxx representation for recursive, versioned XDR structures or a different host API, which would still perform per-field conversion/copying and is not the simple "avoid a redundant roundtrip" described here.

The profile evidence also does not isolate the proposed target. The 42 ms `read xdr with budget` number includes resource decoding and ledger/TTL entry decoding during storage-map construction, while host function/source/auth use the separate `read xdr` zone. The target buffers in the soroswap swap path are comparatively small and consist of one invoke-contract host function, one source account, one source-account auth tree, and one footprint resources object per transaction; eliminating only their C++ serialization is unlikely to clear the 3% / ~18.6 ms Medium threshold. Under the optimize-soroswap objective, Low/sub-threshold findings are rejected, so this hypothesis is NOT_VIABLE.

### Lesson Learned

For this bridge path, distinguish three costs before projecting impact: C++ `xdr_to_opaque` writes, Rust `read xdr` decodes for host function/source/auth, and Rust `read xdr with budget` decodes for resources and ledger/TTL entries. A viable Medium hypothesis needs an isolated measurement or a broader design that removes a measured apply-path portion without changing protocol-visible metering; "the C++ side already parsed it" is not enough because the Rust host still requires native Rust XDR values.
