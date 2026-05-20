# H038: Pre-encode SorobanResources Once per Tx Instead of per InvokeHostFunctionOp

**Date**: 2026-05-20
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanResources` is a per-transaction immutable XDR struct attached to the
`InvokeHostFunctionOp`'s parent `TransactionFrame`
(`mOpFrame.mParentTx.sorobanResources()`,
`src/transactions/InvokeHostFunctionOpFrame.cpp:322`). Its contents — the
declared `instructions`, the read-only and read-write footprints (each a
`VecM<LedgerKey, 1000>`), and the disk-read/write byte counts — are fixed at
tx-construction time and never mutated during apply. The expected behaviour
is that the XDR-encoded byte form of `SorobanResources` is computed at most
once per transaction and reused across any apply-path operations that need
to hand it to the Rust host.

## Mechanism

The current code at
`src/transactions/InvokeHostFunctionOpFrame.cpp:580` calls
`toCxxBuf(mResources)` *inline inside the apply-time `invokeHostFunction`
method*, which freshly XDR-encodes the entire `SorobanResources` struct on
every `InvokeHostFunctionOp::doApply`. For soroswap with 2000 ops/ledger and
footprints of ~10-30 `LedgerKey` entries per tx (each ~50-200 bytes after
XDR padding), this re-encodes ~100-500 KB of repetitive XDR data per
ledger. The deviation from "encode once per tx" is a per-op cost of
walking the same `SorobanResources` graph and emitting it through xdrpp's
buffered marshaller. A pre-encoded `CxxBuf` cached on `TransactionFrame`
(or on the parent op-batching context) would eliminate this per-op work
entirely.

## Trigger

Apply soroswap ledgers (TX=2000, T=8). Each `invokeHostFunction` call
re-encodes `mResources` from scratch even though there is exactly one
`SorobanResources` per parent tx and `InvokeHostFunctionOp` is the sole
op type per soroban tx.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:580` — `toCxxBuf(mResources)`
  per-op encoding
- `src/transactions/InvokeHostFunctionOpFrame.cpp:290` — `mResources` is a
  `SorobanResources const&` reference into the parent tx, immutable for the
  apply duration

## Evidence

- `SorobanResources` is immutable per tx and could be encoded once at
  tx-set-prepare time or memoized on `TransactionFrame`.
- Soroswap exercises 2000 invokes/ledger × ~1 KB encoded SorobanResources ≈
  2 MB of per-ledger XDR work that is structurally redundant.
- The encoding goes through `xdr::xdr_to_msg`-style allocation and copy
  (`toCxxBuf` constructs a fresh `std::unique_ptr<std::vector<uint8_t>>`),
  so the savings include both CPU and per-op allocation pressure.
- The Rust side decodes this same data on every call via
  `non_metered_xdr_from_cxx_buf::<SorobanResources>` (in soroban-env-host
  e2e_invoke), so the decode side does not benefit, but the *encode* side
  is squarely on the apply critical path.

## Anti-Evidence

- Meta-Pattern 8: "Bridge input overhead (~22ms across the trace) and
  C++-side output decode overhead (~28ms) together total ~50ms." This
  ceiling already incorporates per-op `SorobanResources` encoding cost;
  even total elimination of the encode share is structurally bounded
  below ~22ms total per soroswap run = ~0.34ms/ledger ≈ 0.12% of apply.
- Memoizing on `TransactionFrame` requires storing a `CxxBuf` (which owns a
  `std::unique_ptr<std::vector<uint8_t>>`) on the const-borrowed parent tx,
  which conflicts with the existing immutability invariants and would
  require a `mutable` member or a separate per-tx encoding-cache layer.
- A pre-encoded buffer must still be moved/cloned into the per-op call site
  because `CxxBuf` is consumed by-value across the bridge; this re-introduces
  allocation cost unless the bridge signature also changes to take
  `&CxxBuf`, which is the same change H006 already proposed and was
  rejected.
- Tx-set construction already walks `SorobanResources` for surge pricing
  and validation (`commonValidPreSeqNum`), but those phases run before
  apply and are out of objective scope; their pre-existing presence means
  the field is already touched outside apply, but pre-encoding there
  conflates tx-set construction (out of scope) with apply (in scope).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc entry targets
`SorobanResources` per-op encoding specifically. H006 covered small fixed
bridge-input borrow (`resources` was named but the proposal was about
borrow-vs-value, not pre-encoding), so this pre-encoding/memoization angle
is distinct.

### Why It Failed

Meta-Pattern 8 establishes that the entire C++-side bridge input encoding
share across the trace is bounded at ~22ms (≈0.07% of apply when normalized
across the 65-ledger soroswap run, ≈0.34ms/ledger). `SorobanResources`
encoding is one of several inputs encoded per-op (footprint, host function,
auth entries, source account, prng seed); it is a fraction of that 22ms.
Even total elimination of `SorobanResources` encoding cannot reach the 1%
Low floor, much less the 3% Medium minimum required for promotion to
review. The structural ceiling holds regardless of how cleanly the
memoization is implemented.

### Lesson Learned

Per-tx XDR struct encodings on the bridge input side are bounded by
Meta-Pattern 8's ~22ms input ceiling. Apply-path XDR encoding hypotheses
that target a single sub-share of this ceiling (e.g. one XDR struct out of
the five encoded per `invoke_host_function` call) cannot reach Medium
severity. A viable bridge-encoding hypothesis must either (a) target the
*sum* of per-op encodings via a structural redesign that eliminates the
encode/decode round-trip entirely (e.g. shared-memory or zero-copy struct
exchange), or (b) target an encoding site outside this ceiling (e.g. a
much higher-frequency per-entry encoding measured separately).
