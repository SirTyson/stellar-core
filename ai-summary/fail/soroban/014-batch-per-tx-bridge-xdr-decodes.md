# H014: Batch Per-Tx Bridge XDR Decodes (`host_function` + `auth_entries` + `source_account`) in `invoke_host_function`

**Date**: 2026-05-27
**Subsystem**: soroban / Rust bridge entry
**Severity**: Low (below objective severity threshold)
**Impact**: per-tx Rust-side XDR decode reduction at `e2e_invoke::invoke_host_function` entry
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each soroswap transaction enters
`soroban_env_host::e2e_invoke::invoke_host_function` and immediately
performs three separate `metered_from_xdr` decodes — the encoded
`HostFunction` (line 529), the encoded `Vec<SorobanAuthorizationEntry>`
(line 528, via `build_auth_entries_from_xdr` at lines 1155-1164), and
the encoded `AccountId` source account (line 530). On the C++ side
these were just freshly XDR-encoded into `RustBuf` byte buffers in
`InvokeHostFunctionParallelApplyHelper::invokeHostFunction`. The
expected per-tx XDR-bridge cost should be a fraction of the apply path
and decoding the three independent buffers in sequence should not
dominate.

## Mechanism

For every soroswap invoke-host-function transaction
(~2000 txs/ledger), three independent `metered_from_xdr` calls cross
the bridge per tx, each charging budget for byte-by-byte typed XDR
unmarshalling plus per-call setup cost:

- `host_function: HostFunction` — typically a `InvokeContract`
  containing the contract `Address`, the function `Symbol` (`swap`),
  and a small `Vec<ScVal>` of args (a few addresses + i128 amounts).
- `auth_entries: Vec<SorobanAuthorizationEntry>` — typically a single
  entry per soroswap tx with `SOURCE_ACCOUNT` credentials and a nested
  `AuthorizedInvocation` tree describing the router/pool/SAC calls
  the user is authorizing.
- `source_account: AccountId` — a 32-byte public-key wrapper.

A bridge-side batched decode could fuse the three buffers into a single
`(HostFunction, Vec<SorobanAuthorizationEntry>, AccountId)` tuple
serialized once on the C++ side and decoded once on the Rust side,
amortizing call-setup cost and a single `metered_from_xdr` invocation
charge.

## Trigger

Every soroswap apply window. `invoke_host_function` is called once per
`InvokeHostFunctionOpFrame::doParallelApply`, i.e. once per soroban tx
(~2000 per ledger × 5 measured ledgers).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:519-533` —
  per-tx XDR decode entry; the three `metered_from_xdr` calls live in
  consecutive statements.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1155-1164` —
  `build_auth_entries_from_xdr` walks each encoded auth entry buffer.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:870-1080` —
  C++ side `invokeHostFunction` constructs the encoded buffers
  passed across the bridge.

## Evidence

- Three serial `metered_from_xdr` calls per tx × ~2000 txs/ledger =
  6 000 XDR-decode entry-point calls per measured ledger across all
  clusters; per-cluster ≈ 750. Each call has fixed setup cost
  (budget charge, FFI bridge overhead) on top of the byte-walking
  decode cost.
- For soroswap the `Vec<SorobanAuthorizationEntry>` is typically a
  single entry whose nested `AuthorizedInvocation` tree has several
  sub-invocations; the typed decode walks the entire tree.

## Anti-Evidence

- Meta-pattern 4 explicitly caps the XDR bridge contribution:
  > XDR bridge cost is distributed and sub-threshold: C++/Rust XDR
  > bridge preparation (`toCxxBuf`, `addReads`) for soroswap is a real
  > but distributed cost that totals well below the 3% Medium floor.
- The `addReads` zone is documented at 0.19% of apply (per
  prior fail records); per-tx `metered_from_xdr` of three small
  buffers is the same order of magnitude.

## Sizing Against Objective Severity

- Per the bridge cost cap (~2.5%), the *upper bound* of all per-tx
  Rust-side bridge decode work is below the 3% Medium floor.
- The three decodes here are a subset of the bridge cost, sized as
  `(host_function + auth_entries + source_account) / total_bridge`,
  conservatively ≤50% of bridge cost = ≤1.25% of apply.
- Batching cannot remove the byte-walking cost (still the dominant
  per-decode cost), only the call-setup overhead. Achievable saving
  is well below the Low (1%) floor.
- Per the objective's severity gate, this falls in the
  "below objective severity threshold (Low not accepted at hypothesis
  stage)" bucket.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-27
**Failed At**: hypothesis
**Novelty**: PASS — prior bridge rejections covered `toCxxBuf` /
`addReads` / `recordStorageChanges` / `collectEvents`; the per-tx entry
decode trio in `invoke_host_function` is a narrower, previously
unexamined slice of the same bridge.

### Why It Failed

Bounded by meta-pattern 4 (XDR bridge cost is structurally
sub-Medium for soroswap, total bridge work ≤2.5% of apply). Batching
removes only call-setup overhead, not the byte-walking decode cost,
so the achievable saving is far below the Low floor. Pinning down
the exact per-call setup cost would require a fresh Tracy trace
(current trace path no longer on disk per CURRENT_STATE.md), but
even an unrealistically optimistic estimate (eliminate 100% of
setup cost on every decode) cannot clear the 1% Low floor given the
upper-bound cap.

### Lesson Learned

Per-tx XDR bridge decodes at the Rust entry point are bounded by the
overall bridge cost cap. Any future optimization at this layer must
either (a) eliminate the byte-walking decode itself (e.g., by passing
already-decoded structs across the bridge, which is a much larger
architectural change), or (b) target a different non-bridge zone.
Setup-cost amortization at this layer is structurally sub-Low.
