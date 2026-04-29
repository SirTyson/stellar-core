# H013: Cache Per-Tx Auth-Entry CxxBufs at TxBundle Construction

**Date**: 2026-04-29
**Subsystem**: soroban / transactions
**Severity**: Low
**Impact**: Apply-time reduction in Soroban invoke-host bridge preparation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For an immutable `SorobanAuthorizationEntry` vector that lives inside the
`InvokeHostFunctionOp` envelope, the C++/Rust bridge should serialize each auth
entry to XDR bytes (`CxxBuf`) at most once per transaction lifetime.
Specifically, the `authEntryCxxBufs` vector built inside
`InvokeHostFunctionOpFrame::ApplyHelper::invokeHostFunction` (the parallel
worker hot path) should not redo `toCxxBuf(authEntry)` on every
`applyOperations` call when the underlying envelope is unchanged.

## Mechanism

`InvokeHostFunctionOpFrame::ApplyHelper::invokeHostFunction`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:560-565`) iterates
`mOpFrame.mInvokeHostFunction.auth` and calls `toCxxBuf(authEntry)` for
each entry every time the operation applies. Each call XDR-serializes a
`SorobanAuthorizationEntry` (which contains a recursive
`SorobanAuthorizedInvocation` tree) into a fresh
`std::unique_ptr<std::vector<uint8_t>>`. The auth entries are immutable
across the tx's lifetime; the cached `ParallelApplyLedgerKey` precedent
on `TxBundle` (success #4) already shows that per-tx caches keyed by
TxBundle are correctness-preserving for parallel apply.

## Trigger

Run the soroswap apply-load benchmark. Each Soroban tx with one or more
`SorobanAuthorizationEntry` records pays N XDR encodings per operation
apply. With ~3335 invoke-host operations and roughly 1–5 auth entries per
tx, this is ~5k–17k auth-entry XDR encodings per benchmark run.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:560-565` — per-tx
  auth-entry XDR serialization loop inside `invokeHostFunction`.
- `src/transactions/ParallelApplyStage.h:18-245` — `TxBundle` already
  carries cached per-tx parallel-apply data.

## Evidence

The soroswap diagnostic Tracy trace does not break out an explicit
"toCxxBuf authEntry" zone, but the surrounding `addReads`/`addFootprint`
zones together account for ~275 ms across 6748 invocations
(`addReads` 137 ms + `addFootprint` 138 ms). Auth-entry serialization is
a small fraction of bridge prep; the bound is at most a few hundred
microseconds per tx.

## Anti-Evidence

The fail summary notes that the entire C++/Rust XDR bridge cost
(`004-xdr-bridge-serialization-hotspot`,
`006-cache-encoded-xdr-in-memory-soroban-state`) is well below the 3%
Medium floor. The auth-entry slice is a strict subset of bridge prep.
Even an optimistic estimate (10 µs per encoding × 17k encodings = 170 ms
across the whole benchmark = ~0.4% of total apply time) is below the 1%
Low noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a TxBundle-cached
auth-entry buffer; covered indirectly by the broader bridge-cost fail
entries.

### Why It Failed

Per-tx auth-entry serialization is a strict subset of the C++/Rust XDR
bridge preparation cost. Fail summary item 4 ("XDR Bridge Cost Is
Distributed and Sub-Threshold") establishes that the entire bridge prep
(including `toCxxBuf` for `hostFunction`, `resources`, source ID, and
auth) totals well below the 3% Medium floor. Carving out only the
auth-entry slice cannot reach Medium severity. Even Low severity is
unlikely: with most soroswap-shaped txs carrying 1 source-account auth
credential whose XDR encoding is small (<200 bytes), the per-tx saving
is on the order of microseconds. Multiplied across 3335 txs, the
projected saving is well below the 1% noise floor.

### Lesson Learned

Any per-tx XDR caching hypothesis whose target slice is a subset of the
already-rejected bridge serialization cost should be projected against
that cost first. If the bridge total is ≤2.5% (the upper bound from
fail/004), no individual slice can clear the 3% Medium floor.
