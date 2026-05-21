# H025: Add `mRoTTLBumps.empty()` fast path to `flushRoTTLBumpsInTxWriteFootprint`

**Date**: 2026-05-21
**Subsystem**: ledger / parallel apply
**Severity**: Low
**Impact**: ~0.1% wall-clock savings per applyLedger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a soroswap cluster has no read-only TTL bumps accumulated from prior txs
in `mRoTTLBumps`, the pre-tx call to
`ThreadParallelApplyLedgerState::flushRoTTLBumpsInTxWriteFootprint` should be
a near-zero-cost no-op: there is nothing to flush, so no per-tx footprint walk
is required.

## Mechanism

`flushRoTTLBumpsInTxWriteFootprint` (src/transactions/ParallelApplyUtils.cpp:1004)
is called once per tx in the cluster from `applyThread`
(src/ledger/LedgerManagerImpl.cpp:2502) and unconditionally iterates the tx's
read-write footprint, calling `isSorobanEntry(lk)`, `getTTLKey(lk)` (a SHA256
on the encoded key), and constructing `ParallelApplyLedgerKey(ttlKey)` before
probing the map. In soroswap clusters where no prior tx produced an RO TTL
bump for an entry referenced by the current tx's RW footprint,
`mRoTTLBumps.find(...)` returns `end()` and the entire walk is wasted work.

The intended fast path — early-return when `mRoTTLBumps.empty()` — would skip
all per-RW-key SHA256 + key-construction work when there is nothing to flush.

## Trigger

Soroban-only ledgers where RO TTL bumps from prior cluster txs don't intersect
the current tx's RW footprint (common in soroswap, where RW sets are isolated
to a single pair contract's storage and RO sets cover SAC instance/code keys).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1004-1039` —
  `ThreadParallelApplyLedgerState::flushRoTTLBumpsInTxWriteFootprint`: needs
  an `if (mRoTTLBumps.empty()) return;` guard before the per-RW-key loop.
- `src/ledger/LedgerManagerImpl.cpp:2502` — caller, once per tx in
  `applyThread` loop.

## Evidence

Tracy soroswap trace
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`:

- `applyLedger` total = 5230 ms across 71 ledgers (73.7 ms/ledger).
- `parallelApply` aggregate worker time = 12.67 s (178 ms/ledger);
  effective parallelism vs `applySorobanStageClustersInParallel` wall
  (3.46 s, 48.7 ms/ledger) = 3.65×.
- Per ledger: ~95 Soroban txs / 8 clusters = ~12 txs/cluster. Per tx:
  ~3 RW entries (typical soroswap swap touches pair contract pool state).
- Wasted work per cluster: 12 txs × 3 RW × ~1 µs (SHA256 + map probe) ≈
  36 µs aggregate.
- Per ledger across 8 clusters: ~288 µs aggregate / 3.65 effective
  parallelism ≈ 79 µs wall, ~0.1% of applyLedger.

## Anti-Evidence

The cost is real but tiny because (a) per-tx RW footprints are small for
soroswap (~3 entries), and (b) the existing code already returns immediately
on each miss (`b == mRoTTLBumps.end()`). The only saving is the SHA256 and the
`ParallelApplyLedgerKey` construction — both already optimized.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage). Per
ledger wall-clock savings ≈ 79 µs against a 73.7 ms `applyLedger` window =
0.1%, well below the objective's 3% Medium floor and below the 1% Low floor
(itself below benchmark noise). Even with very pessimistic per-RW-key cost
estimates (e.g., 5 µs each instead of 1 µs), the savings would top out near
0.5% — still sub-Low. The mechanism is correct and the diff would be
one-line-clean, but no realistic per-key cost gets this above the threshold
on soroswap's small per-tx RW footprints.

### Lesson Learned

Even when a code path has a literally wasted-work loop, the per-tx RW
footprint size in soroswap (~3 entries) and the small per-cluster tx count
(~12) bound the total saving. Always multiply (tx-count × per-tx work-items ×
per-item cost) and normalize by parallelism before drafting; for soroswap,
fast-path guards in the parallelApply per-tx hot loop need per-item costs in
the tens-of-µs range to clear the Medium floor.
