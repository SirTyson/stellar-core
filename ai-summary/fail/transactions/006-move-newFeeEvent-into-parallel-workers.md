# H006: Move `newFeeEvent` emission from serial `applyParallelPhase` bundle-build loop into parallel `applyThread` workers

**Date**: 2026-05-26
**Subsystem**: transactions
**Severity**: Low
**Impact**: serial bundle-build loop shortening (sub-noise)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The serial `applyParallelPhase` bundle-build loop should perform only
work that genuinely must precede thread dispatch — i.e. constructing
`TxBundle`/`TxEffects`/`TransactionMetaBuilder` so cluster workers can
operate on stable per-tx state. Per-tx work that does not depend on
shared serial state should run on the parallel worker threads to keep
the apply critical path narrow.

## Mechanism

`LedgerManagerImpl::applyParallelPhase` (LedgerManagerImpl.cpp:2967)
contains a serial three-level loop over (stage, cluster, tx) that
constructs `TxBundle`s and, for every tx, immediately calls
`applyCluster.back().getEffects().getMeta().getTxEventManager().newFeeEvent(
   tx->getFeeSourceID(), mutableTxResult->getFeeCharged(),
   TRANSACTION_EVENT_STAGE_BEFORE_ALL_TXS)`
(lines 3008-3015). The `newFeeEvent` call only mutates the per-tx
`TxEventManager` owned by the per-tx `TransactionMetaBuilder`; it does
not depend on any other tx's state and has no cross-tx ordering
constraint within a cluster. It could therefore be moved into
`applyThread` (LedgerManagerImpl.cpp:2484) and run on the parallel
worker thread before `parallelApply`, shortening the serial bundle-build
critical path.

## Trigger

Run apply-load soroswap. The serial bundle-build loop runs once per
ledger before `applySorobanStages` blocks the main thread on cluster
workers.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2967-3032` — `applyParallelPhase`
  serial bundle-build loop (parent of the `newFeeEvent` calls)
- `src/ledger/LedgerManagerImpl.cpp:3008-3015` — per-tx `newFeeEvent`
  emission site
- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread` per-tx
  cluster loop (candidate new home for the `newFeeEvent` call)
- `src/transactions/EventManager.h/.cpp` — `TxEventManager::newFeeEvent`

## Evidence

Tracy zones (soroswap, 71 ledgers):
- `applyParallelPhase` 3,019,511,395 ns (29.39% of applyLedger)
- `applySorobanStages` 3,012,151,266 ns (29.32% of applyLedger)
- `applyParallelPhase` self-time (bundle-build serial loop)
  = 3,019,511,395 − 3,012,151,266 = 7,360,129 ns = 0.072% of applyLedger

Total bundle-build serial-loop budget is 7.36 ms over 71 ledgers ≈
0.10 ms/ledger. Spread across ~200 txs/ledger, `newFeeEvent` work is a
small fraction of this 7.36 ms.

## Anti-Evidence

1. **Parent zone budget is strictly capped at 0.072% of applyLedger.**
   Even if `newFeeEvent` were 100% of the bundle-build self-time, moving
   it to workers would save only ~7 ms (0.07%) — far below the 1%
   noise floor, let alone the 3% Medium threshold.

2. **Adjacent fail records already cover this area.** Fail
   `011-cache-native-asset-contract-info-for-newfeeevent.md` rejected
   caching `AssetContractInfo` inside `newFeeEvent` on identical
   grounds (bundle-build self-time is 0.05–0.20% of close time). Fail
   `004-parallelize-bundle-build-loop.md` rejected moving the entire
   bundle-build loop onto workers for the same reason.

3. **Mechanism risk for tiny win.** Calling `newFeeEvent` on a worker
   thread requires verifying that `TxEventManager` mutation is safe
   off the apply thread (no shared event sink, no global tracker
   touched). The complexity is non-trivial relative to the ≤7 ms
   addressable surface.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — `newFeeEvent` relocation as a separate proposal from
the `AssetContractInfo` cache and the broader bundle-build parallelization
is not in fail/, hypothesis/, reviewed/, or poc/.

### Why It Failed

`applyParallelPhase` serial bundle-build self-time is 0.072% of
`applyLedger` for soroswap. Any per-tx relocation from this serial loop
is strictly bounded by this self-time and cannot reach Medium or even
the 1% noise floor. The `newFeeEvent` call is one of several per-tx
operations within this loop and is at most a fraction of the 7.36 ms
total budget.

### Lesson Learned

Per-tx relocations out of the `applyParallelPhase` bundle-build serial
loop are exhaustively sub-noise: the entire loop self-time is ≤0.1% of
`applyLedger`. Apply Meta-Pattern 9 (Pre-Parallel-Apply Phase Is Thin)
and Meta-Pattern 15 (Apply-Phase Per-Tx Micro-Costs Are Exhaustively
Sub-Threshold) to any future hypothesis that proposes hoisting per-tx
work from the bundle-build loop; the parent-zone cap is the controlling
constraint.
