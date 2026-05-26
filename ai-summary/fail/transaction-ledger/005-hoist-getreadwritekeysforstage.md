# H005: Hoist getReadWriteKeysForStage out of commitChangesFromThreads

**Date**: 2026-05-25
**Subsystem**: transaction-ledger (ParallelApplyUtils / LedgerManagerImpl)
**Severity**: Low
**Impact**: redundant per-stage RW key set construction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The set of RW keys for an `ApplyStage` is derivable purely from the static
footprints of its txs and does not change once the stage is built. It should
therefore be computed at most once per stage and reused across both cluster
construction and the post-cluster commit-back to the global state, rather
than being re-derived during the commit phase.

## Mechanism

`src/transactions/ParallelApplyUtils.cpp:917` calls `getReadWriteKeysForStage`
inside `GlobalParallelApplyLedgerState::commitChangesFromThreads`, which loops
all txs in the stage and inserts each RW key plus its TTL key into an
`unordered_set`. The data is consumed only to disambiguate true RW writes
from RO TTL bumps in `maybeMergeRoTTLBumps`. The same information is
materially implied by the per-cluster `mFootprint` data already produced
during `applySorobanStageClustersInParallel` (`src/ledger/LedgerManagerImpl.cpp:2530`).
The set could be built once at stage-setup time and passed by reference.

## Trigger

Profile `commitChangesFromThreads` zone in soroswap apply-load trace.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:105-132` — `getReadWriteKeysForStage`
  iterating all txs to build set.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `commitChangesFromThreads`
  the caller.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — sibling
  `applySorobanStageClustersInParallel` where the set could be built once.

## Evidence

- `getReadWriteKeysForStage` Tracy self-time: ~0.7 ms / ledger (per prior
  measurement in this session).
- `commitChangesFromThreads` self-time: ~0.85 ms / ledger.
- Each soroswap stage has ~2000 txs × ~4 RW keys = ~8K emplaces into an
  `unordered_set`, all done serially on the apply thread.

## Anti-Evidence

- The set is consumed only once per stage, so amortization gain is bounded
  to a single call elimination.
- `unordered_set::reserve` is already used to pre-size the table.
- The work is on the apply thread but parallel-cluster construction does
  similar per-cluster work; hoisting saves only one pass.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — fail summary has entries on `commitChangesFromThreads`
parallelism (#044, #048, #061, #165) but not specifically about hoisting
`getReadWriteKeysForStage`.

### Why It Failed

Best-case savings = ~0.7 ms / ledger if the function is completely
eliminated. On a 207 ms soroswap apply baseline, that is 0.34% — below the
1% noise floor and an order of magnitude below the 3% Medium gate. Even
combined with the commit zone (0.85 ms self), total ~1.5 ms / ledger =
0.7%, still below threshold. This is sub-Low.

### Lesson Learned

For commit/finalize zones that run on the apply thread but operate on
already-finished cluster output, look at *total* zone cost as a critical-path
ceiling — these do not benefit from the ÷NUM_CLUSTERS normalization that
worker zones get. But also: any single such zone that's already sub-millisecond
cannot generate a Medium win; only a redesign that collapses multiple commit
zones into one pass could (and #044/#048 already failed on that angle).
