# H080: Eliminate per-ledger footprint walk used only to size `mGlobalEntryMap.reserve`

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Low
**Impact**: apply-thread serial `GlobalParallelApplyLedgerState` construction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState`'s constructor
(`src/transactions/ParallelApplyUtils.cpp:386-429`) opens with a
double-nested loop over stages × txBundles (lines 405-417) whose sole
purpose is to compute `estimatedEntries` for a single
`mGlobalEntryMap.reserve(estimatedEntries)` call. The estimate is
`Σ_tx (readWrite.size() * 2 + readOnly.size() * 2 + 1)` — i.e. an upper
bound that double-counts every footprint key plus the source account.
The expected correct behavior is to size the map so subsequent inserts in
`collectModifiedClassicEntries` and
`fetchSorobanReadOnlyEntries from footprints` (plus thread merge-back)
do not trigger repeated rehashes during the lifetime of the global
state.

The hypothesized change is to replace the per-bundle walk with a single
cheap upper-bound estimate computable in `O(1)` from
`stage.numTransactions()` summed across stages, or a fixed
`reserve(2 * numTxs * MAX_FOOTPRINT_KEYS + numTxs)`-style bound, removing
the explicit walk while preserving the rehash-avoidance benefit.

## Mechanism

The current code performs an O(numTxs × footprintSize) walk just to
compute a size hint. The bundle count and the per-tx footprint sizes are
already known to the tx-set framework when stages are constructed; a
much cheaper bound (e.g. `numTxs * (MAX_RW_KEYS + MAX_RO_KEYS) * 2 + numTxs`)
would still avoid all rehashing without touching every footprint vector.
Removing the inner walk shaves a small constant fraction of the apply-thread
serial preamble before parallel cluster dispatch.

## Trigger

Every Soroban ledger that has at least one parallel Soroban phase
constructs `GlobalParallelApplyLedgerState` exactly once, and thus
executes the estimate loop. The soroswap apply-load benchmark
exercises this path on every benchmark ledger with Soroban activity.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:405-417` — the estimation loop.
- `src/transactions/ParallelApplyUtils.cpp:386-429` — the
  `GlobalParallelApplyLedgerState` constructor surrounding the loop.

## Evidence

- The work is purely apply-thread-serial and runs before
  `applySorobanStageClustersInParallel`, so any saving directly
  shortens the gap between `applyTransactions` start and the parallel
  workers being launched.
- The loop's only purpose is a single `reserve()` call; the
  walked data is not retained.

## Anti-Evidence

- The constructor's enclosing work (footprint walk, `reserve`,
  `preParallelApplyAndCollectModifiedClassicEntries` setup) does not
  appear as a distinct hot Tracy zone in the soroswap baseline. The
  smallest enclosing measured zone is
  `applySorobanStages` minus `applySorobanStageClustersInParallel`,
  which is ~63 ms total across 43 stages = ~1.46 ms/stage of all
  surrounding orchestration (constructor + per-stage commit + thread
  destruction + final commitChangesToLedgerTxn + destruction).
- The estimate loop is a small fraction of that ~1.46 ms/stage
  envelope. Even attributing the entire 1.46 ms to the constructor
  preamble and recovering all of it gives 1.46 ms × 43 stages /
  71 ledgers ≈ 0.88 ms/ledger = **0.42%** of the 207 ms soroswap
  median. The estimate loop's actual share is materially smaller
  (sub-100 µs/ledger order of magnitude).
- Removing the precise `reserve` and replacing it with a coarse
  upper-bound triggers slightly more capacity overshoot, which can
  cost memory bandwidth on a hot map; for `UnorderedMap` with default
  load factor the rehash thresholds are already conservatively above
  the precise estimate, so any benefit from the precise bound is
  marginal.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — no existing fail/hypothesis/reviewed/poc file targets
the `GlobalParallelApplyLedgerState` constructor's estimate loop. Prior
investigations of constructor cost (`001-parallelize-cluster-state-setup`,
`001-parallelize-thread-state-construction`) targeted the per-cluster
`ThreadParallelApplyLedgerState` construction, not the per-ledger global
state construction's estimate walk.

### Why It Failed

Below objective severity threshold by 1–2 orders of magnitude. The
estimate loop is well under 100 µs/ledger and even fully eliminating
it cannot move the apply-time needle by 1%, let alone the 3% Medium
floor. The current precise reserve is correctness-equivalent to a
coarse upper bound but more memory-efficient; the proposed change
trades a small CPU saving for a small memory overshoot and does not
clear the noise floor.

### Lesson Learned

The `GlobalParallelApplyLedgerState` constructor preamble (estimate
loop, `mGlobalEntryMap.reserve`, snapshot moves) sits in the same
sub-millisecond bucket as the other rejected per-ledger setup phases.
Future per-ledger setup optimizations must measure the absolute Tracy
self-time of the *combined* preamble (not individual sub-steps)
against the 3% Medium floor; piecemeal removal of small allocations
inside the constructor cannot reach threshold.
