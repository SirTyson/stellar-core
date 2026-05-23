# H013: Run Cluster 0 Inline on the Apply Thread Instead of std::async

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Low (below objective threshold)
**Impact**: apply-time critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStageClustersInParallel` (`ledger/LedgerManagerImpl.cpp:2531`)
should fully utilize the apply thread while parallel workers run. Currently
the apply thread spawns `stage.numClusters()` `std::async` futures (one per
cluster, up to `NUM_CLUSTERS=8`) and then blocks in `future.get()` until each
completes. If instead the apply thread executed one cluster inline (e.g.,
cluster 0) after spawning the other 7 futures, it would do useful critical-
path work rather than idling on `future.get()`. The critical path would then
be `max(apply-thread-cluster, slowest-of-7-async-clusters)` instead of
`slowest-of-8-async-clusters`.

## Mechanism

Today the apply thread waits idle from after `std::async` launch through the
slowest cluster's completion. With balanced clusters (the soroswap benchmark
deliberately creates 8 balanced pair-component clusters per ledger), the wait
is ~50 ms × 1 (longest cluster). Running cluster 0 inline would let the apply
thread amortize ~12.5% of the parallel work it currently waits on.

## Trigger

Soroban-dominated workload with `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS=8`
and equal cluster sizes (the soroswap benchmark shape).

## Target Code

- `ledger/LedgerManagerImpl.cpp:2531-2575` `applySorobanStageClustersInParallel`
  — spawn N-1 futures, call `applyThread` inline for cluster N-1, then
  `future.get()` the remaining N-1 results.
- `ledger/LedgerManagerImpl.cpp:applyThread` — the worker function would be
  invoked directly on the apply thread for one cluster.

## Evidence

- Tracy `applySorobanStageClustersInParallel` self-time = 2,691,904,192 ns
  (26.17%); inclusive total 2,748,978,969 ns (26.72%). The self-time accounts
  for the `future.get()` block on the slowest cluster.
- soroswap benchmark uses exactly 8 balanced clusters per ledger; per-cluster
  worker time is approximately uniform.
- Maximum theoretical recovery: 1/N of the parallel-cluster envelope shifts
  from idle wait to productive work. For NUM_CLUSTERS=8 on the soroswap
  shape, that is at best 1/8 ≈ 12.5% of `applySorobanStageClustersInParallel`
  self-time, i.e. ~336 ms across the 71-call trace ≈ ~4.7 ms/ledger steady
  state.

## Anti-Evidence

- 4.7 ms/ledger ÷ 218 ms/ledger soroswap median = ~2.1% — below the 3% Medium
  threshold and inside the Low-not-accepted band.
- This optimization is **structurally equivalent** to ai-summary/fail/
  transaction-ledger/060-apply-thread-co-runs-one-cluster.md, which was
  rejected on a stronger basis: that record claimed the launch overhead
  difference was the only saving, but the actual ceiling (parallelization
  efficiency) is what dominates.
- Realistic saving is even smaller than 12.5%: the apply thread also has
  pre/post-stage serial work (`collectModifiedClassicEntries`,
  `commitChangesFromThreads`) that bounds the overlap window. After
  accounting for those serial bookends, the apply thread can co-run only
  a fraction of one cluster's time before it must rejoin.
- The `LedgerEntryScope` discipline currently assumes worker threads have
  their own `ThreadParallelApplyLedgerState`; running one cluster on the
  apply thread requires verifying the scope adoption/deactivation discipline
  also works when the apply thread temporarily holds a `ThreadParApply`
  scope.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PARTIAL — close duplicate of fail/060-apply-thread-co-runs-one-cluster.md;
this revision tightens the impact ceiling (12.5% of cluster envelope rather
than launch-overhead delta) but reaches the same NOT_VIABLE conclusion.

### Why It Failed

The maximum theoretical recovery is bounded by `1/NUM_CLUSTERS` of the
parallel-cluster wall time. For the soroswap shape this is 2.1% of apply
time, below the 3% Medium floor. The realistic saving is smaller still
because (a) the apply thread has serial pre/post-stage work that limits the
overlap window, and (b) cluster timing variance on balanced soroswap
clusters is small, so the apply-thread inline cluster will not finish
materially before the slowest async cluster. Meta-pattern #6 (aggregate
worker time must be divided by cluster count) applies in reverse here:
recovering 1/N of a parallel envelope cannot clear Medium when the envelope
is already at the cluster-parallelism ceiling.

### Lesson Learned

For NUM_CLUSTERS-bounded parallel apply, the apply-thread-inline-cluster
optimization is capped at `1/N` of the parallel envelope. On soroswap that
ceiling is ~2%. Future "recover idle apply-thread time" hypotheses must
demonstrate a saving larger than `parallel_envelope / NUM_CLUSTERS` to clear
Medium — typically this requires the apply thread to co-run useful work
that is NOT a cluster (e.g., next-ledger setup overlapped across the
closeLedger boundary, which is independently blocked by post-apply commit
ordering).
