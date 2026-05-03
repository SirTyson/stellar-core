# H002: Reuse a fixed Soroban apply worker pool instead of launching `std::async` threads per stage

**Date**: 2026-05-03
**Subsystem**: transaction-ledger / ledger parallel Soroban apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing per-stage worker launch/scheduling overhead while preserving deterministic cluster execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban apply stage should execute the same clusters, with transactions in each cluster applied in the same order and with results merged in the same deterministic cluster order. The implementation should not create and destroy a fresh OS worker task for every cluster of every stage when the configured parallelism is already capped by `ledgerMaxDependentTxClusters` / `NUM_CLUSTERS`.

A correct optimization would keep at most the configured cluster count of workers alive for the apply phase, dispatch each stage's cluster jobs to those workers, and collect `ThreadParallelApplyLedgerState` results by cluster index before committing them in the existing order.

## Mechanism

`applySorobanStageClustersInParallel` currently constructs a `ThreadParallelApplyLedgerState` and immediately launches `std::async(std::launch::async, ...)` for every cluster in the stage, then waits on all futures. In the soroswap shape, the hot ledger has a single dominant parallel stage with eight true-conflict clusters, so per-cluster `std::async` launch, scheduler handoff, and thread teardown sit directly on the stage critical path before `applySorobanStage` can commit results.

A fixed worker pool owned for the duration of `applySorobanStages` (or the apply thread's lifetime) can remove this per-stage launch cost without changing ledger semantics. Jobs would be submitted with their cluster index, each worker would run the existing `applyThread` body for exactly one cluster at a time, and the main apply thread would place returned thread states into a vector indexed by cluster number before calling `commitChangesFromThreads`.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and add narrow Tracy zones around `ThreadParallelApplyLedgerState` construction, `std::async` launch, first instruction inside the worker, and `future.get()`. The hypothesis is triggered by the normal soroswap stage where `applySorobanStageClustersInParallel` launches one worker task per cluster and then waits for all cluster workers to finish.

Implement a fixed-size worker pool capped at `stage.numClusters()` and never above the configured `NUM_CLUSTERS`; preserve `applyThread`'s per-cluster transaction order and return results by original cluster index. Compare three non-Tracy matrix runs against the accepted baseline.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies each transaction in a cluster sequentially and returns the completed `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs per-cluster state, launches `std::async` once per cluster, then waits on each future.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` waits for cluster workers, runs invariant checks, commits thread changes, and destroys thread states.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` construction collects each cluster footprint from the global state before worker execution.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `commitChangesFromThreads` folds completed thread states after all workers finish; result collection must preserve the existing cluster order.

## Evidence

Current Tracy validation from the recorded soroswap trace shows `applySorobanStageClustersInParallel` inside the `applyLedger` subtree with **3,455,290,270 ns self-time** over 43 calls, mean **80.356 ms**, max **496.820 ms**, and high variance (**185.811 ms stddev**). In the longest `applyLedger` window, there is one dominant Soroban stage: `applyLedger` lasts **589.101 ms**, while `applySorobanStageClustersInParallel` spans **496.771 ms** of that window. The enclosing path is `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStage`.

The source uses `std::async(std::launch::async, ...)` in a loop rather than reusing existing workers. Even if most of the zone's time is legitimate worker execution behind `future.get()`, thread launch and scheduler handoff are still serially initiated once per cluster and are paid in every hot stage. With eight clusters, eliminating only a few milliseconds of launch/scheduling overhead per cluster is plausibly a Medium soroswap win, especially if it also reduces the high variance visible in the stage zone.

Determinism is preserved because the optimization does not split clusters or reorder transactions inside a cluster. It only changes worker lifetime and dispatch mechanics; the main thread can still collect results by cluster index and call the existing invariant and commit logic in the same order.

## Anti-Evidence

A prior investigation of `applySorobanStageClustersInParallel` failed because it over-attributed this broad zone to serial thread-state setup; this hypothesis must not repeat that mistake. The first PoC step must add narrow launch/start/wait instrumentation and reject the idea if `std::async` overhead is only a sub-millisecond slice.

Persistent workers must not exceed `NUM_CLUSTERS`, must not retain scoped ledger entries across jobs, and must not let one stage's `ThreadParallelApplyLedgerState` leak into the next stage. The implementation also has to handle exceptions with the same fail-fast behavior as the current `future.get()` loop.

The worker pool does not address true intra-cluster serialization, which remains the dominant soroswap constraint. If the measured overhead is mostly contract execution time or unavoidable load imbalance among true pair clusters, this will fall below the Medium threshold.
