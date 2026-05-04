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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The soroswap apply-load benchmark generates transactions before the timed interval and measures `closeLedger`; for the target `TX=2000, T=8` run it verifies exactly one Soroban stage with the configured eight clusters. That stage reaches `applySorobanStageClustersInParallel`, where the apply thread constructs each `ThreadParallelApplyLedgerState`, launches one `std::async` task per cluster, then waits on the futures while workers execute all transactions in each cluster sequentially. A persistent worker pool would only remove the launch/teardown/scheduler handoff around those eight tasks; it would not remove serial thread-state construction, per-cluster contract execution behind `future.get()`, invariant checks, ordered thread-state merge, or true intra-cluster serialization.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:11` — prior `001-parallelize-thread-state-construction.md` failed because `applySorobanStageClustersInParallel` self-time includes worker execution behind `future.get()`, so broad zone time cannot be attributed to serial setup or orchestration.
- `ai-summary/CURRENT_STATE.md:41-54` — the accepted current soroswap non-Tracy baseline is 272.250 / 275.886 / 270.551 ms, so the objective's 3% Medium floor is roughly 8.2 ms per ledger.
- `scripts/run_apply_load_matrix.py:417-425` — the benchmark writes scenario thread count into `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`; for the target `T=8` scenario this caps the Soroban stage at eight clusters.
- `src/simulation/ApplyLoad.cpp:2261-2334` — benchmark timing brackets `closeLedger`, excludes transaction generation, and asserts one Soroban stage with `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` clusters.
- `src/simulation/ApplyLoad.cpp:2672-2678` — soroswap setup creates exactly one token pair per configured cluster/bin.
- `src/simulation/ApplyLoad.cpp:3389-3393,3458-3475` — swap generation round-robins transactions across those pairs and gives each transaction pair-specific read-write keys, producing the intended true-conflict cluster shape.
- `src/ledger/LedgerManagerImpl.cpp:2871-3029` — `applyTransactions` builds `ApplyStage` / `TxBundle` data, then calls `applySorobanStages` from `applyParallelPhase`.
- `src/ledger/LedgerManagerImpl.cpp:2673-2709` — `applySorobanStages` constructs one `GlobalParallelApplyLedgerState`, loops over stages, and later commits global changes to the main `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` waits for cluster workers, performs invariant processing, commits completed thread states, and destroys them.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — current orchestration creates one future per cluster with `std::async(std::launch::async, ...)` and then calls `future.get()` for each result.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — each worker applies every transaction in its cluster sequentially and flushes remaining read-only TTL bumps before returning its thread state.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` construction, including footprint collection from global state, happens before the async launch on the apply thread and would still be required with a worker pool.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `commitChangesFromThreads` folds returned thread states in vector order after all workers finish, so ordered merge remains serial glue outside the worker launch mechanism.

### Why It Failed

The local inefficiency exists, but it is too small for this objective's Medium-or-higher threshold. In the measured soroswap shape there is one hot stage and eight cluster tasks, so a worker pool must save more than about 8.2 ms per ledger, or over 1 ms per task launch, before it reaches the 3% floor on the current 272.9 ms baseline. The code trace shows that the broad `applySorobanStageClustersInParallel` time is dominated by the work waited on by `future.get()` rather than launch overhead: per-cluster Soroban execution remains inside `applyThread`, thread-state construction remains serial before launch, and the ordered post-worker merge remains unchanged. Without narrow evidence that eight `std::async` launches cost multiple milliseconds in non-Tracy production runs, the proposed pool is a real but Low/sub-Low orchestration optimization and must be rejected under the optimize-soroswap reviewer criteria.

### Lesson Learned

For parallel Soroban apply orchestration, first count how many one-shot operations occur per measured ledger and compare that count to the top-line apply-time threshold. Broad zones that include `future.get()` waits should be treated as worker execution envelopes, not as evidence that C++ scheduling or setup glue is a Medium-sized bottleneck.
