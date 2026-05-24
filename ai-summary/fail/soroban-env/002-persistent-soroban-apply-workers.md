# H002: Persistent Soroban Apply Workers

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reusing `NUM_CLUSTERS` worker threads and per-worker apply scaffolding across Soroban stages
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban stages should still execute in their deterministic stage order, and clusters within a stage should still apply independently with results committed in the existing cluster order. However, the apply path should not create a fresh `std::async` task/future and fresh worker-side scaffolding for every cluster of every stage when the configured concurrency cap is the fixed `NUM_CLUSTERS`; workers can be persistent for the duration of one `applySorobanStages` call and accept ordered stage/cluster jobs while preserving the same observable ledger changes and metadata ordering.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` launches one `std::async(std::launch::async, ...)` per cluster on every stage, waits for all futures, destroys the future vector, and then the next stage repeats the same task construction path. In soroswap, the benchmark applies many similarly-shaped stages under the same global parallel state, so thread creation/scheduler handoff, future allocation, and cold per-thread apply scaffolding are repeated inside the measured apply window. A fixed stage-local worker pool capped at `stage.numClusters()`/`NUM_CLUSTERS`, returning results through indexed slots that are consumed in cluster order, would preserve determinism while reducing repeated launch/teardown overhead and improving per-worker cache locality for module-cache handles and parallel-apply maps.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000,T=8`) on the next-protocol baseline. During ledger apply, `applySorobanStages` iterates the stage list and calls `applySorobanStageClustersInParallel` for each stage; the current diagnostic trace shows 43 calls to that zone.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — creates `std::future` objects and launches `std::async` for every cluster of every stage.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — serially iterates Soroban stages and could own a persistent worker pool for the whole `applySorobanStages` scope.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` is the per-cluster job body that can become a pool job without changing transaction ordering inside the cluster.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — per-job `ThreadParallelApplyLedgerState` construction may be reusable or allocator-backed when the same worker handles successive clusters.

## Evidence

The current Tracy trace records `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with 2,691,904,192 ns self-time over 43 calls, all contained in `applyLedger`. The source shows a launch/wait/destroy pattern for each stage (`std::async` at lines 2550-2553, `future.get()` at lines 2556-2563, `threadFutures.clear()` at line 2573), and the benchmark uses `T=8`, so a persistent pool can be bounded by the same concurrency already exercised by the benchmark rather than scaling with hardware concurrency.

## Anti-Evidence

A large fraction of the parent zone is expected to be waiting for actual worker execution, so this must not claim the whole 2.69s as removable. Prior fail entry `005.md` showed that simply moving setup work is below threshold; this hypothesis is only viable if focused instrumentation shows repeated task/future/thread scaffolding and worker-local cold-start effects are a multi-percent part of the current soroswap stage cost. The pool must also avoid changing exception propagation, abort behavior, metrics timing, and the ordered `commitChangesFromThreads` result vector.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as persistent apply workers; related prior fail entry 005 only covered moving per-cluster state construction
**Failed At**: reviewer

### Trace Summary

The traced path does create one `std::async(std::launch::async)` job per cluster for every Soroban stage, and `applySorobanStages` repeats this across all stages within the close-ledger apply window. However, each stage still requires a hard barrier: `applySorobanStage` must collect all cluster results, check invariants, and merge `ThreadParallelApplyLedgerState` objects into `GlobalParallelApplyLedgerState` in deterministic cluster order before the next stage can run. The proposed worker pool can remove task/future/thread launch overhead, but it does not remove the dominant worker execution, per-cluster transaction application, stage merge, or stage barrier work, and the cited `applySorobanStageClustersInParallel` Tracy self-time is mostly `future.get()` waiting rather than removable launch overhead.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` is the real per-cluster work: it flushes RO TTL bumps, calls `parallelApply` for every transaction in the cluster, records successful changes, and flushes remaining TTL bumps. A worker pool would still run this body once per cluster.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` constructs a fresh `ThreadParallelApplyLedgerState`, launches a `std::async` future, then calls `future.get()` and stores results in cluster order. The launch pattern is real, but the measured function scope includes waiting for cluster execution.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — after futures return, `applySorobanStage` runs invariant checks, commits thread states to the global state, and destroys the stage-local thread states before returning.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` owns one `GlobalParallelApplyLedgerState` and serially applies stages, so a persistent executor could only reuse workers across stage boundaries, not overlap stages.
- `src/transactions/ParallelApplyUtils.cpp:908-922` — `GlobalParallelApplyLedgerState::commitChangesFromThreads` iterates returned thread states in vector order, preserving deterministic merge order after all cluster jobs finish.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` is stage/cluster-specific: it adopts global/restored entries, binds the cluster scope id, and collects that cluster's footprint entries. Persistent OS workers do not make this object reusable without a separate state-reset redesign.
- `src/transactions/ParallelApplyUtils.cpp:371-384` — comments explicitly state per-thread maps retain no references to the global maps/snapshots because those structures are not thread-safe; this limits the claimed "worker-local scaffolding" reuse to allocator/cache effects rather than reusing live apply state.

### Why It Failed

The inefficiency exists, but the Medium-impact claim is not supported by the traced code path. The only cleanly removable work from a persistent pool is per-job `std::async`/future/thread launch and teardown plus small queueing/allocation effects; the expensive `parallelApply` body, cluster-local `ThreadParallelApplyLedgerState` construction, deterministic `future.get()`-equivalent wait, invariant checks, and `commitChangesFromThreads` merge remain. The hypothesis relies on the full `applySorobanStageClustersInParallel` scope time as evidence, but that scope encloses the blocking wait for cluster execution and prior failed analysis already established this zone is not a removable setup-time estimate. Without focused instrumentation isolating thread launch/teardown at several percent of top-line apply time, this falls below the optimize-soroswap objective's Medium severity threshold.

### Lesson Learned

For parallel Soroban apply, a broad async-launch wrapper zone is not evidence that task scheduling is a Medium-size bottleneck. Future worker-pool hypotheses should first measure `ThreadParallelApplyLedgerState` construction, `std::async` launch, queue handoff, and `future.get()` wait separately; only the non-wait launch/teardown component can be credited to persistent workers.
