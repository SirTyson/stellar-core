# H001: Bounded Parallel-Apply Worker Pool

**Date**: 2026-05-25
**Subsystem**: transactions, ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-stage `std::async` thread churn and improving worker locality
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban clusters in a stage should still run in the same deterministic stage/cluster structure and should still be limited to at most `NUM_CLUSTERS` concurrent workers. The apply path should not create a fresh OS thread/future chain for every cluster in every ledger; it should dispatch cluster jobs to a bounded, reusable apply worker pool and collect `ThreadParallelApplyLedgerState` results in cluster-index order before `commitChangesFromThreads`.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs a `ThreadParallelApplyLedgerState`, immediately launches `std::async(std::launch::async, &LedgerManagerImpl::applyThread, ...)` for every cluster, then waits on all futures. In the current soroswap Tracy trace, events fully contained in `applyLedger` show `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` consuming 2.753s of apply-thread wall time across 43 calls, while the event sample shows thousands of distinct worker thread ids over the run. The dominant child work remains Soroban execution, but repeatedly creating/joining thread stacks and losing thread-local/cache locality is avoidable scheduling overhead on every apply window.

The proposed change is a persistent, bounded executor owned by the apply path (or application) that accepts one cluster job per cluster, never exceeds the configured cluster count, and returns results in deterministic cluster-index order. This differs from intra-cluster parallelism or DAG scheduling: it preserves the existing stage barrier and cluster ordering, changes only worker lifecycle/dispatch mechanics, and should reduce apply time by removing repeated OS-thread creation, future shared-state allocation, and cold worker-local state.

## Trigger

Run the accepted soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on a ledger with parallel Soroban stages. The current trigger is every call to `applySorobanStageClustersInParallel`: for each stage, the code launches one `std::async` task per cluster and joins all futures before committing thread states. A PoC should show fewer unique worker threads across the trace and a reproducible 3-10% reduction in soroswap median apply time across the required three non-Tracy runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` currently constructs per-cluster thread state, launches `std::async`, and joins futures.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is already a self-contained cluster job body suitable for executor dispatch.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` consumes returned thread states and commits them after all cluster jobs finish; result ordering must remain stable here.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` construction remains per-cluster, but should happen on the worker or be passed into the worker without changing cluster semantics.

## Evidence

`ai-summary/CURRENT_STATE.md` identifies the current soroswap trace. `csvexport-release -u` filtered to `applyLedger` containment reports:

- `applyLedger`, `ledger/LedgerManagerImpl.cpp:1484`: 4.437s total across 71 windows.
- `applySorobanStageClustersInParallel`, `ledger/LedgerManagerImpl.cpp:2537`: 2.753s contained wall time across 43 calls, 62.0% of contained `applyLedger`.
- `parallelApply`, `transactions/TransactionFrame.cpp:2392`: 12.682s aggregate worker time across 8,687 calls.

The source shows each of those 43 stage-cluster calls creates a new `std::future` per cluster, and the unwrapped event sample shows worker thread ids increasing into the thousands, consistent with repeated thread creation rather than stable worker reuse. Even a small reduction in per-stage scheduling/cold-start overhead can be Medium because it applies before every cluster's worker execution and is on the critical path for all soroswap apply windows.

## Anti-Evidence

`applySorobanStageClustersInParallel` inclusive wall time is mostly worker execution waited on by `future.get()`, so the full 2.753s is not removable. A valid PoC must directly measure thread creation/future dispatch/cold-start savings, not claim the whole zone. The worker pool must also avoid the overheads that caused prior scheduler-style redesigns to regress: no dynamic DAG, no condition-variable-heavy intra-cluster scheduling, no hardware-concurrency scaling beyond `NUM_CLUSTERS`, and no nondeterministic result commit ordering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The claimed inefficiency is real: the current parallel Soroban apply path constructs one `ThreadParallelApplyLedgerState` per cluster, starts one `std::async(std::launch::async, ...)` per cluster, then consumes the futures in cluster order before committing thread states. However, the soroswap apply-load path is intentionally configured and asserted to have exactly one stage with `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` clusters, which is 8 for the target `soroswap, TX=2000, T=8` scenario. The inclusive `soroban_parallel` phase is dominated by actual `parallelApply` execution and waiting for the slowest cluster; a worker pool can only remove the eight thread/future launches per ledger, not per-cluster state construction, Soroban execution, result merging, or meta/refund work.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the cluster job body; it iterates all transactions in a cluster, calls `parallelApply`, commits successful tx state into the per-thread state, and flushes TTL bumps.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` creates a per-cluster `ThreadParallelApplyLedgerState`, launches `std::async(std::launch::async, &LedgerManagerImpl::applyThread, ...)` once per cluster, and calls `future.get()` in launch order.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` measures the entire worker-launch/wait window as `sorobanParallelApplyMs`, then checks invariants and commits thread states after all cluster jobs complete.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` applies stages sequentially with a stage barrier and commits global parallel state to the main `LedgerTxn` only after all stages finish.
- `src/ledger/LedgerManagerImpl.cpp:2966-3031` — `applyParallelPhase` converts XDR parallel stages/clusters into `ApplyStage`/`Cluster` bundles, then invokes `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` construction copies the cluster footprint from global state and remains required per cluster even with a reusable executor.
- `src/simulation/ApplyLoad.cpp:2323-2332` — the apply-load benchmark asserts max parallelism is exactly one stage with `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` clusters.
- `src/simulation/ApplyLoad.cpp:2672-2682` — soroswap setup creates exactly one token pair per configured cluster/bin, yielding eight clusters for the T=8 matrix scenario.
- `scripts/run_apply_load_matrix.py:116-124,417-424` — the accepted soroswap scenario uses `tx_count=2000`, `thread_count=8`, and writes that thread count to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.
- `src/herder/TxSetFrame.cpp:2326-2340` — txset validation rejects stages with more clusters than `ledgerMaxDependentTxClusters`, so a pool must not exceed the configured cluster bound.
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-005811/logs/f5502210f4e4-20260525-005811-02-soroswap-tx-2000-t-8.log:2372-2396` — non-Tracy run 1 reports median close time 207.046ms and median `soroban_parallel` 147.69ms; the latter is the full worker execution/wait phase, not removable scheduler overhead.
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-010419/logs/f5502210f4e4-20260525-010419-02-soroswap-tx-2000-t-8.log:2372-2396` — non-Tracy run 2 reports median close time 209.272ms and median `soroban_parallel` 149.72ms.
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011026/logs/f5502210f4e4-20260525-011026-02-soroswap-tx-2000-t-8.log:2372-2396` — non-Tracy run 3 reports median close time 206.452ms and median `soroban_parallel` 147.34ms.

### Why It Failed

This is below the objective severity threshold. The mechanism identifies real thread churn, but in the target soroswap benchmark it occurs once per ledger for eight clusters, so a Medium result would need to save roughly 6.2ms per 207ms ledger, or about 0.78ms per launched cluster, before accounting for the synchronization/queueing overhead a reusable executor would add. The measured `soroban_parallel` time is a 147-150ms inclusive wait for actual Soroban execution, and the code shows that per-cluster ledger-state construction and all transaction application remain required. With only eight launches per ledger and no source evidence of large thread-local warmup state in `applyThread`, the projected benefit is Low or sub-1% rather than the required 3-10%.

### Lesson Learned

Do not treat the inclusive `applySorobanStageClustersInParallel` or `soroban_parallel` timing as removable scheduling overhead: it primarily measures worker execution and the apply thread waiting for the slowest cluster. For the current soroswap benchmark, scheduler-lifecycle optimizations must first isolate and measure launch/join overhead directly; without that, eight `std::async` launches per ledger is not a Medium-tier apply-time target.
