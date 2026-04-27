# H001: Parallelize per-cluster ThreadParallelApplyLedgerState setup

**Date**: 2026-04-27
**Subsystem**: transactions
**Severity**: High
**Impact**: soroswap apply-time reduction by restructuring a dominant parallel-apply phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban apply stage contains multiple independent clusters, all per-cluster work that depends only on that cluster's footprint should begin on the cluster worker as soon as possible. Constructing each `ThreadParallelApplyLedgerState` should not serialize footprint scanning and global-entry adoption for every cluster on the apply thread before any cluster starts `parallelApply`. The observable ledger output should remain identical: each cluster still receives the same scoped entries, each transaction is applied in cluster order within its cluster, and returned thread states are merged in deterministic cluster-index order.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs each `ThreadParallelApplyLedgerState` on the caller thread at `src/ledger/LedgerManagerImpl.cpp:2545-2550`, and only then launches `std::async` for `applyThread`. The constructor calls `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` at `src/transactions/ParallelApplyUtils.cpp:988-1000`, which reserves from every transaction footprint and walks both read-write and read-only footprint vectors at `src/transactions/ParallelApplyUtils.cpp:925-985`. For soroswap this makes the setup side of the parallel stage serial, so large clusters wait while the apply thread scans and copies footprint entries for all earlier clusters; moving construction into the async body should overlap this independent setup across the existing cluster workers without changing ledger semantics.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` for `soroswap, TX=4000, T=8` on the current baseline. In the resulting trace, inspect `applyLedger` descendants and compare the stage that contains many independent Soroban clusters: `applySorobanStageClustersInParallel` should show high wall/self time before worker execution is fully underway. A PoC should move `ThreadParallelApplyLedgerState` construction into the worker lambda/future, keep a result slot per cluster index, and rerun the soroswap matrix multiple times.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs each thread state serially, launches futures, and appends results in completion/get order.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — `collectClusterFootprintEntriesFromGlobal` and the `ThreadParallelApplyLedgerState` constructor walk every cluster footprint and copy/adopt entries from global state.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` consumes the returned thread states after all futures complete; deterministic result ordering must be preserved if construction moves into workers.

## Evidence

The current soroswap baseline is `620.996 ms` median apply time in `ai-summary/CURRENT_STATE.md`, with trace `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`. `csvexport-release -e` reports `applySorobanStageClustersInParallel,ledger/LedgerManagerImpl.cpp,2537,1684354306 ns self,37 calls,max 1646630682 ns`; total time is `1700913221 ns`. Unwrap verification against `applyLedger` windows found all 37 events inside `applyLedger` with `1700.913 ms` total and a `1663.036 ms` max event. Structurally, this function is explicitly in the apply path (`applySorobanStage` at `src/ledger/LedgerManagerImpl.cpp:2622-2670`) and the heavy constructor work touches only the target cluster's footprint plus read-only global state.

## Anti-Evidence

`ThreadParallelApplyLedgerState` construction currently runs while `globalState` is deactivated by `DeactivateScopeGuard`, so the worker-side construction must preserve the same scope deactivation/adoption invariants. The returned vector of thread states is currently assembled by iterating futures in cluster order; an implementation that collects results by completion order would be non-deterministic and not viable. The expected gain depends on setup being a meaningful fraction of the critical stage rather than only hidden under worker time, so the PoC must compare repeated soroswap apply-time runs, not only zone self-time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this code through `applyParallelPhase`, which builds `ApplyStage`/`Cluster` objects, calls `applySorobanStages`, then calls `applySorobanStageClustersInParallel` for each Soroban stage. The claimed serial construction is real: the loop constructs every `ThreadParallelApplyLedgerState` before launching its corresponding `std::async`, and the constructor scans each cluster footprint and adopts any matching entries from the deactivated global state. However, the Tracy "self time" evidence for `applySorobanStageClustersInParallel` is not constructor/setup time; it includes waiting for async workers and uninstrumented worker-side work. In the captured max event, worker `doParallelApply` starts were only staggered from about 3.7 ms to 30.7 ms, and the critical worker was the first worker started, so moving setup into the workers would not remove a Medium-tier portion of the top-line soroswap apply time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` converts tx-set parallel stages into apply clusters and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` constructs one global parallel state, then applies each stage and commits the final global state to the ledger transaction.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` measures `applySorobanStageClustersInParallel`, then checks invariants, commits returned thread states in order, and destroys them.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` deactivates `globalState`, constructs one `ThreadParallelApplyLedgerState` per cluster serially, launches each async worker, and retrieves futures in launch order.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` applies transactions sequentially within a cluster and flushes remaining read-only TTL bumps before returning the thread state.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — the thread-state constructor reserves by scanning all tx footprints in the cluster, walks read-write and read-only footprints, and copies/adopts entries that are already present in the global map.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` consumes returned thread states in vector order, so preserving deterministic cluster-index order is required.
- `src/transactions/ParallelApplyUtils.cpp:1041-1064` — `flushRemainingRoTTLBumps` is uninstrumented worker-side work after per-tx parallel apply, which explains why the parent async-wait zone can remain large after the last observed `doParallelApply` zone.
- `src/main/ApplicationImpl.cpp:172-206,1301-1305` — `std::async` threads used here are not registered in `mThreadTypes`, so moving construction into the worker would also require revisiting the main/apply-thread assertion in `collectClusterFootprintEntriesFromGlobal`.

### Why It Failed

This is below the objective severity threshold. The serial setup exists and is on the apply path, but the hypothesis over-attributes `applySorobanStageClustersInParallel` self time to that setup. Direct unwrap of the cited Tracy trace shows the setup-induced worker-start spread in the max event is roughly 27 ms, while the captured critical worker was already the first launched worker and the outer zone continued long after the last observed `doParallelApply` event. That makes the proposed change unlikely to produce the required 3-10% reproducible soroswap apply-time reduction; the dominant cost in the target phase remains worker execution/imbalance and uninstrumented post-apply work, not serial thread-state construction.

### Lesson Learned

For parent zones that launch futures, Tracy self time is not equivalent to pre-launch setup time: it can include future waits and uninstrumented work running on worker threads. Before promoting a parallelization hypothesis, compare worker start times and the critical worker's position/order, not just the parent zone's aggregate self time.
