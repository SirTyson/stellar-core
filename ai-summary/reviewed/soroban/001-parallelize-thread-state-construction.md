# H001: Parallelize Per-Cluster Thread State Construction

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: High
**Impact**: soroswap apply-time reduction by removing serial setup from the parallel Soroban apply phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `closeLedger`, each Soroban apply stage should spend most of its time executing independent clusters on worker threads. Per-cluster `ThreadParallelApplyLedgerState` setup should not serialize the stage when the setup work only reads immutable global state, LCL snapshots, and cluster footprints; the observable result should remain the same map of per-thread changes merged back in the existing deterministic cluster order.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs each `ThreadParallelApplyLedgerState` on the apply thread before launching `std::async`. That constructor calls `collectClusterFootprintEntriesFromGlobal`, scans every transaction footprint in the cluster, computes TTL keys, and copies matching global entries into the thread map; this is independent per cluster but runs serially. Moving this construction into the worker task would overlap the setup across at most `stage.numClusters()` workers, preserve deterministic merge order by still collecting futures in index order, and reduce the critical path for soroswap ledgers with many independent clusters.

## Trigger

Run the current soroswap benchmark (`scripts/run_apply_load_matrix.py --tracy`, soroswap TX=4000, T=8). The current reference trace reports `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with **1,684,354,306 ns self-time** over 37 calls and **1,700,913,221 ns total time**, inside the `applyLedger` path. The code path is `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStage` -> `applySorobanStageClustersInParallel`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — serially constructs `ThreadParallelApplyLedgerState` before launching each worker future.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — constructor path scans the cluster footprint and populates `mThreadEntryMap` from the global map.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — stage orchestration already merges returned thread states after futures complete, providing a deterministic merge point.

## Evidence

The Tracy self-time hotspot is on an applyLedger descendant, not TX-set construction: `applySorobanStageClustersInParallel` is called by `applySorobanStage` at `LedgerManagerImpl.cpp:2635`, which is called by `applySorobanStages` at `2703`, by `applyParallelPhase` at `3028`, by `applyTransactions` at `2882`, and by `applyLedger` at `1687`. The zone's self-time is large because the async call is not launched until after `std::make_unique<ThreadParallelApplyLedgerState>(app, globalState, cluster, i)` returns. The constructor only reads `global.getGlobalEntryMap()`, cluster footprints, the snapshot/config/module-cache references, and writes into its own `mThreadEntryMap`, so each cluster's setup appears parallelizable without changing ledger output.

## Anti-Evidence

`DeactivateScopeGuard globalStateDeactivateGuard(globalState)` currently covers both construction and worker execution; moving construction into the worker must preserve the scope discipline and ensure the global scope is deactivated before any worker reads entries from it. `GlobalParallelApplyLedgerState` and the LCL snapshot must also be safe for concurrent const reads during setup; if any hidden mutable cache is touched during `collectClusterFootprintEntriesFromGlobal`, that would need synchronization or a narrower refactor.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The ledger-close path reaches this code through `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStage` -> `applySorobanStageClustersInParallel`. In `applySorobanStageClustersInParallel`, each cluster's `ThreadParallelApplyLedgerState` is constructed synchronously before its `std::async` worker is launched, so construction for later clusters cannot overlap with either earlier construction or earlier worker execution. The constructor copies a per-thread snapshot, clones a module-cache handle, copies prior restores, and scans the cluster footprint to copy matching entries from the deactivated global entry map into the thread map. Stage merge already waits for futures and commits returned thread states in vector order, so moving construction into the async task can preserve deterministic merge order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — `applyLedger` invokes `processFeesSeqNums` and then `applyTransactions`, placing the target path inside ledger apply time.
- `src/ledger/LedgerManagerImpl.cpp:2967-3030` — `applyParallelPhase` builds `TxBundle` clusters for Soroban stages and then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `applySorobanStages` builds a `GlobalParallelApplyLedgerState`, applies each stage, and only commits global changes to `LedgerTxn` after all stages complete.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` deactivates the global scope, constructs each thread state serially, launches each future, and collects returned states in future-vector order.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` consumes an already-built thread state, applies cluster transactions sequentially, flushes TTL bumps, and returns the state for deterministic merge.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` construction reserves the thread map, iterates every read-write and read-only footprint key in the cluster, computes TTL keys for Soroban entries, and copies any matching global-map entries into the thread scope.
- `src/transactions/ParallelApplyUtils.cpp:371-384` — comments describe the intended model: per-thread objects retain no references to non-thread-safe global maps/snapshots, and required information is copied into them before use.
- `src/transactions/ParallelApplyUtils.cpp:893-922` — `commitChangesFromThreads` runs after futures complete and merges thread maps into global state in the order of the returned `threadStates` vector.
- `src/bucket/BucketListSnapshot.h:69-77,160-164` and `src/bucket/BucketListSnapshot.cpp:84-94` — copied snapshots share immutable bucket data but get independent mutable stream caches, supporting per-thread copied snapshots.
- `src/rust/src/soroban_proto_any.rs:761-775` — `SorobanModuleCache::shallow_clone` clones shared ownership of a thread-safe module cache handle, matching the intended use from C++-launched threads.

### Findings

The inefficiency exists on the soroswap apply path. The current order is `make_unique<ThreadParallelApplyLedgerState>` then `std::async`, so per-cluster state setup is serialized by construction. This setup is not a one-time ledger setup: it occurs once per cluster per Soroban apply stage, and the soroswap matrix sets `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` equal to the scenario thread count (`T=8`), with generated soroswap swaps round-robined across exactly that many pairs/clusters.

The proposed optimization is structurally correct if implemented carefully. `collectClusterFootprintEntriesFromGlobal` reads the global entry map and prior restore map and writes only the new thread state's private maps; the global state is not mutated again until after all futures are collected. `DeactivateScopeGuard` already deactivates the global scope for the full duration of future launch and collection, which is the required precondition for `scopeAdoptEntryOptFrom` copies. Concurrent const reads of the global maps are safe as long as no commit starts before futures complete, and copied `ApplyLedgerStateSnapshot` instances are designed to have per-copy stream caches for thread use.

There are two implementation hazards for the PoC. First, `collectClusterFootprintEntriesFromGlobal` currently asserts `threadIsMain() || app.threadIsType(APPLY)`, which is true for the current serial construction but not for `std::async` worker threads registered outside `ApplicationImpl::mThreadTypes`; moving construction into the worker requires removing or relocating that assertion rather than calling `app.threadIsType` from the async thread. Second, the `DeactivateScopeGuard` must remain in the caller around both future launch and future collection so worker-side adoption from the global scope observes `global.mActive == false`.

Severity is assessed as Medium rather than High. The serial work is real and executes in a hot `closeLedger` descendant, and with eight soroswap clusters the setup component can be reduced from roughly sum-of-cluster setup to max-cluster setup. However, the cited Tracy zone is the whole `applySorobanStageClustersInParallel` function, including worker waiting, so the constructor-only share still needs a PoC benchmark to prove a >10% top-line apply-time reduction.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp:2530-2575` and `src/ledger/LedgerManagerImpl.cpp:2483-2521`, with supporting adjustment in `src/transactions/ParallelApplyUtils.cpp:925-931`.
- **Change description**: Launch one async task per cluster without first constructing `ThreadParallelApplyLedgerState` on the apply thread. The async task should construct its own `ThreadParallelApplyLedgerState` from `(app, globalState, cluster, clusterIdx)`, then run the existing per-cluster apply loop and return the state. Keep `DeactivateScopeGuard globalStateDeactivateGuard(globalState)` in the parent function until all futures have been joined, and keep collecting futures in cluster-index order before `commitChangesFromThreads`.
- **Correctness check**: Existing parallel Soroban tests should cover ordering, scope adoption, TTL bumps, restored entries, and deterministic merge behavior (`src/transactions/test/ParallelApplyTest.cpp` and Soroban invoke-host tests). Also verify invariant checks still run after future completion and before global merge.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py --tracy` for the active soroswap `TX=4000, T=8` scenario and compare top-line apply time across repeated runs. Add a temporary Tracy zone or timing split around `ThreadParallelApplyLedgerState` construction in the PoC branch to confirm the constructor setup component moves from serialized per-stage time into worker time; expected accepted impact is a reproducible 3-10% apply-time reduction unless constructor setup proves to dominate enough for High.
