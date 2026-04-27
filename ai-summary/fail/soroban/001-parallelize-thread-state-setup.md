# H001: Parallelize Soroban Thread State Setup With Worker Execution

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring a dominant `closeLedger` phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban stage with independent clusters should start all cluster workers with minimal serial pre-work, bounded by the existing `NUM_CLUSTERS`/stage cluster count, and should preserve deterministic transaction ordering by committing each cluster's effects back in the same stage order. Per-cluster state construction should not unnecessarily delay later workers when the data each worker needs is independent of other clusters in the same stage.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs each `ThreadParallelApplyLedgerState` synchronously on the apply thread before launching that cluster's `std::async` worker. The constructor calls `collectClusterFootprintEntriesFromGlobal`, which scans every transaction footprint in the cluster and copies matching global entries/TTL entries into the thread map; for soroswap this is per-cluster setup on the critical path before that cluster can begin executing. Moving the expensive footprint collection/state construction behind the worker boundary, or otherwise batching/pre-extracting immutable per-cluster inputs and constructing thread states concurrently, should reduce stage wall time without changing observable ledger output because clusters are still independent and `commitChangesFromThreads` can continue merging results in deterministic stage order.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` for `soroswap, TX=4000, T=8` using the current baseline trace. Inspect the `applyLedger` subtree: stages with multiple clusters show `applySorobanStageClustersInParallel` as a large self-time/wall-time zone even though workers are supposed to run independently. A PoC should move the `ThreadParallelApplyLedgerState` construction/`collectClusterFootprintEntriesFromGlobal` work into the launched worker path or an equivalent bounded worker pool, then compare repeated soroswap median apply time against the 620.996 ms baseline.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs `ThreadParallelApplyLedgerState` on the apply thread at lines 2545-2550 before launching each async worker, then waits for futures in submission order.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` and constructor scan cluster read-only/read-write footprints and copy global/TTL entries into the thread-local map.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` treats the parallel-cluster call as the dominant stage subphase before invariant checking and deterministic merge.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`. `csvexport-release -e` reports `applySorobanStageClustersInParallel,ledger/LedgerManagerImpl.cpp,2537` with 1,684,354,306 ns self-time across 37 calls; total-time export reports 1,700,913,221 ns total inside `applyLedger`, with a max single call of 1,663,036,113 ns. Unwrapped events confirm all 37 `applySorobanStageClustersInParallel` events are contained inside `applyLedger` windows. Structurally, the current loop serializes thread-state setup for every cluster before each worker starts, so later clusters cannot overlap their footprint collection with earlier workers' execution.

## Anti-Evidence

Some of the `applySorobanStageClustersInParallel` self-time is future waiting rather than setup itself, so the PoC must separately instrument or compare constructor/collection time before assuming the entire zone is reducible. `collectClusterFootprintEntriesFromGlobal` currently asserts it runs on the main/apply thread and uses `LedgerEntryScope` adoption from the global scope, so a viable implementation must preserve scope-safety semantics, avoid concurrent mutation of `GlobalParallelApplyLedgerState`, and keep worker count capped by the existing stage clusters/`NUM_CLUSTERS` configuration.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The code does serialize `ThreadParallelApplyLedgerState` construction before each `std::async` launch, and that constructor does scan each cluster footprint and copy any matching global entries into the thread-local map. However, the timing evidence does not isolate that setup cost: `applySorobanStageClustersInParallel` has one Tracy zone on the apply thread, and its self/wall time includes the subsequent `future.get()` waits for worker execution. Because worker-side Soroban execution is the dominant operation hidden behind those waits, the cited 1.68s parent-zone self time cannot be treated as reducible setup time or as evidence for the objective's Medium/High threshold.

There are also correctness constraints that the hypothesis acknowledges but does not resolve. `collectClusterFootprintEntriesFromGlobal` currently asserts main/apply-thread execution, and global-to-thread ledger-entry adoption is only legal while the global scope is inactive. Moving construction into workers may still be correct because the global entry map is const during the stage and adoption copies entries rather than mutating them, but the design must deliberately preserve the `DeactivateScopeGuard` lifetime, deterministic future ordering, and safe module-cache cloning/access.

### Alternative Angle

First instrument the actual setup work with dedicated timing around `ThreadParallelApplyLedgerState` construction and/or `collectClusterFootprintEntriesFromGlobal`, then compare that measured setup time against soroswap median apply time. If the isolated setup cost is at least 3% of apply time, refine the hypothesis to construct state inside the launched worker lambda, keep the global scope deactivated until all worker futures complete, return thread states in cluster-index order for deterministic merge, and either shallow-clone module caches on the apply thread before launch or prove `app.getModuleCache()->shallow_clone()` is safe from the worker threads.

If the isolated setup cost is below threshold, the better performance angle is not this parent-zone self time. Look instead for the actual dominant child work inside worker transaction execution, or for repeated footprint/global-entry work that can be eliminated rather than merely overlapped.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` consumes a prebuilt thread state, applies every transaction in the cluster, then flushes remaining read-only TTL bumps.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs all thread states serially before each async launch and then waits for futures in submission order.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `collectClusterFootprintEntriesFromGlobal` reserves the thread map, scans each tx footprint, copies matching global entries, and currently enforces main/apply-thread execution.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — `collectModifiedClassicEntries` already preloads Soroban read-only entries and TTLs into the global map, reducing some repeated per-thread fallback lookups.
- `src/ledger/LedgerEntryScope.h:184-192` and `src/ledger/LedgerEntryScope.cpp:489-501` — global-to-thread adoption is a permitted scope transition, but only from an inactive source scope.
- `src/ledger/LedgerManagerImpl.cpp:954-962` and `src/rust/src/soroban_module_cache.rs:54-60` — per-thread module cache handles are produced by shallow-cloning the apply state's shared Soroban module cache.
