# H001: Parallelize Soroban Cluster State Setup Before Worker Launch

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: High
**Impact**: soroswap apply-time reduction by restructuring a dominant `closeLedger` phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban stage should start up to the configured cluster parallelism promptly, and any cluster-local state setup should run concurrently with the worker that will consume it. The primary apply thread should still collect worker results and commit stage effects in deterministic cluster order, but it should not serially build every cluster's thread-local ledger state before later clusters are allowed to start.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs each `ThreadParallelApplyLedgerState` on the primary apply thread before calling `std::async` for that cluster. That constructor calls `collectClusterFootprintEntriesFromGlobal`, which reserves and populates `mThreadEntryMap` by walking every transaction footprint in the cluster and copying matching entries from the global map. On soroswap, this serial setup delays worker launch for later clusters in every stage; moving thread-state construction into the async task, or using a bounded persistent worker pool that performs setup inside each worker, should overlap this per-cluster footprint work without changing the deterministic result-collection order.

## Trigger

Run the current soroswap apply-load benchmark with `NUM_CLUSTERS=8` / `ledgerMaxDependentTxClusters=8` and many independent Soroban clusters. In the baseline Tracy trace `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`, `applySorobanStageClustersInParallel` is a descendant of `applyLedger` for all 37 events and accounts for 1,700.913 ms total inside apply; self-time export reports 1,684.354 ms self-time at `ledger/LedgerManagerImpl.cpp:2537`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — serially constructs `ThreadParallelApplyLedgerState` and only then launches each `std::async`.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — `ThreadParallelApplyLedgerState` construction walks cluster footprints, reserves the thread map, and copies global entries.
- `src/ledger/LedgerManagerImpl.cpp:2622-2664` — stage-level caller preserves deterministic post-worker invariant checks, commit, and thread-state destruction.

## Evidence

The current trace confirms this zone is inside the measured `applyLedger` envelope, not TX-set construction: `applyLedger` has 65 events totaling 4,591.087 ms, and all 37 `applySorobanStageClustersInParallel` events fall within those windows. Structurally, the launch loop performs setup for cluster `i` before worker `i` can begin and before cluster `i+1` setup can begin, despite `globalState` being read-only during this phase under `DeactivateScopeGuard`. The result vector can remain deterministic by storing futures in cluster index order and calling `get()` in that same order, exactly as the current code does.

## Anti-Evidence

The Tracy self-time for `applySorobanStageClustersInParallel` includes time spent waiting for worker execution, so it overstates the setup-only component. A PoC needs to separately time construction and thread launch overhead; if most of the 1.7 s is actual host execution rather than serialized setup, the win may drop below the High-tier threshold. The change must also keep worker count bounded by `stage.numClusters()` / configured cluster count and must not let cluster result merge order depend on scheduler order.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`applyTransactions` dispatches Soroban phases to `applyParallelPhase`, which builds `ApplyStage`/`Cluster` bundles and calls `applySorobanStages`. For each stage, `applySorobanStage` calls `applySorobanStageClustersInParallel`, where the primary apply thread creates every `ThreadParallelApplyLedgerState` before launching the corresponding `std::async` worker. The state constructor walks that cluster's transaction footprints, reserves the thread map, copies matching entries out of the deactivated global map, clones the module cache, and only then permits `applyThread` to start executing host functions. Results are already collected and later committed in vector order, so moving construction into the async task can preserve deterministic merge order if futures remain indexed by cluster.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2963` — `applyTransactions` enters the parallel Soroban path, records benchmark phase timings, and later processes results deterministically.
- `src/ledger/LedgerManagerImpl.cpp:2966-3030` — `applyParallelPhase` converts transaction-set stages into `ApplyStage`/`Cluster` objects, then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` builds one `GlobalParallelApplyLedgerState` and applies each stage sequentially.
- `src/ledger/LedgerManagerImpl.cpp:2622-2669` — `applySorobanStage` measures `sorobanParallelApplyMs`, then checks invariants, commits thread changes, and destroys thread states after all workers finish.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` deactivates the global scope, constructs each thread state serially, launches one `std::async` per cluster, and retrieves futures in launch order.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` consumes the prebuilt thread state, applies every transaction in the cluster, commits successful per-tx effects into the thread map, and returns the thread state.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — `ThreadParallelApplyLedgerState` construction reserves `mThreadEntryMap`, scans read/write and read-only footprints, looks up matching global entries, copies adopted entries into the thread scope, clones the module cache, and copies previous restore state.
- `src/transactions/ParallelApplyUtils.cpp:893-922` — `GlobalParallelApplyLedgerState::commitChangesFromThreads` merges returned thread states in vector order, preserving deterministic stage effects independent of worker completion order.
- `src/main/ApplicationImpl.cpp:201-205,1300-1305` — only the ledger-close thread is registered as `ThreadType::APPLY`; async cluster workers are unregistered, so worker-side construction must not call the current `app.threadIsType(APPLY)` assertion unchanged.

### Findings

The inefficiency exists: per-cluster thread-state setup is serialized on the primary apply thread even though the work is cluster-local and precedes the worker that uses it. The hot-path requirement is also met: benchmark output for the cited soroswap run shows mean close time of 628.36 ms, `apply_transactions` at 596.36 ms, `parallel_total` at 588.13 ms, and `soroban_parallel` at 509.60 ms, so this path dominates measured apply time. The existing Tracy zone cannot by itself prove a High-severity win because its self-time includes waiting for worker execution, but the constructor performs a full per-ledger footprint scan across clusters and can plausibly save Medium-tier time if the serial setup component is a modest fraction of `soroban_parallel`.

The proposed overlap is structurally correct with implementation caveats. `globalState` is deactivated before worker launch and is not committed to until after all futures return, so worker-side construction can read the global map as immutable and still return thread states for ordered merging. The PoC must address the current `collectClusterFootprintEntriesFromGlobal` thread-type assertion because `std::async` workers are not registered application threads; simply moving the existing constructor call into the async lambda without changing that assertion would abort. The PoC should also add direct timing around thread-state construction, because the baseline phase timers currently measure construction plus worker execution and cannot isolate the setup-only win.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp:2483-2574` and `src/transactions/ParallelApplyUtils.cpp:925-1000`.
- **Change description**: Launch one async task per cluster and construct `ThreadParallelApplyLedgerState` inside that task immediately before running the current `applyThread` body, or fold construction into a new worker entry point that returns the same `std::unique_ptr<ThreadParallelApplyLedgerState>`. Keep `threadFutures` indexed by cluster and keep the `get()`/`threadStates.emplace_back()` loop in index order. Remove or replace the `AppConnector& app` parameter/assertion in `collectClusterFootprintEntriesFromGlobal` so construction is allowed on these unregistered async workers without weakening actual data-safety checks.
- **Correctness check**: Existing parallel Soroban apply tests should cover deterministic transaction results, metadata ordering, restored entries, TTL handling, and invariant delta behavior; the PoC should especially run the Soroban/parallel-apply tests that exercise `InvokeHostFunctionOpFrame::parallelApply`, `ThreadParallelApplyLedgerState::getLiveEntryOpt`, and `GlobalParallelApplyLedgerState::commitChangesFromThreads`.
- **Benchmark focus**: Add temporary or test-only timing to split `sorobanParallelApplyMs` into thread-state construction, worker execution/wait, and future collection. The objective metric is mean soroswap apply/close time from `scripts/run_apply_load_matrix.py`; to clear this review's Medium severity, the PoC should show a reproducible 3-10% reduction in apply time, which corresponds to roughly 19-63 ms on the cited 628 ms mean close-time run.
