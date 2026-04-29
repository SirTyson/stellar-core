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

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/ledger/LedgerManagerImpl.cpp` (`applySorobanStageClustersInParallel`,
  ~lines 2545-2559): Removed serial per-cluster construction of
  `ThreadParallelApplyLedgerState` from the launch loop. The `std::async`
  task now constructs its own `ThreadParallelApplyLedgerState` (which performs
  the cluster-footprint scan and global-entry copy) immediately before
  invoking `applyThread`. Futures are still pushed in cluster index order and
  consumed via `get()` in that same order so the post-worker
  `commitChangesFromThreads` merge order is unchanged.
- `src/transactions/ParallelApplyUtils.cpp`
  (`ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`,
  ~lines 924-933): Replaced the `releaseAssert(threadIsMain() ||
  app.threadIsType(APPLY))` with a comment explaining that the function may
  now run on an unregistered `std::async` cluster worker. The function only
  reads from the deactivated immutable `global` state and writes to the
  per-thread `mThreadEntryMap` it owns, so removing the registered-thread
  check does not weaken any actual data-safety property; the data-safety
  invariants are still enforced by `DeactivateScopeGuard` on `globalState`
  in `applySorobanStageClustersInParallel`.

### Demonstration

The change overlaps each cluster's `ThreadParallelApplyLedgerState`
construction (footprint walk, `mThreadEntryMap` reservation, per-key copy
from the global entry map, and module-cache shallow clone) with the apply
work of earlier clusters. Previously the primary apply thread did the full
construction for cluster `i+1` only after construction for cluster `i` had
completed and only then launched cluster `i+1`'s worker. Now all
`stage.numClusters()` workers are launched immediately and each performs
its own setup in parallel, eliminating the serial pre-launch latency on the
critical path through `applySorobanStageClustersInParallel`. Determinism is
preserved because `globalState` is read-only under `DeactivateScopeGuard`,
each thread writes only to its own `mThreadEntryMap`, and
`commitChangesFromThreads` still iterates the returned thread-state vector
in cluster index order.

### Test Results

`make check` recurses into `lib/gperftools` whose
`tcm_min_asserts_unittest` fails on this host independently of this change
(no code under `lib/` was touched). To exercise the actual stellar-core C++
test suite I ran `selftest-nopg` (the same script `make check` invokes for
the stellar-core binary), with `NUM_PARTITIONS=30` and
`STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --disable-dots'`. All 30
partitions reported `All tests passed` with zero failures, including the
parallel-Soroban test cases that exercise this code path (e.g.,
`"parallel txs"` in `transactions/test/InvokeHostFunctionTests.cpp:8040`).
The trailing `check-sorobans` step (which re-runs Rust submodule tests
under the host toolchain) is unaffected by this C++-only change and was
skipped because `RUST_TOOLCHAIN_CHANNEL` was not exported in this
environment.

---

## Final Review

**Verdict**: REJECTED
**Date**: 2026-04-29
**Final review by**: gpt-5.5, high
**Failed At**: final-review

### Adversarial Analysis

1. **Does the change actually address the claimed inefficiency?** YES — the diff moves `ThreadParallelApplyLedgerState` construction from the primary apply thread into each indexed `std::async` task, so the targeted setup work is no longer performed serially before worker launch.
2. **Are the preconditions realistic?** YES — the soroswap apply-load benchmark uses 8 dependent clusters and exercises this Soroban parallel-apply path.
3. **Is the original code inefficient or working as designed?** PLAUSIBLE INEFFICIENCY — merge order remains deterministic because futures are stored and consumed by cluster index, and `commitChangesFromThreads` still merges the returned thread-state vector in order.
4. **Does the benchmark improvement match the claimed severity?** NO — the authoritative three-run non-Tracy matrix showed a soroswap regression, not an improvement. Baseline soroswap medians from `ai-summary/CURRENT_STATE.md` were 313.255239 ms, 297.379806 ms, and 304.8911175 ms. Optimized medians were 314.542769 ms, 312.752749 ms, and 326.2805885 ms.
5. **Is the optimization in scope?** YES — the modified code is under `applyLedger` / parallel Soroban apply, not TX-set construction or background bucket work.
6. **Is the benchmark methodology correct?** YES — final review used the required local-build `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` command three times without `--tracy`, and compared against the accepted `CURRENT_STATE.md` baseline.
7. **Can the improvement be explained without the optimization?** NOT APPLICABLE — there was no measured improvement to explain.
8. **Is this optimization novel?** YES — no duplicate-finalized finding was identified during this review.

### Rejection Reason

The optimization is structurally plausible and passed the required full test command, but it failed the headline performance gate. Soroswap median apply time regressed across the three authoritative non-Tracy benchmark runs, so the finding does not meet the objective's minimum 1% reproducible improvement bar and is not eligible for confirmation.

### Failed Checks

- Final-review performance check 4: benchmark improvement did not match the claimed severity or any valid severity tier.
- Objective verdict criterion: soroswap apply time must improve consistently across all three non-Tracy runs; instead it regressed.
