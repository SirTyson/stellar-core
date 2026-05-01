# H001: Reuse Bounded Workers for Soroban Stage Apply

**Date**: 2026-04-29
**Subsystem**: transactions, ledger
**Severity**: Medium
**Impact**: reduce soroswap apply time by removing repeated `std::async` worker creation and scheduling gaps from parallel Soroban stage execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying each Soroban `ApplyStage` should still execute every cluster independently, preserve the sequential transaction order inside each cluster, collect each cluster's resulting `ThreadParallelApplyLedgerState`, and merge thread states back in deterministic cluster-index order. The implementation should not create more concurrent workers than the configured number of clusters, and it should produce identical ledger entries, transaction results, metadata, metrics, and PRNG sub-seeds for a given tx set.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` constructs a fresh `ThreadParallelApplyLedgerState` and launches a fresh `std::async(std::launch::async, ...)` task for every cluster of every stage, then blocks on the resulting futures. In the current soroswap Tracy trace, this direct `applyLedger` descendant has 4.179839638 s total time across 41 calls, but the longest stage windows contain much less contained `TransactionFrame::parallelApply` worker work than wall time: for example one 825.528 ms stage contains only 334.910 ms aggregate worker `parallelApply` time and a 48.932 ms hottest worker, and the five long steady-state windows sum to 4.141581 s while their hottest-worker lower bound sums to about 1.449 s. Reusing a bounded worker pool for the whole `applySorobanStages` call, or otherwise keeping workers alive across stages and dispatching exactly one deterministic cluster job per worker, should remove thread lifecycle and scheduling gaps without changing cluster ordering or exceeding `NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load benchmark with the trace from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`.
Export `applyLedger`, `applySorobanStageClustersInParallel`, and `parallelApply` events with `csvexport-release -u`, then compare each stage window's wall time to the contained per-thread `parallelApply` durations. The issue triggers on Soroban-heavy ledgers with many stages: the current trace has 41 stage launches and repeatedly creates/join-waits async workers inside the measured apply window.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` creates a new `std::async` future per cluster per stage and then waits on every future.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` calls the async launcher for each stage before deterministic invariant checks and `commitChangesFromThreads`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` has the natural lifetime for a bounded worker pool because it owns the `GlobalParallelApplyLedgerState` and iterates all stages for the ledger.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is already a cluster-sized unit of work that preserves sequential order within one cluster and returns the thread-local state needed for ordered merge.
- `src/transactions/ParallelApplyStage.h:116-158` — `ApplyStage` exposes clusters by deterministic index, which can be preserved even if worker execution is scheduled through persistent workers.

## Evidence

The relevant zone is a direct child of the measured apply path: `applyLedger` totals 5.774332215 s across 69 ledgers in the diagnostic trace, `applyTransactions` totals 5.167167578 s, `applySorobanStages` totals 4.397943881 s, and `applySorobanStageClustersInParallel` totals 4.179839638 s at `ledger/LedgerManagerImpl.cpp:2537`. Self-time for `applySorobanStageClustersInParallel` is 4.134538049 s, which is expected because the main thread is blocked in future waits while worker zones run on other threads. Event analysis shows a large wall/worker mismatch in the long apply-stage windows: stage durations of 780.353 ms, 780.614 ms, 853.127 ms, 901.958 ms, and 825.528 ms had hottest-worker `parallelApply` totals of 711.924 ms, 323.876 ms, 202.639 ms, 161.214 ms, and 48.932 ms respectively. The code creates fresh async tasks at lines 2545-2554 for every stage, so even when cluster work is small or already complete, the measured apply stage still pays thread creation, scheduling, and future synchronization costs.

## Anti-Evidence

Some of the apparent gap may be Tracy instrumentation or OS scheduling overhead amplified by profiling, so a PoC must confirm repeated non-Tracy `scripts/run_apply_load_matrix.py` improvement rather than relying only on trace ratios. `ThreadParallelApplyLedgerState` construction is intentionally performed before launching the async task today and a prior hypothesis found parallelizing that setup alone sub-threshold; this hypothesis is distinct and should not be reduced to moving setup into workers. A worker-pool implementation must also preserve exception propagation, `DeactivateScopeGuard` behavior for the global state, per-cluster scope IDs, and deterministic collection of `threadStates` by cluster index before `commitChangesFromThreads`.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger path enters `applyParallelPhase`, builds `ApplyStage`/`Cluster` objects, constructs one `GlobalParallelApplyLedgerState`, and then iterates stages in `applySorobanStages`. For each stage, `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` per cluster, launches one `std::async(std::launch::async, ...)` task per cluster, waits on all futures, then `applySorobanStage` performs invariant checks and merges the returned thread states into the global state in the collected order. Inside each worker, `applyThread` applies transactions sequentially within the cluster and returns the cluster-local state; a bounded pool can preserve this stage barrier and ordered merge while eliminating repeated OS-thread/future creation across the many soroswap stages.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is a cluster-sized unit: it computes the deterministic tx sub-seed from `txNum`, flushes read-only TTL bumps that affect the next write footprint, calls `TransactionFrameBase::parallelApply`, commits successful tx results into the thread state, flushes remaining TTL bumps, and returns the state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs a fresh future vector per stage, deactivates the global scope, constructs one `ThreadParallelApplyLedgerState` per cluster, launches `std::async(std::launch::async, ...)`, and collects futures in launch/cluster-index order with exception-to-abort handling.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` treats the async launcher as the parallel subphase, then checks per-tx invariants, calls `GlobalParallelApplyLedgerState::commitChangesFromThreads`, and destroys thread states before the next stage.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` owns the `GlobalParallelApplyLedgerState`, loads the immutable header once, iterates all stages, and is the correct lifetime for a ledger-local bounded worker pool.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` computes the stage read-write set and merges thread states sequentially, preserving deterministic commit order as long as the result vector is indexed by cluster.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` construction copies/adopts cluster footprint entries from global state and assigns the dynamic scope index from the cluster index; a pool must still create a fresh state per cluster/job.
- `src/transactions/ParallelApplyUtils.cpp:1004-1054` and `src/transactions/ParallelApplyUtils.cpp:1241-1252` — worker execution contains uninstrumented TTL-flush and per-tx commit work in addition to `TransactionFrame::parallelApply`, so the Tracy wall/`parallelApply` gap should not be treated as entirely recoverable thread-launch overhead.
- `src/transactions/ParallelApplyStage.h:116-158` and `src/transactions/ParallelApplyStage.cpp:76-86` — `ApplyStage` exposes deterministic cluster count and indexed cluster access needed for stable dispatch/result slots.
- `/mnt/nvme2/apply-load/1695facd04c8-20260429-010922/logs/1695facd04c8-20260429-010922-02-soroswap-tx-2000-t-8.log:2372-2392`, `/mnt/nvme2/apply-load/1695facd04c8-20260429-011626/logs/1695facd04c8-20260429-011626-02-soroswap-tx-2000-t-8.log:2372-2392`, and `/mnt/nvme2/apply-load/1695facd04c8-20260429-012311/logs/1695facd04c8-20260429-012311-02-soroswap-tx-2000-t-8.log:2372-2392` — authoritative non-Tracy phase breakdowns show `soroban_parallel` is a dominant per-ledger subphase at roughly 236-252 ms median, while the overall soroswap close-time median is roughly 297-313 ms.

### Findings

The inefficiency exists: current code performs repeated per-stage/per-cluster `std::async(std::launch::async, ...)` creation and future synchronization in the measured `closeLedger` apply path. It is hot for the soroswap benchmark because the workload uses up to eight clusters and many stages, so the implementation can create hundreds of short-lived async tasks per ledger inside `soroban_parallel`.

The proposed direction is correctness-compatible if it is limited to scheduler mechanics. A viable implementation must still create a fresh `ThreadParallelApplyLedgerState` for each cluster, keep the `GlobalParallelApplyLedgerState` inactive while adopting entries into thread scopes and while cluster jobs run, execute each cluster's transactions sequentially, wait at every stage boundary before invariant checks and `commitChangesFromThreads`, propagate worker exceptions through the same abort path, and merge returned states by cluster index rather than completion order.

The hypothesis's Tracy wall/worker-gap evidence overstates recoverable savings because worker time outside `TransactionFrame::parallelApply` includes TTL flushes and `commitChangesFromSuccessfulTx`, and stage barriers/load imbalance remain real. However, the core waste is still large enough to test: at the baseline soroswap shape, replacing repeated OS-thread/future creation across many stage-cluster jobs only needs to save on the order of 9 ms per 300 ms ledger to reach the objective's 3% Medium floor, which is plausible for hundreds of `std::async` launches.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp:2483-2574` and `src/ledger/LedgerManagerImpl.cpp:2622-2710`; keep `src/transactions/ParallelApplyUtils.cpp` semantics unchanged except for any mechanical signature changes needed to pass scheduler state.
- **Change description**: introduce a ledger-local bounded worker pool or equivalent persistent worker set with size `max(stage.numClusters())` over the `applySorobanStages` call. For each stage, allocate a result vector sized to `stage.numClusters()`, submit exactly one cluster job per cluster index, have each job build/use its fresh `ThreadParallelApplyLedgerState` and call the existing `applyThread` logic, wait for all jobs before returning, and preserve exception-to-`printErrorAndAbort` behavior.
- **Correctness check**: existing parallel-apply coverage in `src/transactions/test/ParallelApplyTest.cpp` and Soroban apply tests in `src/transactions/test/InvokeHostFunctionTests.cpp` should remain unchanged; pay particular attention to deterministic metadata, read-only TTL bump behavior, invariant checks, and per-transaction PRNG sub-seeds.
- **Benchmark focus**: compare repeated non-Tracy `scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8 runs against the baseline medians in `ai-summary/CURRENT_STATE.md`. The relevant top-line metric is apply/close time; subphase logs should show `soroban_parallel` decreasing by at least about 9 ms per ledger to clear the Medium threshold, with no regression in `commit_from_thrds`, `commit_to_ltx`, or tail phases.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-01
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/ledger/LedgerManagerImpl.h` — Forward-declared `ParallelApplyWorkerPool`,
  added `std::unique_ptr<ParallelApplyWorkerPool> mApplyWorkerPool` member, and
  declared an out-of-line `~LedgerManagerImpl()` so the unique_ptr destructor
  can see the complete type.
- `src/ledger/LedgerManagerImpl.cpp` — Defined `ParallelApplyWorkerPool`: a
  bounded persistent worker pool with a mutex+condvar task queue and
  `std::packaged_task<void()>` jobs. Workers are spawned lazily up to the
  largest cluster count seen and reused for the lifetime of the
  `LedgerManagerImpl`. Added the destructor (`= default`) and constructor
  initialization. Refactored
  `LedgerManagerImpl::applySorobanStageClustersInParallel` to:
    * pre-size `threadStates` to `stage.numClusters()` so each worker writes
      its slot by cluster index (preserving deterministic merge order in
      `commitChangesFromThreads`),
    * build a vector of `packaged_task`s wrapping the existing `applyThread`
      logic (each constructed with its fresh `ThreadParallelApplyLedgerState`),
    * submit the batch to `mApplyWorkerPool->submitBatch(...)`, then await
      each future in submission/cluster-index order with the same
      `printErrorAndAbort` exception-propagation behavior as the previous
      `std::async` path.
  The `DeactivateScopeGuard` over the `GlobalParallelApplyLedgerState` and
  the per-cluster scope index passed to `ThreadParallelApplyLedgerState`
  construction are unchanged.

### Demonstration

The previous implementation called `std::async(std::launch::async, ...)` for
every cluster of every stage (41 stage launches and up to 8 clusters each in
the soroswap trace), creating and tearing down hundreds of OS threads per
ledger inside the measured `applySorobanStageClustersInParallel` window.
With this change, the pool spawns at most `max(stage.numClusters())` threads
once and dispatches each cluster job through a queue+condvar handoff, so per-
stage cost reduces to two notify_all calls plus N `future::get()` waits and
the workers stay live across stages and across ledgers. Cluster construction,
scope guarding, sequential intra-cluster apply, and ordered merge are all
preserved unchanged.

### Test Results

- `./src/stellar-core test "[parallelapply]"` — all 23 test cases /
  2,721,857 assertions pass.
- `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  — full unit suite + `selftest-nopg` + `check-nondet` exit 0; final
  `All 2 tests passed` reported, with every Rust submodule `test result:
  ok. 0 failed` line confirmed and no `FAIL`/`ERROR` lines in the output.
