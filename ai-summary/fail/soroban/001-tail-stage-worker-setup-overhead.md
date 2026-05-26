# H001: Tail Soroban stages spend more wall time in worker setup than worker apply

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing serialized tail-stage worker launch/setup overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each Soroban apply stage, `applySorobanStageClustersInParallel` should spend wall time approximately equal to the slowest cluster's actual `parallelApply` work plus a small fixed scheduling margin. In a short tail stage with only tens of milliseconds of worker apply work, the stage should not occupy the apply thread for hundreds of milliseconds. Worker construction and per-cluster state setup should either be amortized by a persistent `NUM_CLUSTERS` executor or overlapped with worker execution while preserving the existing stage barrier.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` constructs every `ThreadParallelApplyLedgerState` on the apply thread, launches one `std::async` per cluster, and then waits for all futures before the next stage can proceed. In the current soroswap trace, several tail stages have tiny measured worker payloads but still spend ~376-389 ms in the wrapper, which suggests serialized setup/thread-launch/scheduler overhead dominates those stages after the accepted native Soroswap optimizations made per-tx execution faster. Moving to a persistent bounded executor and constructing thread state inside worker tasks, or preconstructing the next stage's thread states while the current stage workers run, should remove the apply-thread serial tail without changing transaction order, result order, PRNG seeds, or commit ordering.

## Trigger

Run the current `soroswap,TX=2000,T=8` apply-load Tracy benchmark from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`

Within `applyLedger`, inspect `applySorobanStageClustersInParallel` events and contained `parallelApply` worker events. The tail stages show the suspected overhead:

- stage 39: wrapper wall 387.357 ms, max worker `parallelApply` 210.800 ms
- stage 40: wrapper wall 379.575 ms, max worker `parallelApply` 142.038 ms
- stage 41: wrapper wall 376.098 ms, max worker `parallelApply` 79.402 ms
- stage 42: wrapper wall 381.491 ms, max worker `parallelApply` 39.673 ms

The wrapper-minus-max-worker gap across these four stages is about 1.05 s over 71 `applyLedger` windows, or ~14.8 ms/ledger. Against the current non-Tracy soroswap median baseline (~207.6 ms), even partial recovery clears the 3% Medium threshold.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` - `applySorobanStageClustersInParallel` serially constructs thread states, launches `std::async`, and waits for futures.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` - `applySorobanStage` enforces the stage barrier, then commits and destroys thread states.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` - `ThreadParallelApplyLedgerState` constructor copies restored-entry state and collects cluster footprint entries from global state before the worker starts.
- `src/transactions/ParallelApplyUtils.cpp:924-986` - `collectClusterFootprintEntriesFromGlobal` performs per-cluster preload work that is currently part of setup rather than worker execution.

## Evidence

The current trace confirms the target zones are descendants of the measured `applyLedger` path:

- `applyLedger` total: 4,412,547,914 ns across 71 calls (`ledger/LedgerManagerImpl.cpp:1484`).
- `applySorobanStageClustersInParallel` total: 2,718,087,904 ns across 43 calls (`ledger/LedgerManagerImpl.cpp:2537`).
- Contained worker `parallelApply` totals show balanced large stages but severe tail-stage underutilization; in the four tail stages above, the wrapper holds the apply thread for hundreds of milliseconds after the largest measured worker payload is only 40-211 ms.
- The proposed fix does not add unbounded parallelism: it should use at most the configured `ledgerMaxDependentTxClusters` / `NUM_CLUSTERS` worker lanes and retain the existing deterministic stage barrier and serial `commitChangesFromThreads`.

## Anti-Evidence

Prior investigations rejected broad "parallelize thread-state setup" and "persistent worker executor" variants when benchmark runs did not improve. This hypothesis depends on the current post-native-soroswap baseline, where tail stages now show a much larger wrapper-minus-worker gap, and it still needs direct instrumentation that separates thread-state construction, `std::async` launch, scheduler delay, and future wait. If that gap is Tracy artifact, background-thread interference, or uninstrumented worker work rather than removable setup/launch overhead, the hypothesis should fail.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL - duplicate of `ai-summary/fail/soroban/summary.md` entries `001-parallelize-thread-state-setup.md + 001-parallelize-thread-state-split.md + 002-parallel-cluster-setup-serialization.md + 001-parallelize-thread-state-construction.md` and `002-persistent-parallel-apply-worker-executor.md`
**Failed At**: reviewer

### Trace Summary

The traced close-ledger path is `applyLedger` -> `applySorobanStages` -> per-stage `applySorobanStage` -> `applySorobanStageClustersInParallel`. The target function does construct `ThreadParallelApplyLedgerState` serially on the apply thread before launching one `std::async` per cluster, but the measured wrapper also includes waiting for worker completion. Each worker then runs `applyThread`, which contains per-transaction work outside the inner `TransactionFrame::parallelApply` / `OperationFrame::parallelApply` zones, including RO TTL flushing and thread-state commit of each transaction's modified entries.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1485` - `applyLedger` is the apply-thread entrypoint and owns the top-level Tracy `ZoneScoped` used by the benchmark.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` - `applyThread` loops over each cluster's transactions, calls `parallelApply`, commits successful transaction changes into thread state, and flushes remaining RO TTL bumps before returning.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` - `applySorobanStageClustersInParallel` constructs thread states, launches async workers, then synchronously waits on every future; wrapper time therefore includes slowest-worker wait, not just setup/launch overhead.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` - `applySorobanStage` enforces the stage barrier, checks invariants, commits thread states to global state, and destroys thread states before the next stage.
- `src/ledger/LedgerManagerImpl.cpp:2673-2724` - `applySorobanStages` creates one global parallel state, applies all stages sequentially, then commits global changes to the parent `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` - `ThreadParallelApplyLedgerState` setup copies restored-entry metadata and preloads global footprint entries for the cluster before worker launch.
- `src/transactions/ParallelApplyUtils.cpp:1041-1064` and `1164-1252` - worker-side RO TTL flushing and per-transaction commit work are outside the inner `parallelApply` zone but still inside the async worker future.
- `src/transactions/TransactionFrame.cpp:2385-2454` and `src/transactions/OperationFrame.cpp:175-188` - the inner `parallelApply` zones cover transaction/operation application, but do not cover all worker-future work counted by the wrapper.

### Why It Failed

This is substantially the same optimization surface already rejected in the Soroban fail summary: parallelizing/moving `ThreadParallelApplyLedgerState` setup off the apply-thread critical path and replacing per-stage `std::async` launch with a persistent bounded executor. The current evidence still infers setup/launch overhead from `applySorobanStageClustersInParallel` wrapper-minus-inner-`parallelApply` wall time, which prior reviews explicitly marked insufficient because the wrapper includes worker execution and future wait time; the source trace confirms that gap also includes uninstrumented worker-side work outside the inner `parallelApply` zones.

### Lesson Learned

Do not use `applySorobanStageClustersInParallel` wrapper-minus-worker-`parallelApply` time as a proxy for removable setup overhead. A future non-duplicate hypothesis would need direct measurements separating thread-state construction, async launch/scheduler delay, worker-side non-`parallelApply` work, and `future.get()` wait time, and would need to show a new Medium-or-better apply-time saving despite the prior failed PoCs.
