# H061: Streaming `commitChangesFromThreads` Fold As Worker Futures Complete

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (sub-threshold)
**Impact**: apply-time critical-path reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStage` should overlap the apply-thread-serial `commitChangesFromThreads` fold (per-thread `mThreadEntryMap` → `mGlobalEntryMap` merge) with the still-running slowest cluster worker. Specifically: as each worker future completes, the apply thread should immediately drain that thread's per-thread state into the global map — instead of the current pattern, where the apply thread waits for ALL N futures via the existing `future.get()` loop AND THEN performs the entire N-thread fold serially in `commitChangesFromThreads`. By the time the slowest worker completes, only its own thread map remains to be folded into the global map. Critical-path = max(worker_i) + (1/N) * commit_total, instead of max(worker_i) + commit_total.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` (src/ledger/LedgerManagerImpl.cpp:2556-2572) currently collects all N=8 futures sequentially in launch order via `future.get()`, then `commitChangesFromThreads` runs on the apply thread serially over the N thread states. The 8 thread folds happen entirely after the slowest worker finishes. If the apply thread instead waited on completed-future readiness (e.g., a completion queue, or polling-with-yield), it could begin folding the 7 fast workers' maps into the global map while the slowest worker is still executing. This is structurally distinct from H003 (`parallel-fold-commitchangesfromthreads`) which proposed N-way parallel reduction of the fold; this proposal keeps the fold sequential on the apply thread but pipelines it with the in-flight slowest worker.

## Trigger

Run soroswap apply-load on the 7 large ledgers (479 ms/ledger; 8 balanced pair-conflict clusters; `commitChangesFromThreads` ~9 ms/ledger serial on apply thread after all workers join).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:applySorobanStageClustersInParallel:2556-2573` — sequential `future.get()` loop
- `src/ledger/LedgerManagerImpl.cpp:applySorobanStage:2656` — `commitChangesFromThreads` call site
- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState::commitChangesFromThreads:908` — per-thread fold loop body

## Evidence

- Per Tracy aggregation on 7 large soroswap ledgers: `commitChangesFromThreads` = 63 ms / 7 = 9 ms/ledger serial on thr=11 (apply thread).
- `applySorobanStageClustersInParallel` end-to-end = 2862 ms / 7 = 409 ms/ledger; the gap to `applySorobanStage` (418 ms/ledger) is ~9 ms — matches `commitChangesFromThreads`.
- The apply thread is provably idle during the 409 ms cluster-apply phase (no overlapping apply-thread zones).
- Std::future supports `wait_for(0ms)` polling for non-blocking completion checks; conversion to `std::experimental::when_any` or a completion-queue is straightforward.

## Anti-Evidence

- Soroswap clusters are deliberately balanced (per H001 `resplit-artificial-soroban-apply-clusters` reviewer note, 8 true footprint-conflict components of comparable size). The variance between fastest and slowest worker is small — the overlap window for the 7 fast workers is bounded by that variance.
- Cluster wall-clock variance on the trace: examining per-worker `parallelApply` totals (22250 ms aggregate / 8 workers / 7 ledgers ≈ 397 ms/worker/ledger; cluster phase = 409 ms/ledger) — variance is ~12 ms (3%).
- With 7 fast workers each ~390-395 ms and 1 slow worker at ~409 ms, the apply thread has ~15-20 ms to fold 7 thread maps. The 9 ms full fold easily fits in that window — making the fold completely hidden — but only saves the 9 ms that would otherwise run after the slowest worker.
- 9 ms / 479 ms = 1.9% per large soroswap ledger — below the Medium (3%) threshold.
- Implementation requires either polling with thread-yielding (CPU waste on apply thread) or restructuring to `std::experimental::when_any` / hand-rolled completion queue with mutex+condvar — non-trivial review burden.
- `commitChangesFromThreads` mutates `mGlobalEntryMap` which is shared across stages; ordering of per-thread folds must be deterministic. Streaming completion is order-non-deterministic, so the fold must still be applied in a deterministic canonical order (e.g., cluster index) — meaning the apply thread cannot apply thread-k's fold immediately, only buffer it until threads 0..k-1 are ready. This collapses most of the overlap benefit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H003 (`parallel-fold-commitchangesfromthreads`, which parallelizes the fold itself across N reducers) and from H051 (`parallelize-per-cluster-thread-state-setup-into-worker`, which targets ctor work). This proposal pipelines the existing serial fold with the in-flight slowest worker.

### Why It Failed

Two compounding limits push savings below the Medium floor:

1. **Determinism ordering constraint**: `commitChangesFromThreads` must apply per-thread folds in a canonical order (cluster index) to produce identical `mGlobalEntryMap` state across nodes. Even if thread 5 completes first, its fold cannot be applied until threads 0..4 are done. With balanced clusters, all threads finish near-simultaneously, so the deterministic-order serialization eliminates most of the apply-window overlap.

2. **Absolute ceiling**: `commitChangesFromThreads` is only 9 ms / 479 ms = 1.9% of large-ledger apply time. Even if 100% of the fold could be hidden behind the slowest worker (only true under non-deterministic ordering, which is out-of-scope per OBJECTIVE OUT_OF_SCOPE), the critical-path saving is 1.9% — below the 3% Medium floor and within benchmark noise.

Combined with the meta-pattern #6 cluster-normalization rule (already-low aggregate fold time / N reducer arms gives near-zero per-fold cost) and meta-pattern #5 (sub-threshold narrow fixes), this proposal cannot reach Medium.

### Lesson Learned

Streaming-completion overlap of per-thread reductions with in-flight workers requires (a) cluster timing variance large enough to provide a meaningful overlap window AND (b) deterministic merge order that does not collapse into "wait for first cluster anyway". For soroswap's deliberately balanced 8-cluster shape and stellar-core's determinism requirements, both conditions fail. Future overlap-with-slowest-worker proposals must target work that (a) is order-independent (no canonical-order constraint), (b) is at least 3%+ of apply time even before overlap accounting, and (c) has cluster variance large enough that the slowest cluster is identifiable and dominates.
