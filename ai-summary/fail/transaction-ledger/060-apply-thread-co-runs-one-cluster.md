# H060: Apply Thread Co-Runs One Cluster Instead of Idling on `future::get`

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (sub-threshold)
**Impact**: apply-time critical-path reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `applySorobanStageClustersInParallel` partitions a stage into N=NUM_CLUSTERS=8 clusters, the apply thread should not block idle on the slowest worker future. Instead, since the apply thread is by definition awake and the work is already partitioned into exactly NUM_CLUSTERS units, the apply thread should execute one of those clusters itself in-line, with the remaining N-1 launched via `std::async`. This adds no parallelism above NUM_CLUSTERS (the configured cap), eliminates one `std::async` task launch (~5-15 µs), and gives the in-line cluster cache-warm execution on the apply thread.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` (src/ledger/LedgerManagerImpl.cpp:2530-2575) currently launches all N cluster apply tasks via `std::async(std::launch::async, ...)` and then iterates over the futures calling `future.get()`. The apply thread is idle during the entire 409 ms (per large soroswap ledger) wait. If the apply thread instead executed one cluster directly while N-1 workers ran async, the critical path would only change if (a) the apply thread is faster than a std::async worker (e.g., due to L1/L2 cache warmth from preceding serial phases), or (b) the std::async launch latency contributes meaningfully. Neither is true for soroswap at scale.

## Trigger

Run soroswap apply-load benchmark on the 7 large ledgers (~409 ms parallel-cluster phase per ledger, 8 deliberately balanced pair-conflict clusters).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:applySorobanStageClustersInParallel:2530-2575` — std::async launch + future.get() wait loop
- `src/ledger/LedgerManagerImpl.cpp:applyThread:2483` — per-cluster apply entry point that would be called in-line

## Evidence

- Apply thread is provably idle during the 409 ms/large-ledger parallel cluster phase (zone `applySorobanStageClustersInParallel` on thr=11, no other apply-thread zones overlap).
- One fewer `std::async` task launch eliminates ~5-15 µs of kernel/futex overhead.
- The apply thread has just finished `GlobalParallelApplyLedgerState` construction and serial pre-parallel-apply, so its L1/L2 may be warm for footprint metadata.

## Anti-Evidence

- Per the benchmark setup (H001 `resplit-artificial-soroban-apply-clusters` reviewer note), the 8 clusters are deliberately balanced footprint-conflict groups. The critical-path cluster time variance is small — the apply-thread cluster choice barely changes max-of-N.
- Even if the apply-thread cluster finishes 5% faster than the worker average, with 8 balanced clusters the max-of-7-workers + 1-apply-thread = essentially the same as max-of-8-workers. Critical-path savings: < 1 ms/ledger.
- The `std::async` launch cost (~10 µs × 1 saved launch) is rounding error against a 409 ms cluster apply.
- Existing async machinery is consistent and isolated; introducing apply-thread re-entrancy into `applyThread` could break `ThreadParallelApplyLedgerState` ownership invariants (it expects to live on a worker thread, not the apply thread that also owns `GlobalParallelApplyLedgerState`).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not duplicated by any prior fail/hypothesis/reviewed/poc entry. Distinct from H051 (move ThreadParallelApplyLedgerState construction into worker — opposite direction) and H003 (parallel fold of `commitChangesFromThreads` — different phase).

### Why It Failed

Total recoverable critical-path budget is bounded above by:
1. The std::async launch overhead difference (~10 µs × 1 task = ~10 µs/ledger, negligible).
2. The cluster-time variance reduction from picking the "fast" cluster for the apply thread. With 8 deliberately balanced footprint-conflict clusters and 409 ms each, even a generous 10% cache-warmth advantage on the in-line cluster gives ~40 ms aggregate but only ~5 ms critical-path benefit (the slowest worker still dominates). At 5 ms / 479 ms = 1.0% per large soroswap ledger, this sits below the objective's Medium threshold and at the boundary of benchmark noise.

The objective context further notes (OUT_OF_SCOPE) that schemes which scale parallelism above `NUM_CLUSTERS` are out of scope. While this proposal does not exceed NUM_CLUSTERS in terms of concurrent execution, it does add re-entrancy complexity to the apply thread (which also holds `GlobalParallelApplyLedgerState`) without a Medium-class win to justify the review burden.

### Lesson Learned

Idle-apply-thread offload only pays when (a) the apply thread can do work that is on the critical path AND (b) the offloaded slice is large relative to per-ledger critical path. For NUM_CLUSTERS-bounded parallel apply with balanced footprint-conflict clusters, the apply thread's idle window is itself the critical path; "co-running" one cluster cannot shorten max-of-N unless the chosen cluster is the slowest one, which is non-deterministic and impossible to know in advance. Future apply-thread-idle reuse proposals must target deferred work that can run concurrently with the slowest worker — not a re-partition of the existing parallel work.
