# H002: Background bucket merges overlap Soroban apply and may steal critical-path CPU

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by preventing lazy bucket merge CPU contention during measured apply windows
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Lazy bucket merge work should not reduce the measured `closeLedger` apply throughput for soroswap. During the Soroban parallel apply phase, the node should reserve CPU for the configured `NUM_CLUSTERS` apply workers and the apply thread; non-urgent `FutureBucket` merge tasks should either run outside those windows, run at lower priority, or be paused when they would contend with apply workers. Ledger output must remain unchanged: merge scheduling can change, but bucket hashes, future resolution before use, and publication semantics must not.

## Mechanism

`FutureBucket::startMerge` posts merge tasks immediately to the application's background worker pool via `app.postOnBackgroundThread`, and those tasks execute CPU-heavy `BucketT::merge` / index-building work independently of the apply thread. The current soroswap Tracy trace contains `Merge task`, `merge`, `createIndex`, `LiveBucketIndex`, and `InMemoryIndex` events starting inside measured `applyLedger` windows, while some late Soroban stages show large wall time with much smaller contained `parallelApply` worker time. If background merge workers share cores, cache, memory bandwidth, or allocator locks with Soroban apply workers, temporarily quiescing or deprioritizing lazy merge tasks during `applyParallelPhase` should shorten apply wall time without changing deterministic ledger effects.

## Trigger

Run the current diagnostic trace from `ai-summary/CURRENT_STATE.md` and intersect events with `applyLedger` windows:

`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`

The apply-window aggregation shows background bucket work overlapping the measured path:

- `Merge task` total 1,125,689,608 ns across 50 events (`bucket/FutureBucket.cpp:421`)
- `merge` total 1,125,570,787 ns across 50 events (`bucket/BucketBase.cpp:351`)
- `createIndex` total 370,373,170 ns across 22 events (`bucket/BucketIndexUtils.cpp:37`)
- `LiveBucketIndex` total 369,764,420 ns across 21 events (`bucket/LiveBucketIndex.cpp:48`)
- `InMemoryIndex` total 369,611,380 ns across 21 events (`bucket/InMemoryIndex.cpp:309`)

As a concrete reproduction check, run the apply-load matrix twice with an experimental gate that prevents new `FutureBucket` merge tasks from starting while `applyLedger` is in `applyParallelPhase`, then lets them resume before publication/catchup can observe missing futures. If soroswap medians drop reproducibly while bucket outputs remain identical, the contention model is confirmed.

## Target Code

- `src/bucket/FutureBucket.cpp:406-459` — obtains the worker IO context, builds the packaged merge task, stores its future, and posts it to the background worker pool.
- `src/bucket/BucketListBase.cpp:728-797` — level spill/prepare path starts lazy merges from `addBatchInternal` and nonblocking `resolveAnyReadyFutures`.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch` runs on the ledger finalization path and can start new live-bucket merge work.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` and `src/ledger/LedgerManagerImpl.cpp:2672-2705` — Soroban parallel apply windows where background merge quiescence should be active.
- `src/bucket/FutureBucket.cpp:274-304` — `FutureBucket::resolve` remains the correctness boundary; any quiescence scheme must still resolve before a future bucket becomes synchronously needed.

## Evidence

The target is in scope only as a contention hypothesis, not as a direct optimization of lazy background merge throughput. The evidence is that merge/index tasks start during the current `applyLedger` windows and their aggregate CPU time is comparable to several percent of the current soroswap baseline if they contend with the 8 apply lanes. The same trace also shows tail-stage wall times substantially exceeding contained `parallelApply` work, which is consistent with scheduler or CPU-resource contention from work outside the Soroban worker pool.

The proposed design preserves determinism because it does not alter transaction execution, stage order, commit order, or bucket merge contents. It only changes when nonblocking merge tasks are allowed to consume background CPU. It also does not exceed `NUM_CLUSTERS`; it reduces competing background work while the configured apply workers run.

## Anti-Evidence

The objective explicitly excludes lazy bucket merge work when it is merely visible in Tracy and not on the synchronous apply critical path. This hypothesis is only viable if measurement shows real contention or waiting that shortens after merge quiescence; simply reducing `Merge task` time is not sufficient. The benchmark host may also have enough cores that background merges do not affect the 8 Soroban workers, in which case the overlapping zones are harmless and this should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The traced benchmark path drains all live and hot-archive bucket futures immediately before taking the per-ledger timing sample, so no prior-ledger lazy merge should still be running when the measured close begins. Soroban parallel apply then runs inside `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages`; new `FutureBucket` merges are not started on that path. They are posted later from `sealLedgerTxnAndStoreInBucketsAndDB` -> `BucketManager::addLiveBatch` after transaction application has completed, so a gate scoped to `applyParallelPhase` has no new merge tasks to suppress and cannot explain a Medium soroswap apply-time win.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:34-40,120-124,417-423` — the soroswap matrix scenario uses `time_writes=true` by default and writes that into `APPLY_LOAD_TIME_WRITES`, so reported "close time" is the configured apply-load timer.
- `src/simulation/ApplyLoad.cpp:2265-2308` — `benchmarkModelTxTpsSingleLedger` chooses the close or total-apply timer, then calls `resolveAllFutures()` for both live and hot-archive bucket lists before reading `timeBefore`.
- `src/ledger/LedgerManagerImpl.cpp:1668-1688` — `mTotalTxApply` covers fee/sequence processing through `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2784-2915` — `applyTransactions` loads config and invokes `applyParallelPhase` for parallel Soroban phases.
- `src/ledger/LedgerManagerImpl.cpp:2967-3029` and `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applyParallelPhase` builds bundles and calls `applySorobanStages`; stages run before ledger sealing and bucket insertion.
- `src/ledger/LedgerManagerImpl.cpp:3320-3367` — `sealLedgerTxnAndStoreInBucketsAndDB` updates in-memory state asynchronously, adds contracts to the module cache, then calls `BucketManager::addLiveBatch` after transaction application has finished.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch` delegates to `mLiveBucketList->addBatch`, which is the path that can start live-bucket merges.
- `src/bucket/BucketListBase.cpp:169-188` — `BucketLevel::commit` is the synchronous correctness boundary: if a live future is needed, it calls `FutureBucket::resolve()`.
- `src/bucket/BucketListBase.cpp:728-797` — `addBatchInternal` spills levels, prepares new future merges, commits level 0, and only resolves already-ready futures nonblocking.
- `src/bucket/FutureBucket.cpp:274-304` — `FutureBucket::resolve` blocks on `mOutputBucketFuture.get()` only when a future bucket is synchronously required.
- `src/bucket/FutureBucket.cpp:347-459` — `FutureBucket::startMerge` posts the CPU-heavy merge task to the application's background worker pool.

### Why It Failed

The optimization target is not on the relevant measured Soroban parallel-apply critical path. In the apply-load benchmark, pending future buckets are resolved before timing starts, and the source path that posts new lazy merge work is reached only after `applyParallelPhase` completes. The objective also excludes lazy background bucket merge work unless the apply path synchronously waits on it; the only blocking boundary is `FutureBucket::resolve`, and this benchmark deliberately drains futures before measuring. Tracy overlap with broad `applyLedger` windows is therefore insufficient evidence for a Medium apply-time optimization, and the proposed `applyParallelPhase` quiescence gate would be a no-op for newly-started bucket merges.

### Lesson Learned

Do not treat background `Merge task` zones inside broad ledger-close Tracy windows as Soroban apply-worker contention. For bucket futures, first prove either a synchronous `FutureBucket::resolve` wait inside the timed path or a task start that actually occurs before/during `applyParallelPhase`; otherwise the work is lazy bucket maintenance outside this objective's accepted optimization surface.
