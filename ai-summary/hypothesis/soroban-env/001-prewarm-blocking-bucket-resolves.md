# H001: Prewarm Blocking Bucket Resolves Before Apply Commit

**Date**: 2026-05-24
**Subsystem**: soroban-env / bucket apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by overlapping unfinished bucket merge/index work before `BucketLevel::commit` blocks in the measured close-ledger path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Bucket merges may continue to run on background workers, but the measured `applyLedger` critical path should avoid synchronously waiting for the unfinished tail of a merge/index build at the moment a bucket level is committed. If a future bucket is already known to be required by an upcoming spill, the apply path should either resolve it earlier while other deterministic apply work is still running or proactively wait/poll at a point that overlaps with parallel Soroban execution, then commit the already-resolved output in the same bucket-level order.

## Mechanism

`BucketLevel::commit` calls `FutureBucket::resolve` when `mNextCurr` is a live `FutureBucket`. `resolve` clears inputs and then blocks on `mOutputBucketFuture.get()` if the merge output is not ready, which can pull unfinished merge and index-construction work into the synchronous `applyLedger` window. The current bucket list code already has nonblocking `resolveAnyReadyFutures`, but it only resolves futures that are done; a targeted apply-time prewarm for levels that will spill in the current ledger could start the wait earlier, or otherwise schedule/index-prime the needed output, so the same future completion cost is overlapped with independent Soroban cluster work instead of paid at the commit barrier.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`TX=2000,T=8`). Soroswap's high write volume produces frequent bucket updates; when a level spill occurs and the previous `next` merge is still unfinished, `BucketListBase::addBatch` commits that level and may block on `FutureBucket::resolve` before the ledger close can finish.

## Target Code

- `src/bucket/BucketListBase.cpp:167-191` — `BucketLevel::commit` synchronously calls `arg.resolve()` for live future buckets.
- `src/bucket/FutureBucket.cpp:274-304` — `FutureBucket::resolve` blocks on `mOutputBucketFuture.get()` and promotes the result to `FB_LIVE_OUTPUT`.
- `src/bucket/FutureBucket.cpp:411-459` — merge tasks run on background workers and build the output bucket asynchronously.
- `src/bucket/LiveBucketIndex.cpp:41-70` — live bucket output construction may build an in-memory or disk index before the future becomes ready.
- `src/bucket/BucketIndexUtils.cpp:30-50` — `createIndex` constructs the bucket index used by the output bucket.
- `src/bucket/BucketListBase.cpp:740-783` — `addBatch` determines spill order, commits higher levels, prepares new merges, then commits level 0.
- `src/bucket/BucketListBase.cpp:785-796` and `src/bucket/BucketListBase.h:534-539` — existing nonblocking `resolveAnyReadyFutures` only adopts futures that are already complete.

## Evidence

The objective explicitly excludes lazy bucket work unless the apply path synchronously waits on it. The current soroswap diagnostic trace shows apply-contained blocking and index work: unwrap containment reports 447 `resolve` events inside `applyLedger` totaling 123,214,928 ns, 21 `LiveBucketIndex` events inside `applyLedger` totaling 350,497,193 ns, and 92 `InMemoryIndex` events inside `applyLedger` totaling 394,789,199 ns. These are not TX-set construction zones; they occur during the measured `applyLedger` windows, and `FutureBucket::resolve` is the code path that turns unfinished background merge/index work into a synchronous wait.

This differs from rejected bucket-scan hypotheses that targeted point lookup or background merge totals. The proposed optimization targets only the unfinished portion that `applyLedger` actually waits for, and preserves determinism by keeping bucket commit order unchanged and merely moving when the wait is incurred.

## Anti-Evidence

The full `LiveBucketIndex` and `InMemoryIndex` apply-contained totals may include worker execution that overlaps with apply and is not fully on the critical path; the safely claimable portion is the `FutureBucket::resolve` blocking tail. A viable PoC needs timeline instrumentation proving that prewarming reduces the blocking part of `resolve` rather than just moving identical wait time earlier, and must not exceed the existing background-worker / `NUM_CLUSTERS` concurrency assumptions or change bucket hashes, spill order, publication state, or restart semantics.
