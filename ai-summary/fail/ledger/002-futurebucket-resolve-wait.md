# H002: Reduce Blocking FutureBucket Resolve Waits During Bucket Commit

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Low
**Impact**: possible p95 apply-time reduction from less bucket-merge blocking
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Bucket merge work should run in the background and should only affect apply time when `BucketLevel::commit` must synchronously promote a future bucket whose merge has not completed. Any optimization for this objective should reduce the blocking `FutureBucket::resolve` wait that occurs inside `applyLedger`, not just speed up background-only merge work.

## Mechanism

`BucketLevel::commit` calls `FutureBucket::resolve`, which clears inputs and then blocks on `mOutputBucketFuture.get()` if the merge output is not ready. The current trace has `FutureBucket::resolve` at `bucket/FutureBucket.cpp:278` with 216 events and 296.100 ms inside `applyLedger` windows, suggesting occasional synchronous wait on unfinished background bucket merges. A possible idea was to resolve or schedule such futures earlier so `addLiveBatch` does not block during sealing.

## Trigger

Run the current soroswap apply-load benchmark over ledgers that spill BucketList levels while previous merges are still running. Inspect `FutureBucket::resolve` events inside `applyLedger` in the baseline Tracy trace.

## Target Code

- `src/bucket/FutureBucket.cpp:274-304` — `resolve()` blocks on `mOutputBucketFuture.get()` when output is not ready.
- `src/bucket/BucketListBase.cpp:167-191` — `BucketLevel::commit()` calls `resolve()` during apply-path bucket commits.
- `src/bucket/BucketListBase.cpp:681-797` — `addBatchInternal()` commits spill levels and only nonblocking-resolves ready futures at the end.

## Evidence

The event-overlap check confirms the wait zone occurs inside `applyLedger`, so the synchronous portion is in scope. `FutureBucket::resolve` self-time is large relative to the small `addLiveBatch` / `addBatchInternal` self-times because the wait occurs in the child `resolve` zone.

## Anti-Evidence

The aggregate wait is only 296.100 ms across 4,591.087 ms of `applyLedger` trace time, and the objective explicitly excludes background bucket merge work except for the blocking wait portion. The source already calls `resolveAnyReadyFutures()` nonblocking at the end of `addBatchInternal`; unresolved futures that still block are unfinished background work, not redundant foreground work. Without changing merge scheduling or worker capacity, there is no clear deterministic, apply-local mechanism to eliminate the wait.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded in ledger fail/hypothesis dirs

### Why It Failed

The only directly measured in-scope portion is the wait for unfinished background work, and the obvious nonblocking cleanup is already present. The likely win is below the objective severity threshold or would require broader background merge scheduling changes that are not clearly apply-path local.

### Lesson Learned

For BucketList hypotheses under this objective, distinguish blocking `FutureBucket::resolve` waits from total merge time. Large `Merge task` totals are not enough; the proposal must reduce synchronous wait inside `applyLedger`.
