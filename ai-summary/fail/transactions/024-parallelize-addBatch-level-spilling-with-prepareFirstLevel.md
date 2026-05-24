# H024: Parallelize addBatch Level-Spilling Loop With prepareFirstLevel

**Date**: 2026-05-24
**Subsystem**: transactions (bucket-list apply-blocking surface)
**Severity**: Low
**Impact**: apply-time reduction (soroswap headline)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketListBase::addBatchInternal` is the synchronous apply-blocking core of
`addLiveBatch` (330 ms aggregate, 6.87% of `applyLedger` in the current
soroswap trace). Its two dominant sub-zones operate on disjoint level state
and could in principle run concurrently:

1. **The levels-spilling loop** (`for (i = highest..1)`): for each level that
   should spill on this ledger, calls `mLevels[i-1].snap()`,
   `mLevels[i].commit()` (which performs a `FutureBucket::resolve()` —
   blocking wait on the prior background merge), and
   `mLevels[i].prepare(...)` (kicks off the next merge). Aggregate apply-path
   `resolve` time on the live BucketList is 136 ms = 2.83% of `applyLedger`.
2. **`mLevels[0].prepareFirstLevel(...)`**: synchronous in-memory merge of
   the new level-0 snap with the existing level-0 curr, then writes a real
   level-0 file with hash + index. Aggregate 189 ms = 3.94% of `applyLedger`
   (`freshInMemoryOnly` 40.7 ms + `mergeInMemory put loop` 74 ms +
   `mergeInternal` ~50 ms + small constant overhead).

Expected: a correct apply path should overlap these two independent CPU/IO
streams so the critical path becomes
`max(levels_loop, prepareFirstLevel) + commit/resolveAnyReadyFutures`,
rather than the current `levels_loop + prepareFirstLevel + ...` serial sum.

## Mechanism

The two sub-flows touch disjoint `mLevels[i]` slots for the level-0 in-memory
merge path used at every soroswap ledger:

- `prepareFirstLevel` writes `mLevels[0].mNext` (in-memory shell + level-0
  output file). It does not read `mLevels[i]` for `i >= 1`.
- The spilling loop pulls `mLevels[i-1].snap()` (only at spill ledgers) and
  commits / prepares `mLevels[i]`. For level-0 spilling at even ledgers, it
  reads `mLevels[0].mCurr` BEFORE `prepareFirstLevel` mutates
  `mLevels[0].mNext`, so the snap is taken from the still-stable curr.

Anti-evidence on closer reading: when level-0 spills (ledger % 2 == 0),
`mLevels[0].snap()` rotates `mCurr` into a (now-stale) snap, and the new
level-0 incoming material becomes the new `mNext` via `prepareFirstLevel`.
The level-1 spilling work uses the just-rotated level-0 snap as input to
`startMerge` (line 769). So the spilling loop reads level-0 state that was
just rotated. If `prepareFirstLevel` ran concurrently it would not mutate
`mCurr` (only `mNext`), so the snap and curr that level-1 prepare needs are
stable. The parallelization is structurally feasible.

## Trigger

Run the soroswap apply-load benchmark on the current baseline; observe
`addLiveBatch` ≈ 330 ms aggregate, with the synchronous serialization of the
spilling loop and `prepareFirstLevel` accounting for the entire 6.87% of
`applyLedger`.

## Target Code

- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal` — serialize
  levels loop and `prepareFirstLevel`.
- `src/bucket/BucketListBase.cpp:169-191` — `BucketLevel::commit` calls
  `FutureBucket::resolve()` which is the dominant 136 ms blocking wait.
- `src/bucket/BucketListBase.cpp:196-238` — `prepareFirstLevel` is the
  189 ms synchronous in-memory merge + put-loop + index-build path.
- `src/bucket/LiveBucket.cpp:614-698` — `mergeInMemory` already runs index
  build async inside prepareFirstLevel; the put loop and `mergeInternal`
  remain on the apply thread.

## Evidence

- Apply-path `resolve` total on `bucket/FutureBucket.cpp:278` for the live
  BucketList = 136.27 ms = 2.83% of `applyLedger` (78 events / 72 ledgers).
- `prepareFirstLevel` total = 189.30 ms = 3.94% of `applyLedger` (73 events).
- Sum 325 ms ≈ matches the 330 ms `addLiveBatch` total, confirming these
  two pieces account for essentially all of the apply-blocking bucket work.
- OBJECTIVE explicitly allows targeting blocking bucket work waited on by
  apply (e.g., unfinished `FutureBucket::resolve` during `BucketLevel::commit`).

## Anti-Evidence

- The two streams DO touch overlapping `BucketManager`-level state
  (merge counter increments, `incrMergeCounters<LiveBucket>` from both
  `mergeInMemory` and from `mergeInternal` inside the background `Merge task`
  spawned by `startMerge`). These updates are thread-safe but contend.
- The remaining serial work in `mLevels[0].commit()` and final
  `resolveAnyReadyFutures()` cannot be removed.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (prior bucket fails
(`001-lazy-level0-live-bucket-file-materialization.md`,
`002-raw-xdr-live-bucket-writes.md`,
`004-blocking-live-bucket-put-loop-below-threshold.md`) targeted lazy file
writes, raw XDR sidecar writers, and pipelining the put loop respectively;
none targeted parallelizing the spilling loop with `prepareFirstLevel`).

### Why It Failed

Critical-path savings are bounded by `min(resolve_time, prepareFirstLevel_time)
= min(136 ms, 189 ms) = 136 ms ≈ 2.83% of applyLedger`. This is strictly
below the 3% Medium floor specified in the objective's SEVERITY_SCALE.

A real implementation would also incur:
- Thread spawn / join overhead (`std::async` or similar): a few hundred µs
  per ledger × 73 ledgers ≈ a few ms baseline.
- Possible contention on `BucketManager`'s thread-safe counters and
  thread-pool for `startMerge` background tasks.
- API surface changes across `BucketListBase`, `BucketLevel`, and
  `addLiveBatch` callers.

Net projected savings would be measurably below 2.83% after subtracting
parallelization overhead — well below the Medium floor. Per the
objective's rules, hypotheses with projected impact in the Low range
(1–3%) are not accepted at the hypothesis stage and must be written to
`ai-summary/fail/`.

### Lesson Learned

`addLiveBatch`'s blocking-apply surface is structurally bounded by
`max(resolve_time, prepareFirstLevel_time)` after parallelization, not by
their sum. Future bucket-pipeline hypotheses should verify that the
parallelizable portion exceeds the Medium floor on the longer of the two
serial streams (not just their sum). For the current soroswap baseline,
`prepareFirstLevel` at 3.94% is itself just barely above Medium, but
removing it from the critical path saves only the SHORTER stream
(`resolve` at 2.83%) — not the long one. This is a general property of
parallelizing two serial streams: the savings equal `min`, not `max`.
