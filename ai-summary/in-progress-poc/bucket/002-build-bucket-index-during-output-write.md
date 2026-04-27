# H002: Build Bucket Index Metadata During Output Writes to Shorten Merge Futures

**Date**: 2026-04-27
**Subsystem**: bucket
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing BucketList merge-future stalls during ledger close
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a bucket merge or fresh bucket write finishes, stellar-core should produce the same bucket file, hash, tombstone elisions, index lookup behavior, and BucketList state as it does today. However, constructing the index for the just-written bucket should not require reopening and rereading the same output file when the output iterator has already observed every entry and byte offset in deterministic sorted order.

## Mechanism

`BucketOutputIterator::getBucket` finalizes the output hash, then calls `createIndex` when no prebuilt index is supplied. `createIndex` constructs `LiveBucketIndex` / `DiskIndex` / `InMemoryIndex` by reopening the bucket file and scanning entries that were just serialized by `BucketOutputIterator::put` and `XDRStream::writeOne`. For file-based merges this second pass lengthens background `Merge task` futures; later ledger closes block in `FutureBucket::resolve` when those futures are not ready, so moving index metadata collection into the output-write pass should reduce apply-time stalls without changing deterministic bucket contents.

## Trigger

Run the soroswap apply-load benchmark through ledgers that spill BucketList levels. The issue appears when `BucketListBase::addBatchInternal` promotes a pending future with `BucketLevel::commit`, causing `FutureBucket::resolve` to wait for merge output whose index was built by a second file scan.

## Target Code

- `src/bucket/FutureBucket.cpp:274-303` — `FutureBucket::resolve` blocks the apply path on `mOutputBucketFuture.get()` when a merge has not finished.
- `src/bucket/FutureBucket.cpp:411-428` — background `Merge task` calls `BucketT::merge`.
- `src/bucket/BucketBase.cpp:392-426` — file-based merge writes output through `BucketOutputIterator` and then adopts it.
- `src/bucket/BucketOutputIterator.cpp:141-164` — `put` already sees every output entry in canonical sorted order and tracks `mBytesPut`.
- `src/bucket/BucketOutputIterator.cpp:196-240` — `getBucket` computes the hash and calls `createIndex` if no prebuilt index is available.
- `src/bucket/BucketIndexUtils.cpp:30-50` — `createIndex` constructs an index by scanning the bucket file.
- `src/bucket/DiskIndex.cpp:149-249` and `src/bucket/InMemoryIndex.cpp:119-160` — index constructors reread entries, derive keys/type ranges, offsets, counters, and bloom-filter input.

## Evidence

The current soroswap Tracy trace shows the apply path blocking on bucket futures: `resolve,bucket/FutureBucket.cpp,278` accounts for `296,099,873 ns` across `216` events fully inside `applyLedger` windows. `addLiveBatch,bucket/BucketManager.cpp,1031` contributes `489,540,693 ns` inside apply, and `sealLedgerTxnAndStoreInBucketsAndDB,ledger/LedgerManagerImpl.cpp,3376` contributes `533,841,455 ns`, so bucket sealing is a meaningful part of close time.

The causal background work is visible in the same trace: `Merge task,bucket/FutureBucket.cpp,421` totals `1,742,874,008 ns`, while `createIndex,bucket/BucketIndexUtils.cpp,37` totals `1,146,328,085 ns` over `31` calls. Not every merge/index event is itself inside an `applyLedger` interval because merges run asynchronously, but unresolved merge latency re-enters the measured apply path through `FutureBucket::resolve`. Since the output iterator already has the sorted entry stream and byte position needed for `keysToOffset`, type ranges, counters, asset-to-pool mappings, and key hashes, an index-builder sidecar in the write pass should remove the redundant read/deserialize pass from merge futures.

## Anti-Evidence

`LiveBucket::mergeInMemory` already prebuilds the level-0 in-memory index concurrently from `mergedEntries`, so this hypothesis should target file-based bucket outputs where `preBuiltIndex` is absent. Care is also required for DiskIndex page-boundary semantics and BinaryFuseFilter seed behavior: the builder must reproduce the current `DiskIndex` and `InMemoryIndex` metadata exactly, or fall back to the existing `createIndex` path.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The traced close-ledger path confirms that higher-level BucketList spills start background `FutureBucket` merges, and later spills synchronously promote the pending output through `BucketLevel::commit` / `FutureBucket::resolve`. The merge task writes the canonical output once through `BucketOutputIterator`, then `getBucket` commonly falls through to `createIndex`, which reopens the temp bucket and deserializes the same entries to build `LiveBucketIndex` or `HotArchiveBucketIndex` metadata before adoption. Level-0 live merges are already optimized with `LiveBucket::mergeInMemory` and a prebuilt index, but file-based merges still pay the second pass. The cited `createIndex` time is large relative to merge-task time and plausibly explains enough unresolved future latency to clear the 3% Medium objective floor.

### Code Paths Examined

- `src/bucket/BucketListBase.cpp:292-315` — `BucketLevel::prepare` constructs a `FutureBucket`, launching a file-based merge for levels above the in-memory level-0 path.
- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal` spills levels, calls `mLevels[i].commit()` before starting the next merge, and therefore can block on a previous merge future during closeLedger.
- `src/bucket/BucketListBase.cpp:196-238` and `src/bucket/LiveBucket.cpp:614-697` — the level-0 live path is not the target because it merges vectors in memory, builds `LiveBucketIndex` from `mergedEntries`, and passes `preBuiltIndex` to `getBucket`.
- `src/bucket/FutureBucket.cpp:274-303` — `FutureBucket::resolve` calls `mOutputBucketFuture.get()`, putting unfinished background merge latency directly on the apply path.
- `src/bucket/FutureBucket.cpp:411-428` — the background merge task calls `BucketT::merge`.
- `src/bucket/BucketBase.cpp:392-426` — file-based merge streams old/new inputs into `BucketOutputIterator` and finalizes by calling `out.getBucket(bucketManager, &mk)`.
- `src/bucket/BucketOutputIterator.cpp:78-164` — `put` applies tombstone elision, adjacent same-key replacement, canonical-order assertions, and writes only the flushed buffered entry; this is the right point to feed an index builder with the exact entries that reach disk.
- `src/bucket/BucketOutputIterator.cpp:167-240` — `getBucket` flushes the last buffered entry, closes the file, computes the hash, tries existing-bucket index reuse and supplied `preBuiltIndex`, then otherwise calls `createIndex`.
- `src/bucket/BucketIndexUtils.cpp:30-50` — `createIndex` constructs a fresh bucket index from the just-written filename.
- `src/bucket/LiveBucketIndex.cpp:28-69` — live buckets smaller than the default cutoff use `InMemoryIndex`; larger buckets use `DiskIndex<LiveBucket>`.
- `src/bucket/HotArchiveBucketIndex.cpp:16-29` — hot archive buckets always build a disk index from the file.
- `src/bucket/InMemoryIndex.cpp:119-158` — file-backed in-memory index construction opens the bucket file and rereads every XDR entry, skipping META entries and collecting entries/type ranges/counters.
- `src/bucket/DiskIndex.cpp:132-299` — disk index construction opens the bucket file, rereads each entry, records page range offsets, type boundaries, counters, live asset-to-pool mappings, key hashes for the binary fuse filter, and then persists the index if configured.
- `src/util/XDRStream.h:483-514` — `XDROutputFileStream::writeOne` writes the framed XDR bytes, updates the supplied hash, and increments `bytesPut`, so `BucketOutputIterator` can know each flushed entry's starting offset before the write and ending offset after it.
- `src/bucket/BucketManager.cpp:477-560` — adoption preserves duplicate-bucket behavior and can install a supplied index via `maybeSetIndex`; an output-side builder must keep the existing reuse and race-handling order intact.

### Findings

The inefficiency exists. For normal file-based bucket outputs, `BucketOutputIterator` serializes the canonical stream once and `createIndex` then performs a second file open plus full XDR read/deserialize pass to recover information already available during the write: entry keys, start offsets, type boundaries, counters, asset-to-pool mappings, and key hashes for the bloom-like filter. Existing optimizations only partially mitigate this: duplicate-hash adoption can reuse an index when one already exists, and `LiveBucket::mergeInMemory` avoids the scan for level-0 live merges, but higher-level file merges still pass no `preBuiltIndex`.

The path is hot for this objective. `BucketListBase::addBatchInternal` runs inside bucket sealing during closeLedger; merge tasks run asynchronously, but unfinished work becomes apply latency through `FutureBucket::resolve`. The hypothesis' trace attributes 1.146s of 1.743s merge-task time to `createIndex` and 296ms of apply-window time to `FutureBucket::resolve`; even recovering a substantial fraction of that resolve stall is in the Medium range for a roughly 4.6s apply trace.

The proposed fix is correctness-preserving if implemented as a sidecar builder that observes only entries actually flushed to disk, after tombstone elision and duplicate-key replacement. For disk indexes, the builder must use the pre-write `mBytesPut` as `pos`, reproduce `DiskIndex` page-boundary logic (`pos >= pageUpperBound`), use the same `shortHash::getShortHashInitKey` and retry behavior for `BinaryFuseFilter16`, build the same type ranges via `updateTypeBoundaries` / `buildTypeRangesMap`, and still call the existing index persistence path when `BUCKETLIST_DB_PERSIST_INDEX` is enabled. For in-memory live indexes, the builder must populate the same `InMemoryBucketState`, counters, asset map, and type ranges as the file-backed constructor; for hot archive, only disk-index behavior is required. If any exact-equivalence check fails in tests, falling back to the current `createIndex` path is safe.

### PoC Guidance

- **Target code**: `src/bucket/BucketOutputIterator.{h,cpp}`, `src/bucket/DiskIndex.{h,cpp}`, `src/bucket/InMemoryIndex.{h,cpp}`, `src/bucket/LiveBucketIndex.{h,cpp}`, `src/bucket/HotArchiveBucketIndex.{h,cpp}`, and `src/bucket/BucketIndexUtils.{h,cpp}`.
- **Change description**: Add an output-side index builder used by `BucketOutputIterator` for file-backed outputs. Feed the builder when a buffered entry is actually flushed to `XDROutputFileStream::writeOne`, using the current `mBytesPut` as that entry's file offset. Keep existing behavior for empty buckets, existing-bucket index reuse, caller-supplied `preBuiltIndex`, and shutdown/error fallback. The final index object must compare equal to one produced by `createIndex` for the same bucket file.
- **Correctness check**: Use existing bucket index equality operators under `BUILD_TESTS` to compare output-built indexes against `createIndex` for live small/in-memory, live large/disk, and hot archive buckets. Exercise META entries, tombstone elision at bottom levels, adjacent same-key replacement, liquidity-pool INIT asset mappings, type range scans, page-boundary ranges, and persisted index loading.
- **Benchmark focus**: Measure soroswap apply-load ledgers that spill BucketList levels. The expected win is lower `createIndex`/merge-task wall time and fewer or shorter `FutureBucket::resolve` stalls inside apply; a Medium PoC should show at least a 3% reproducible reduction in top-line apply time.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-27
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/BucketOutputIterator.h:28-67` and `src/bucket/BucketOutputIterator.cpp:25-371` — added output-side index builders, recorded each flushed entry at the pre-write file offset, built a live in-memory or disk index directly from the output stream, and preserved existing-bucket index reuse, caller-supplied prebuilt index reuse, empty-bucket handling, and fallback to `createIndex`.
- `src/bucket/DiskIndex.h:70-151` and `src/bucket/DiskIndex.cpp:59-354` — factored disk-index construction into a reusable `DiskIndex::Builder` that reproduces the previous range-index, type-range, counter, asset-to-pool, and BinaryFuseFilter metadata logic and can persist indexes through the existing save path.
- `src/bucket/LiveBucketIndex.h:100-117`, `src/bucket/LiveBucketIndex.cpp:41-103`, `src/bucket/HotArchiveBucketIndex.h:58-66`, and `src/bucket/HotArchiveBucketIndex.cpp:16-42` — added constructors that wrap output-built disk indexes in the existing public index types.
- `src/bucket/BucketBase.cpp:392-395`, `src/bucket/LiveBucket.cpp:515-518,673-677`, `src/bucket/HotArchiveBucket.cpp:31-34`, `src/bucket/BucketManager.cpp:1670-1672`, `src/bucket/test/BucketTests.cpp:555-556`, `src/history/test/HistoryTestsUtils.h:113-117`, `src/history/test/HistoryTestsUtils.cpp:147-154,240-244`, and `src/invariant/test/BucketListIsConsistentWithDatabaseTests.cpp:185-189` — threaded `Config` into `BucketOutputIterator` construction so it can select the same live in-memory/disk cutoff and disk page size as `createIndex`.

### Demonstration

The optimization builds the bucket index from the exact stream of entries that `BucketOutputIterator` flushes to disk, using the current byte count as each entry's canonical file offset. This removes the normal post-write `createIndex` reopen-and-rescan pass for file-backed live and hot-archive bucket outputs while preserving a fallback path if online index construction cannot complete.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`. `make -j $(nproc)` passed using `ALL_SOROBAN_GIT_STATE_STAMPS=` because this worktree stores submodule gitdirs under the worktree gitdir rather than `.git/modules`. `./src/stellar-core test --ll fatal -r simple --abort --disable-dots "[bucket][bucketindex]"` passed all 12 bucket-index test cases, and `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check ALL_SOROBAN_GIT_STATE_STAMPS=` completed successfully with all tests passing.

---

## Final Review — Needs Revision

**Date**: 2026-04-27
**Final review by**: gpt-5.5, high

### What Needs Fixing

The implementation built and the full test suite passed, but the benchmark result is not reproducible enough to confirm. Using the accepted baseline from `ai-summary/CURRENT_STATE.md` (`soroswap` median apply time 620.996218 ms; `sac` median apply time 709.638870 ms), three independent optimized runs produced:

| Run | sac median | sac delta | soroswap median | soroswap delta |
|-----|------------|-----------|-----------------|----------------|
| 1 | 696.704935 ms | 1.82% faster | 621.093128 ms | 0.02% slower |
| 2 | 747.969470 ms | 5.40% slower | 602.205256 ms | 3.03% faster |
| 3 | 756.642514 ms | 6.62% slower | 622.268604 ms | 0.20% slower |

Only one of three runs clears the 3% Medium threshold, and the two non-winning runs are essentially flat-to-regressed for the soroswap headline metric. The only winning soroswap run also has a max-sac regression above the allowed tradeoff envelope. This fails the final-review requirement that soroswap apply-time improvement be consistent across multiple benchmark runs.

The code audit also found a likely source of overhead that may be contributing to the inconsistent result: `BucketOutputIterator` constructs and feeds output-side index builders for all outputs, including paths that later use a caller-supplied `preBuiltIndex` or `inMemoryState` and discard the collected builder state. In particular, the level-0 live `mergeInMemory` path already builds a prebuilt index asynchronously, but the new iterator still collects duplicate in-memory/disk index metadata while serializing the bucket.

### Revision Instructions

Revise the PoC before another final review:

1. Avoid output-side index collection on paths that will not use it, especially `LiveBucket::mergeInMemory` with `preBuiltIndex` and callers passing `inMemoryState`. If this requires an explicit constructor option or lazy builder initialization, keep the default behavior clear and deterministic.
2. Reduce avoidable large-bucket overhead from accumulating `mInMemoryIndexEntries` up to the live in-memory cutoff when the final bucket will use a disk index, or demonstrate with Tracy that this overhead is below noise.
3. Re-run the apply-load matrix at least 3 times, preferably 5, and require the soroswap median improvement to be consistent. A single good run among flat/regressed runs is not sufficient.
4. Include a Tracy comparison against the accepted baseline showing that the targeted bucket zones (`createIndex`, merge task duration, and/or `FutureBucket::resolve`) moved in the expected direction and that no apparent win is coming from TX-set construction zones.
5. Document the max-sac tradeoff explicitly. If max-sac regresses, the soroswap improvement must be consistently larger and the max-sac regression should stay under the envelope described in the final-review supplement.

### Checks Passed So Far

- Source diff is in scope for the bucket apply path and test edits are mechanical constructor-signature updates only.
- The build succeeds with the configured Tracy flags when using the documented worktree stamp workaround: `make -j30 ALL_SOROBAN_GIT_STATE_STAMPS=`.
- The full suite passes with `env NUM_PARTITIONS=30 make check ALL_SOROBAN_GIT_STATE_STAMPS=`.
- Correctness risk from index metadata equivalence appears covered by existing bucket-index tests, but performance evidence is insufficient for confirmation.
