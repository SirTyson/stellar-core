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
