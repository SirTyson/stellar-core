# H001: Lazy Level-0 Live-Bucket File Materialization

**Date**: 2026-05-20
**Subsystem**: transactions / ledger apply / live bucket finalization
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by moving synchronous level-0 live-bucket disk materialization off the `applyLedger` critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Closing a soroswap ledger should synchronously produce the same `BucketList` hash, in-memory bucket contents, live-bucket index, ledger-close meta, and subsequent ledger read behavior. Persisting the corresponding level-0 live bucket file should not have to block `applyLedger` once the deterministic bucket hash and in-memory representation are available, provided history publication and restart safety still wait for or recover the materialized file before it is externally required.

## Mechanism

`finalizeLedgerTxnChanges` currently blocks on `BucketManager::addLiveBatch`, which calls `LiveBucketList::addBatch` and level-0 `prepareFirstLevel`; the level-0 in-memory merge then serializes and writes the merged bucket before returning the new bucket object. In the current soroswap trace, `addLiveBatch` overlaps `applyLedger` by 265,886,696 ns across 71 apply windows (5.08% of `applyLedger`), with `prepareFirstLevel` at 177,565,298 ns total and `mergeInMemory` at 138,366,164 ns total. A redesign that computes the deterministic bucket hash and installs the in-memory bucket/index synchronously, while materializing/adopting the bucket file on a bounded background worker, would remove most of this serial finalization slice without changing transaction execution or consensus-visible ordering.

## Trigger

Run the current apply-load soroswap benchmark (`soroswap, TX=2000, T=8`) on the accepted baseline trace. Ledgers with many SAC balance writes drive `finalizeLedgerTxnChanges` into `addLiveBatch`, which synchronously builds the level-0 live bucket file before `applyLedger` returns.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges` seals the `LedgerTxn`, launches in-memory-state update asynchronously, but still calls `addLiveBatch` synchronously.
- `src/bucket/BucketManager.cpp:1025-1045` — `BucketManager::addLiveBatch` forwards the live batch to the live bucket list and blocks until it is installed.
- `src/bucket/LiveBucketList.cpp:14-27` — `LiveBucketList::addBatch` calls `addBatchInternal` and then initializes bucket caches before returning.
- `src/bucket/BucketListBase.cpp:196-237` — level-0 `prepareFirstLevel` creates the fresh in-memory-only snap and calls `LiveBucket::mergeInMemory`.
- `src/bucket/LiveBucket.cpp:621-697` — `LiveBucket::mergeInMemory` merges entries, builds an index future, writes the bucket file, waits for the index, and returns the new bucket.
- `src/bucket/BucketOutputIterator.cpp:167-247` — `getBucket` computes the bucket hash and adopts the temp file as the bucket.

## Evidence

The trace path from `ai-summary/CURRENT_STATE.md` was timestamp-filtered against `applyLedger` windows. `applyLedger` totals 5,230,315,999 ns across 71 windows. `sealLedgerTxnAndStoreInBucketsAndDB` overlaps the apply windows by 303,523,146 ns (5.80%), and `addLiveBatch` accounts for 265,886,696 ns (5.08%). The bucket work is a direct descendant of `applyLedger` through `finalizeLedgerTxnChanges`, not TX-set construction and not lazy background merge work.

Structurally, level-0 live buckets already retain `inMemoryState` and accept a pre-built `LiveBucketIndex`; the synchronous file write is needed for the bucket hash and persistence, not for computing transaction results. That suggests a deterministic in-memory hash/install step plus deferred file materialization could preserve observable ledger state while shortening the close critical path.

## Anti-Evidence

The bucket hash is consensus-visible through the ledger header, so the synchronous step must still compute exactly the same record-framed XDR hash as the eventual file. Restart, history publication, bucket GC, and `adoptFileAsBucket` assumptions currently expect a real file at installation time; the PoC must either introduce a durable "pending materialization" state with explicit waits at those boundaries or prove that all consumers can operate from the in-memory bucket until the file exists. The background worker must also be bounded and must not exceed the configured apply parallelism constraints.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The hot path is real: `sealLedgerTxnAndStoreInBucketsAndDB` calls `finalizeLedgerTxnChanges`, which synchronously calls `BucketManager::addLiveBatch`; this descends through `LiveBucketList::addBatch`, `BucketListBase::addBatchInternal`, level-0 `prepareFirstLevel`, `LiveBucket::mergeInMemory`, and `BucketOutputIterator::getBucket` before `snapshotLedger` stores the consensus bucket-list hash. However, the proposed lazy file materialization cannot remove most of the measured `addLiveBatch` slice. The ledger close still has to synchronously produce merged level-0 entries, the exact XDR-framed SHA-256 bucket hash, a usable in-memory `LiveBucketIndex` with counters, and a `BucketList`/`HistoryArchiveState` representation before the ledger state advances.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges` seals LTX changes, starts unrelated hot-archive and in-memory Soroban work asynchronously, but calls `addLiveBatch` synchronously before returning.
- `src/ledger/LedgerManagerImpl.cpp:3371-3419` — `sealLedgerTxnAndStoreInBucketsAndDB` calls `snapshotLedger`, stores the ledger header and `HistoryArchiveState`, then builds the next apply snapshot after `addLiveBatch` has completed.
- `src/bucket/BucketManager.cpp:1025-1045` — `addLiveBatch` forwards to `LiveBucketList::addBatch`, then immediately reports live-bucket size, entry-count, and index-cache metrics that depend on the installed bucket list/indexes.
- `src/bucket/LiveBucketList.cpp:14-27` — `LiveBucketList::addBatch` calls `addBatchInternal` and then `maybeInitializeCaches`, which uses bucket entry counters from each bucket index.
- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal` walks spill levels, then always prepares and commits level 0 synchronously before non-blocking resolution of older background merges.
- `src/bucket/BucketListBase.cpp:196-237` — `prepareFirstLevel` only uses the in-memory fast path when current level 0 already has in-memory entries; otherwise it falls back to normal file-backed `FutureBucket` preparation.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` synchronously merges sorted entry vectors, starts in-memory index construction, writes the merged entries through `LiveBucketOutputIterator`, waits for the index, and returns the bucket with in-memory entries.
- `src/bucket/BucketOutputIterator.cpp:25-74` and `src/bucket/BucketOutputIterator.cpp:167-247` — the iterator writes the protocol metadata entry, hashes exactly what it writes, closes the temp file, finishes the hash, obtains or builds an index, and adopts the file as the canonical bucket.
- `src/bucket/LiveBucketIndex.cpp:84-91`, `src/bucket/LiveBucketIndex.cpp:223-256`, and `src/bucket/InMemoryIndex.cpp:264-303` — in-memory indexes already support serving lookups without file reads, but they still must be available synchronously for current snapshots and metrics.
- `src/bucket/BucketListSnapshot.cpp:171-201`, `src/bucket/BucketListSnapshot.cpp:307-345`, and `src/bucket/BucketListSnapshot.cpp:601-650` — point/bulk loads can be served from cache-hit in-memory indexes, but eviction scanning still opens bucket files directly through snapshot bucket pointers.
- `src/history/HistoryArchive.cpp:530-565` and `src/history/HistoryArchive.cpp:467-508` — `HistoryArchiveState` records bucket hashes and sizes from the live bucket list, and publish preparation later expects bucket hashes to resolve to materialized bucket objects.

### Why It Failed

The inefficiency exists and is on the apply path, but the Medium-tier impact claim is not supported after tracing the required synchronous work. The hypothesis attributes the full 5.08% `addLiveBatch` overlap, or at least the 3.39% `prepareFirstLevel` overlap, to removable file materialization. In the actual path, only a subset of `LiveBucket::mergeInMemory` is clearly deferable: physical temp-file write/adopt/fsync and the persistence wait. The synchronous ledger close still must do the entry conversion/merge, produce the exact bucket hash by hashing the same XDR record stream, build or obtain the live-bucket index/counters, install the bucket in level 0, compute the ledger header bucket-list hash, and construct the new snapshot/HAS. Since the entire `mergeInMemory` zone is only 138,366,164 ns / 5,230,315,999 ns = 2.65% of apply time, and the truly deferable portion is strictly smaller than that, the projected gain falls below the objective's Medium threshold.

The approach would also require a broad pending-materialization state: current non-empty `BucketBase` objects require a filename and file existence, `BucketBase::isEmpty` treats empty filenames as zero-hash empty buckets, snapshot eviction/type scans open bucket files directly, history publication resolves hashes through `BucketManager`, and restart safety relies on persisted HAS bucket hashes corresponding to bucket files. Those constraints are not impossible to redesign around, but they further reduce confidence that this is a clean 3-10% apply-time win.

### Lesson Learned

For level-0 bucket optimizations, separate total `addLiveBatch` overlap from the subset that can actually leave the critical path. Consensus-visible hashing, merged in-memory state, indexes/counters, bucket-list installation, and snapshot/HAS construction remain synchronous; only residual physical file materialization can be deferred, so the maximum plausible recovery here is below the soroswap objective's acceptance floor.
