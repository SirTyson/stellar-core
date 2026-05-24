# H002: Hash-First Level-0 Bucket Commit With Deferred File Adoption

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / bucket
**Severity**: Medium
**Impact**: reduce synchronous ledger-seal time by separating consensus bucket hash production from bucket file/index adoption
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

At the end of `closeLedger`, the live BucketList snapshot must expose the exact same `bucketListHash` and deterministic entry ordering as today's `addLiveBatch` path before the new ledger header is published. However, the apply thread should not have to finish all level-0 bucket file adoption and index plumbing synchronously if it can compute the bucket hash from the sorted in-memory merge output first and hand the identical file/index materialization to a background task whose completion is required only before the bucket is read from disk or published.

The correct behavior is a snapshot that is hash-complete and read-complete from in-memory entries immediately, with the on-disk bucket file atomically adopted later under the same hash.

## Mechanism

Prior addLiveBatch deferral hypotheses failed because `snapshotLedger` immediately needs the live BucketList hash. The current `LiveBucket::mergeInMemory` already separates the expensive pieces structurally: it first merges into `mergedEntries`, then writes each entry through `LiveBucketOutputIterator::put`, computes the hash in `getBucket`, waits for index construction, and adopts the file as a bucket. The deviation is that the hash and readable in-memory bucket state are only produced after the synchronous write/adopt path, even though the deterministic `mergedEntries` vector is already available.

A hash-first level-0 bucket path would compute the bucket hash directly from `mergedEntries` using the same XDR framing and hasher as `BucketOutputIterator`, create a `LiveBucket` backed by the in-memory entries and prebuilt index under that hash, update the BucketList snapshot immediately, and defer file write/adoption to a background future that asserts it produces the same hash. This addresses the structural blocker recorded in the fail summary rather than trying to defer `addLiveBatch` past `snapshotLedger` without a replacement hash source.

## Trigger

Run `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` with `APPLY_LOAD_TIME_WRITES=true`. Instrument the level-0 `mergeInMemory put loop`, `BucketOutputIterator::getBucket`, and `snapshotLedger` boundary. The trigger is a ledger whose level-0 live bucket is produced from in-memory `initEntries/liveEntries/deadEntries`, where immediate consumers can read the newly merged entries from memory and do not need the just-written bucket file before the ledger header hash is computed.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3365` — `finalizeLedgerTxnChanges` launches independent async writers, calls `addLiveBatch`, then waits before returning to snapshot/publish.
- `src/bucket/BucketListBase.cpp:681-797` — `addBatchInternal` synchronously calls `prepareFirstLevel` and commits level 0 before `snapshotLedger` can compute `bucketListHash`.
- `src/bucket/LiveBucket.cpp:621-697` — `mergeInMemory` materializes `mergedEntries`, starts index construction, writes the bucket file, waits for the index, and returns a bucket with in-memory state.
- `src/bucket/BucketOutputIterator.cpp:76-165` — `put` serializes sorted bucket entries into a file and updates the same hash needed for the bucket identity.
- `src/bucket/BucketOutputIterator.cpp:167-255` — `getBucket` finishes the hash, creates or reuses an index, and adopts the temporary file as a bucket.

## Evidence

- The fail summary establishes the key structural fact: `addLiveBatch -> snapshotLedger -> bucketListHash` is mandatory and synchronous because `snapshotLedger` needs the hash. This hypothesis targets that exact dependency by producing the hash before file adoption instead of simply deferring the whole batch.
- `LiveBucket::mergeInMemory` already retains `mergedEntries` in memory and passes them into `out.getBucket(..., std::make_unique<std::vector<BucketEntry>>(std::move(mergedEntries)), preBuiltIndex)`, so the new level-0 bucket can be read from memory while disk materialization completes.
- Existing failed records put `addLiveBatch`/level-0 bucket work in the low-single-digit ms per ledger range. That was below Medium when only partially optimized, but a hash-first design can remove the synchronous file write/adopt/index-wait portion from the apply critical path while preserving the consensus hash.

## Anti-Evidence

- This is a BucketList state-machine redesign, not a surgical local edit. It must define what happens on crash between hash publication and file adoption, and startup/catchup must either finish or reject incomplete hash-first bucket materialization safely.
- The deferred writer must use byte-for-byte identical serialization and assert the computed hash matches the published in-memory bucket hash; otherwise this becomes consensus-risky.
- If current level-0 write/adopt time is only ~1-2% of the 211 ms baseline after native Soroswap optimizations, the change may still fall below Medium despite addressing the structural blocker.
- Background bucket work is out of scope unless the apply path currently waits on it; the measurable win is only the synchronous portion that blocks `snapshotLedger`, not lazy merge work that already runs off-thread.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — this hash-first variant is distinct from the prior whole-`addLiveBatch` and `getBucket`-only deferral records, but those records already bound the relevant bucket-write savings
**Failed At**: reviewer

### Trace Summary

The close-ledger path seals the `LedgerTxn`, extracts init/live/dead vectors, calls `BucketManager::addLiveBatch`, then only after that unseals the ledger header to call `snapshotLedger`, persist the `HistoryArchiveState`, and publish the new `CompleteConstLedgerState`. Level 0 is committed synchronously through `prepareFirstLevel`, `LiveBucket::freshInMemoryOnly`, `LiveBucket::mergeInMemory`, `BucketOutputIterator::put`, and `BucketOutputIterator::getBucket`; the resulting bucket hash feeds `BucketListBase::getHash` and then `LedgerHeader.bucketListHash`. Snapshot reads can use an in-memory index cache hit, but bucket objects are otherwise immutable file-backed artifacts used for future merges, persistence, GC, and restart recovery.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3331-3367` — `finalizeLedgerTxnChanges` seals the transaction, starts independent in-memory-state work, then calls `addLiveBatch` synchronously before returning.
- `src/ledger/LedgerManagerImpl.cpp:3408-3418` — after `finalizeLedgerTxnChanges`, `snapshotLedger` sets `bucketListHash`, then the header and `HistoryArchiveState` are persisted.
- `src/bucket/BucketManager.cpp:1026-1045` — `addLiveBatch` updates the live BucketList and reports size/cache metrics immediately.
- `src/bucket/BucketListBase.cpp:196-238` — level 0 builds an in-memory snap bucket, calls `LiveBucket::mergeInMemory`, and installs the returned bucket as `mNextCurr`.
- `src/bucket/BucketListBase.cpp:169-191,781-783` — `commit` promotes the in-memory merge result into `mCurr` before `addBatchInternal` returns.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` builds `mergedEntries`, starts index construction, writes every entry through the output iterator, waits for the index, and returns `out.getBucket`.
- `src/bucket/BucketOutputIterator.cpp:76-255` — `put` buffers, serializes, writes, and hashes framed XDR records; `getBucket` closes the stream, finalizes the hash, chooses/builds an index, and adopts the file.
- `src/bucket/BucketBase.h:74-105` and `src/bucket/BucketBase.cpp:59-106` — bucket filename and hash are `const`; non-empty buckets are constructed with an existing filename, and `isEmpty` asserts that empty filename and zero hash agree.
- `src/bucket/BucketInputIterator.cpp:128-145` — file-based iterators only open the bucket filename present at construction time; an empty filename yields no entries.
- `src/bucket/FutureBucket.cpp:36-83,347-459` — higher-level merges capture input bucket shared pointers, record their hashes, and later run `BucketT::merge` on those same bucket objects.
- `src/bucket/BucketListSnapshot.cpp:170-201,210-277` — point and bulk snapshot reads can consume `CACHE_HIT` entries from an in-memory index, but `FILE_OFFSET` results require the bucket file.

### Why It Failed

The proposed "hash-first" bucket is not representable in the current BucketList model. `LiveBucket`/`BucketBase` objects are immutable once constructed: the filename and hash are `const`, the file-backed constructor asserts the file exists, and `isEmpty` treats `filename.empty()` with a nonzero hash as an invariant violation. A background adoption task cannot later mutate the already-published bucket pointer into a file-backed bucket; if a future level-1 merge captures the hash-first bucket before materialization, `BucketInputIterator` will still see the original empty filename and read no entries.

The durability boundary is also load-bearing. `snapshotLedger` is immediately followed by persisting the `HistoryArchiveState` and ledger header; publishing a hash before the corresponding bucket file is adopted creates a crash window where the node's durable LCL references a missing bucket. Waiting for adoption before this DB/header persistence would restore the existing synchronous critical path, while making it safe would require a new pending-materialization journal or mutable/lazy bucket-file abstraction across snapshots, merges, GC, startup, and history publication.

Finally, the impact is below this objective's Medium threshold even if the engineering issues were solved. Existing transaction-ledger fail records measured the whole `addBatchInternal`/`addLiveBatch` bucket path around 4.5 ms per ledger on a 211 ms soroswap baseline (~2.1%), with `getBucket`/adoption and the level-0 put loop individually in the tens-of-microseconds range. This hypothesis can only remove a subset of that already sub-3% path, so it is below the optimize-soroswap review floor.

### Lesson Learned

Producing the consensus hash earlier is not enough for a viable BucketList apply optimization: the bucket object also has to remain a durable, immutable, file-backed artifact for future merges and restart recovery. Future bucket hypotheses need a measured >3% apply-time target that changes actual merge/materialization work, not just the publication point of a sub-threshold level-0 write.
