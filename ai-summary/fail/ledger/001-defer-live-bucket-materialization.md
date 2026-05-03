# H001: Defer synchronous live-bucket materialization behind a snapshot-visible level-0 overlay

**Date**: 2026-05-03
**Subsystem**: ledger / BucketList commit on apply path
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by removing most synchronous `addLiveBatch` work from the apply critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Closing a soroswap ledger should make the new live BucketList state visible to
the next ledger and commit the deterministic bucket-list hash, but it should not
need to synchronously serialize and hash the entire level-0 bucket file before
`snapshotLedger`. The apply thread should be able to publish a snapshot that can
answer reads from the just-produced level-0 batch while deterministic bucket-file
materialization finishes off-thread.

## Mechanism

`LedgerManagerImpl::finalizeLedgerTxnChanges` currently calls
`BucketManager::addLiveBatch` synchronously immediately before
`sealLedgerTxnAndStoreInBucketsAndDB` calls `snapshotLedger`; this makes the
whole `LiveBucketList::addBatch` / `BucketListBase::addBatchInternal` /
`LiveBucket::mergeInMemory` pipeline a hard apply-thread barrier. A structural
change could commit the new level-0 batch as a hashable, snapshot-visible
in-memory overlay/future bucket, compute the deterministic bucket hash from the
same ordered entries, and let the serialize/hash/write/index materialization
complete in the background before publication or GC needs the bucket file. This
differs from local streaming or async-launch reorderings: it moves the
`snapshotLedger` dependency from "bucket file exists" to "deterministic
level-0 contents are sealed and readable", preserving observable ledger order.

## Trigger

Run the current `scripts/run_apply_load_matrix.py --tracy` soroswap workload
(`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`). Each ledger
after sealing calls `finalizeLedgerTxnChanges`, synchronously writes the live
batch, then immediately snapshots the BucketList hash.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3331-3367` — seals the `LedgerTxn`, launches
  in-memory state update async, then synchronously calls `addLiveBatch`.
- `src/ledger/LedgerManagerImpl.cpp:3408-3418` — calls `snapshotLedger` and
  constructs the next `CompleteConstLedgerState` immediately after
  `finalizeLedgerTxnChanges`.
- `src/bucket/BucketManager.cpp:1025-1046` — synchronous `addLiveBatch` wrapper.
- `src/bucket/LiveBucketList.cpp:14-27` and
  `src/bucket/BucketListBase.cpp:681-797` — live `addBatch` and level-0 commit
  sequence.
- `src/bucket/LiveBucket.cpp:621-697` — `mergeInMemory`, including the
  synchronous put loop and bucket construction.

## Evidence

The current soroswap trace records `applyLedger` total time of
5,230,315,999 ns over 71 ledgers. Inside that envelope, `addLiveBatch` totals
296,423,547 ns / 72 calls, about 5.7% of `applyLedger`; its child
`addBatchInternal` totals 294,677,433 ns, and `mergeInMemory` totals
138,366,164 ns. The source ordering shows this work is not background bucket
merge noise: it runs directly on the apply thread before `snapshotLedger`, so a
design that removes most of the synchronous live-batch materialization can meet
the Medium threshold.

## Anti-Evidence

The ledger header hash must remain deterministic and must not depend on a
background race. The optimization is only viable if the sealed overlay/future
bucket has a deterministic hash and read interface before `snapshotLedger`, and
if publication/history/GC cannot observe a missing bucket file. Prior rejected
bucket hypotheses show that local `mergeInMemory` put-loop tweaks and short
async reorderings are too small; this requires a broader barrier redesign.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to `013-async-addlivebatch-overlap-in-finalize.md`, but not a duplicate; this proposal changes the snapshot/materialization contract rather than only reordering work before the existing `snapshotLedger` barrier.
**Failed At**: reviewer

### Trace Summary

The close path seals the `LedgerTxn`, extracts init/live/dead vectors, runs `addLiveBatch`, then immediately unseals the header to call `snapshotLedger`, persist the ledger header plus `HistoryArchiveState`, and build the next `CompleteConstLedgerState`. Level-0 live-bucket ingestion currently creates an in-memory snap, synchronously merges it with level-0 curr, writes and hashes the bucket stream, adopts the canonical file, and only then commits that bucket as level-0 curr. The proposed overlay would need to satisfy three consumers before the ledger close can safely finish: the deterministic header hash, the next snapshot's read API, and the persisted HAS/header restart contract. The first and third consumers keep a synchronous barrier that the hypothesis does not account for.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3437-3473` — `getAllEntries` seals the transaction, starts in-memory Soroban update asynchronously, then calls `BucketManager::addLiveBatch` synchronously before returning.
- `src/ledger/LedgerManagerImpl.cpp:3514-3525` — immediately after `finalizeLedgerTxnChanges`, `snapshotLedger`, `storePersistentStateAndLedgerHeaderInDB`, and `advanceApplySnapshotAndMakeLedgerState` run under the same seal flow.
- `src/ledger/LedgerManagerImpl.cpp:3271-3318` — persistent state stores a HAS built from the current BucketLists and the last-closed ledger header; the HAS contains bucket hashes, not the overlay contents needed to recover a missing file.
- `src/bucket/BucketManager.cpp:1025-1046` and `src/bucket/BucketManager.cpp:1106-1124` — `addLiveBatch` mutates `mLiveBucketList`; `snapshotLedger` hashes the live and hot-archive BucketList hashes into the ledger header.
- `src/bucket/BucketListBase.cpp:196-238`, `src/bucket/BucketListBase.cpp:681-797` — level 0 uses `freshInMemoryOnly`, `mergeInMemory`, `setNextInMemory`, and immediate `commit`; higher levels may also synchronously commit prior futures before the new level-0 bucket is installed.
- `src/bucket/LiveBucket.cpp:531-561` and `src/bucket/LiveBucket.cpp:613-697` — the transient in-memory snap has no durable hash/file, while `mergeInMemory` produces the real bucket by merging entries, building an index, writing/hash-finalizing the bucket stream, and adopting the result.
- `src/bucket/BucketOutputIterator.cpp:169-248` and `src/bucket/BucketManager.cpp:445-560` — `getBucket` obtains the hash from the serialized stream and adopts/renames the canonical bucket file before returning a shared `LiveBucket`.
- `src/bucket/BucketBase.cpp:34-41`, `src/bucket/BucketBase.cpp:99-110`, and `src/bucket/BucketListSnapshot.cpp:171-196` — non-empty snapshot buckets are expected to have a filename and index; an in-memory-only `LiveBucket` with empty filename/zero hash is treated as empty, not as a snapshot-visible bucket.
- `src/history/HistoryArchive.cpp:530-565` and `src/history/HistoryArchive.cpp:234-255` — HAS construction records each level's curr/snap hashes and recomputes the bucket-list hash from those strings.

### Why It Failed

The proposal removes the wrong barrier. `snapshotLedger` cannot commit a deterministic BucketList hash from an unmaterialized level-0 bucket unless core has already computed the exact hash of the canonical bucket byte stream. That hash is produced by serializing and hashing the ordered bucket entries in `BucketOutputIterator`, so the hash-critical part of materialization remains synchronous even if file adoption is delayed.

More importantly, the ledger close path persists the last-closed header and `HistoryArchiveState` immediately after `snapshotLedger`. That persistent state only names buckets by hash. If the level-0 bucket file is still being materialized in the background and the process crashes after the DB state is committed, restart/catchup can see a HAS and header that reference a bucket hash with no canonical bucket file to reload. Correctness therefore requires either blocking before persistent-state commit until the bucket is durably reconstructable, or adding a new durable recovery log for overlay contents; the hypothesized "finish before publication or GC needs the bucket file" is too late.

Even ignoring the durability blocker, the existing snapshot/query layer does not already support a non-empty hash-bearing bucket without a file: `BucketBase::isEmpty` treats empty-filename/zero-hash buckets as empty, `getIndex` asserts a filename, and snapshot reads open the bucket file when the index returns a file offset. Supporting a snapshot-visible overlay would be a broad new bucket representation, while still needing synchronous canonical hash computation. The remaining deferrable file-write/adopt/index fraction is bounded below the objective's Medium threshold, consistent with prior failures showing the `mergeInMemory put loop` alone is about 1.21% of `applyLedger`.

### Lesson Learned

For live BucketList commit optimizations, the hard barrier is not only "can the next snapshot answer reads"; it is also "can the persisted ledger header/HAS survive a crash by hash alone." Any proposal to defer bucket materialization past `snapshotLedger` must include a crash-recovery story for hash-referenced buckets and must separate unavoidable synchronous canonical-hash work from merely deferrable file I/O.
