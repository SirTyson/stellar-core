# H001: Parallelize synchronous live-bucket level-0 batch merge

**Date**: 2026-05-23
**Subsystem**: crypto, bucket, ledger
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in blocking BucketList writes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The live BucketList update at the end of `closeLedger` should produce the exact
same bucket files, hashes, BucketList levels, merge counters, and ledger header
state as today, but the expensive level-0 batch construction and in-memory merge
should not run as one serial main-thread pass. The merge input ordering is
canonical, so the work should be shardable into deterministic key ranges and
recombined in the same observable order without changing consensus output.

## Mechanism

`LedgerManagerImpl::finalizeLedgerTxnChanges` calls `BucketManager::addLiveBatch`
synchronously after `ltx.getAllEntries`, and `BucketListBase::addBatchInternal`
then performs level spill checks, builds the fresh level-0 batch, commits it, and
resolves ready futures on the apply critical path. In the current soroswap trace,
the blocking live-bucket add path is a Medium-sized wall-time component:
timestamp-filtered Tracy events inside `applyLedger` show `addLiveBatch`
contributing 280,204,269 ns over 71 ledgers and `addBatchInternal` contributing
317,721,215 ns inside the same apply windows, while total `applyLedger` time is
4,475,605,676 ns. A protocol-gated implementation that splits level-0 fresh
bucket creation / in-memory merge into at most `NUM_CLUSTERS` deterministic
sorted ranges, then performs a final ordered k-way output pass, could reduce the
blocking portion by 3-7% without touching lazy background merge work.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on a
ledger sequence that performs normal live BucketList writes. The trigger is the
post-apply finalization phase after `ltx.getAllEntries(initEntries, liveEntries,
deadEntries)`, when thousands of Soroban contract-data changes are sorted,
written, hashed, and merged into level 0 before `sealLedgerTxnAndStoreInBucketsAndDB`
can snapshot the bucket list.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3215-3367` -
  `finalizeLedgerTxnChanges` launches hot-archive and in-memory-state futures,
  but runs `addLiveBatch` synchronously and waits for all bucket work before
  returning.
- `src/bucket/BucketManager.cpp:1025-1045` - `BucketManager::addLiveBatch`
  wraps the blocking live BucketList update and metrics.
- `src/bucket/BucketListBase.cpp:681-797` -
  `BucketListBase::addBatchInternal` serially performs spill/prepare/commit and
  level-0 batch work.
- `src/bucket/BucketListBase.cpp:193-238` -
  `BucketLevel<LiveBucket>::prepareFirstLevel` builds the fresh batch and uses
  in-memory merge when the current bucket is already indexed.
- `src/bucket/BucketOutputIterator.cpp:167-197` -
  `BucketOutputIterator::getBucket` flushes the final buffered entry, closes the
  output, and hashes the bucket on the critical path.

## Evidence

The latest accepted trace in `ai-summary/CURRENT_STATE.md` is
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
`csvexport-release` total-time output reports `applyLedger`
(`ledger/LedgerManagerImpl.cpp:1484`) at 4,475,605,676 ns, `finalizeLedgerTxnChanges`
at 342,847,455 ns, `addLiveBatch` (`bucket/BucketManager.cpp:1031`) at
312,127,216 ns, and `addBatchInternal` (`bucket/BucketListBase.cpp:688`) at
310,336,733 ns. Unwrapped event timestamp filtering confirms this is not a
TX-set-construction artifact and not lazy background merge work: 280,204,269 ns
of `addLiveBatch` and 317,721,215 ns of `addBatchInternal` occur inside
`applyLedger` windows.

The source structure also supports a deterministic parallelization hypothesis.
The inputs are already materialized as `initEntries`, `liveEntries`, and
`deadEntries`, bucket output must be globally ordered by BucketEntry identity,
and range partitioning followed by a final ordered merge can preserve byte-for-byte
output order. This targets the synchronous wait portion explicitly; it does not
optimize `Merge task` or other background BucketList work that the objective
marks out of scope.

## Anti-Evidence

This is a larger redesign, not a local crypto primitive cleanup. The final output
hash, duplicate/tombstone elision semantics, shadow handling, merge counters,
empty-bucket handling, index construction, and fsync behavior must remain
byte-identical. The parallelism must be capped at `NUM_CLUSTERS`; using hardware
concurrency would violate the objective. A PoC must also separate level-0 fresh
bucket work from future resolution and prove that the final ordered merge is not
so serial that it consumes the expected win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated
**Failed At**: reviewer

### Trace Summary

The reachability claim is correct: after `LedgerTxn` is sealed into
`initEntries`, `liveEntries`, and `deadEntries`, `finalizeLedgerTxnChanges`
updates hot archive and in-memory Soroban state asynchronously but calls
`BucketManager::addLiveBatch` synchronously before the bucket-list hash is
snapshotted into the ledger header. The level-0 live-bucket path sorts the new
batch, merges it with the in-memory current bucket, writes/hashes the final
ordered bucket stream, and adopts the resulting bucket before apply can proceed.
However, the cited total live-bucket batch time is not large enough under the
objective's authoritative non-Tracy baseline to clear the Medium floor, and only
a fraction of that total is actually removable by parallelizing range-local
fresh/merge work.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3215-3367` - `finalizeLedgerTxnChanges` calls `ltx.getAllEntries`, starts asynchronous hot-archive and in-memory-state work, then synchronously calls `addLiveBatch`.
- `src/ledger/LedgerManagerImpl.cpp:3408-3419` - `sealLedgerTxnAndStoreInBucketsAndDB` snapshots the bucket-list hash only after `finalizeLedgerTxnChanges` returns, so live bucket output is apply-critical.
- `src/bucket/BucketManager.cpp:1025-1045` - `addLiveBatch` records metrics and delegates directly to `LiveBucketList::addBatch`.
- `src/bucket/LiveBucketList.cpp:14-27` - `LiveBucketList::addBatch` invokes `addBatchInternal` then initializes caches for newly-added live buckets.
- `src/bucket/BucketListBase.cpp:681-797` - `addBatchInternal` performs spill checks, commits/prepares higher levels, runs level-0 `prepareFirstLevel`, commits level 0, then non-blockingly resolves ready futures.
- `src/bucket/BucketListBase.cpp:193-238` - level 0 builds a fresh in-memory-only snap and calls `LiveBucket::mergeInMemory` when the current bucket has in-memory entries; otherwise it falls back to the regular file-based prepare path.
- `src/bucket/LiveBucket.cpp:381-483` - `convertToBucketEntry` creates lightweight references, sorts them by canonical ledger-entry identity, and materializes a sorted `BucketEntry` vector.
- `src/bucket/LiveBucket.cpp:531-561` - `freshInMemoryOnly` constructs the sorted in-memory batch and records new-entry merge counters.
- `src/bucket/LiveBucket.cpp:614-698` - `mergeInMemory` performs the ordered two-way merge, already overlaps `LiveBucketIndex` construction on an async task with the output write/hash loop, then waits for the index before adopting the bucket.
- `src/bucket/BucketBase.cpp:289-337` - `mergeInternal` is the canonical merge loop, including shutdown checks and equal-key handling through bucket-specific merge semantics.
- `src/bucket/LiveBucket.cpp:117-189` and `src/bucket/LiveBucket.cpp:191-313` - `maybePut` and `mergeCasesWithEqualKeys` preserve shadow, INIT/LIVE/DEAD, tombstone, and merge-counter semantics that any partitioned implementation must reproduce exactly.
- `src/bucket/BucketOutputIterator.cpp:76-165` and `src/bucket/BucketOutputIterator.cpp:167-255` - output remains globally ordered, tombstones may be filtered, duplicate identities collapse through a one-entry buffer, the final stream is closed and SHA256-finalized, and `adoptFileAsBucket` installs the bucket.
- `src/bucket/BucketManager.cpp:1106-1124` - `snapshotLedger` uses the resulting live bucket-list hash to populate `LedgerHeader::bucketListHash`.

### Why It Failed

The optimization target exists, but the severity projection does not satisfy the
objective. The current accepted baseline records authoritative non-Tracy
soroswap medians of 221.845 ms, 217.379 ms, and 215.707 ms, averaging about
218.3 ms per ledger; a Medium finding therefore needs roughly 6.5 ms/ledger of
reproducible apply-time reduction. The hypothesis's own timestamp-filtered
ceiling is 280.2 ms of `addLiveBatch` or 317.7 ms of `addBatchInternal` across
71 ledgers, i.e. about 3.9-4.5 ms/ledger even if the entire synchronous live
bucket add path disappeared.

The realistic removable portion is smaller than that ceiling. The target is
only level-0 fresh/merge work inside `addBatchInternal`, while `addLiveBatch`
also includes metrics, cache initialization, spill/commit bookkeeping, and ready
future resolution. More importantly, `mergeInMemory` already overlaps index
construction with the output loop, and the final canonical bucket stream still
has to be emitted in one observable order, SHA256-finalized, closed, adopted, and
used for the ledger-header bucket hash. A deterministic range-parallel design
could reduce some sort/merge CPU work, but it cannot remove that serial
write/hash/adoption tail. This leaves the likely improvement in Low territory,
which the optimize-soroswap objective explicitly rejects.

### Lesson Learned

Blocking bucket work must be sized against the non-Tracy headline apply-time
baseline and the removable subzone, not against a diagnostic Tracy denominator.
For level-0 bucket changes, separate parallelizable sort/merge CPU from the
already-overlapped index build and the irreducible ordered output/hash/adopt
tail before promoting a redesign to Medium severity.
