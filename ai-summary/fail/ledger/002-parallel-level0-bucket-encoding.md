# H002: Parallelize deterministic level-0 bucket XDR encoding before ordered hash/write

**Date**: 2026-05-03
**Subsystem**: ledger / BucketList commit on apply path
**Severity**: Medium
**Impact**: 3-4% soroswap apply-time reduction by moving per-entry level-0 bucket XDR encoding off the apply-thread serial section while preserving byte order and bucket hashes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`addLiveBatch` must produce exactly the same sorted level-0 live bucket bytes, SHA-256 bucket hash, in-memory entries, and index before `snapshotLedger` observes the new BucketList state. It should not, however, require the apply thread to perform every independent per-entry XDR encoding step serially when the output entry order is already fixed and the final hash/write pass can consume pre-encoded byte slices in deterministic order.

## Mechanism

`LiveBucket::mergeInMemory` first constructs a deterministic `mergedEntries` vector, then `BucketOutputIterator::put` serializes each entry, updates the stream/hash state, and writes the bucket file in one serial loop. A bounded worker pool, capped by `ledgerMaxDependentTxClusters` / `NUM_CLUSTERS`, could pre-encode disjoint ranges of the already-ordered `BucketEntry` vector into byte buffers, after which the apply thread would feed those buffers to SHA-256 and the output stream in the original order. This preserves deterministic bucket bytes and hash while parallelizing the expensive, independent XDR encoding/copy work that currently sits inside the synchronous `addLiveBatch` barrier.

## Trigger

Run the current soroswap apply-load diagnostic trace
`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Every closed ledger calls `LedgerManagerImpl::finalizeLedgerTxnChanges`, extracts init/live/dead vectors, and synchronously calls `BucketManager::addLiveBatch`; level 0 then builds and writes the in-memory merged bucket before `snapshotLedger`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3331-3367` — `finalizeLedgerTxnChanges` must wait for `addLiveBatch` before returning to the `snapshotLedger` barrier.
- `src/bucket/BucketManager.cpp:1025-1046` — synchronous `addLiveBatch` wrapper on the apply path.
- `src/bucket/BucketListBase.cpp:681-797` — `addBatchInternal` installs the level-0 bucket and resolves ready futures.
- `src/bucket/LiveBucket.cpp:621-697` — `mergeInMemory` builds `mergedEntries`, constructs an index future, then serially calls `out.put(e)` for every merged entry.
- `src/bucket/BucketOutputIterator.cpp:78-164` and `src/bucket/BucketOutputIterator.cpp:169-198` — `put` and `getBucket` currently interleave sorted-order validation, XDR serialization, hash update, file write, and final hash production.
- `src/bucket/LiveBucket.cpp:381-484` — `convertToBucketEntry` materializes sorted bucket entries and could share the same ordered-range work partitioning.

## Evidence

The current soroswap trace records `applyLedger` total time of 5,230,315,999 ns. Timeline overlap analysis shows `addLiveBatch` contributes 265,886,696 ns inside `applyLedger` windows (296,423,547 ns total), about 5.1% of apply time. In the same in-scope windows, bucket `put` overlaps for 167,268,139 ns, `writeOne` overlaps for 126,581,415 ns, `mergeInMemory put loop` overlaps for 60,950,811 ns, and `convertToBucketEntry` overlaps for 25,984,811 ns. Prior failures ruled out deferring file I/O alone and local put-loop tweaks, but explicitly leave encode/hash-side restructuring as the remaining way to attack the synchronous level-0 bucket barrier.

## Anti-Evidence

The final SHA-256 hash must consume the exact canonical byte stream in order, so the hash/write phase itself remains serial unless the bucket hash format changes, which is out of scope. If most `writeOne` time is buffered file I/O or sequential hasher work rather than XDR encoding, the realized gain could fall below the Medium threshold; the PoC must instrument or benchmark the pre-encoding fraction directly. Buffering encoded entries increases memory pressure, so the implementation should bound parallelism by `NUM_CLUSTERS`, reuse per-worker buffers, and avoid changing background bucket merge behavior or BucketList determinism.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/subsumed by `ai-summary/fail/ledger/summary.md` row 008, `008-cache-encoded-bytes-for-unchanged-level0-bucket-entries.md`
**Failed At**: reviewer

### Trace Summary

The apply path seals the `LedgerTxn`, launches the independent in-memory Soroban-state update, then calls `BucketManager::addLiveBatch` synchronously before `snapshotLedger` hashes the BucketLists into the ledger header. Live level 0 uses `freshInMemoryOnly` to build an in-memory snap, then `mergeInMemory` merges current and snap entries into `mergedEntries`, starts index construction asynchronously, and serially emits the canonical bucket stream through `BucketOutputIterator`. The only work this hypothesis can move off the apply-thread serial loop is the XDR sizing/packing part of `XDROutputFileStream::writeOne`; ordered hash ingestion, buffered file write, close, hash finalization, bucket adoption, and the snapshot-visible hash remain synchronous. The prior ledger fail summary already rejected the same level-0 put-loop/XDR-encoding target because even ideal removal of that encoding work was below the objective's Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3331-3367` — `getAllEntries` seals the transaction and `addLiveBatch` runs synchronously before the method returns.
- `src/ledger/LedgerManagerImpl.cpp:3408-3418` — immediately after `finalizeLedgerTxnChanges`, `snapshotLedger`, persistent state/header storage, and next-state construction consume the new BucketList hash.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch` is a synchronous wrapper over `mLiveBucketList->addBatch`.
- `src/bucket/BucketManager.cpp:1106-1124` — `snapshotLedger` reads the live/hot-archive BucketList hashes into the ledger header.
- `src/bucket/BucketListBase.cpp:196-238` — live level 0 creates a `freshInMemoryOnly` snap, then immediately sets next curr to the result of `LiveBucket::mergeInMemory`.
- `src/bucket/BucketListBase.cpp:681-797` — `addBatchInternal` prepares and commits level 0, then only nonblocking-resolves ready futures.
- `src/bucket/LiveBucket.cpp:531-561` — `freshInMemoryOnly` materializes sorted in-memory bucket entries without a file/hash.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` builds `mergedEntries`, overlaps index construction with the put loop, then returns a bucket from `out.getBucket`.
- `src/bucket/BucketOutputIterator.cpp:78-164` — `put` enforces order/tombstone rules, buffers one entry, and calls `mOut.writeOne` for the previous entry.
- `src/bucket/BucketOutputIterator.cpp:169-248` — `getBucket` writes the final buffered entry, closes the stream, finalizes the SHA-256 hash, selects/builds an index, and adopts the file.
- `src/util/XDRStream.h:483-515` — `writeOne` computes `xdr_size`, resizes/reuses a stream buffer, XDR-encodes the object, writes framed bytes, and then feeds the same bytes to the hasher.

### Why It Failed

This hypothesis is not novel enough to promote: row 008 in the ledger failure summary already covers the same performance target, the level-0 `mergeInMemory`/`BucketOutputIterator` XDR-encoding work, and states that even an ideal optimization eliminating all XDR encoding work in that put loop would be below the objective's 3% Medium floor. The traced code agrees with that bound. Pre-encoding ranges can remove only `xdr_size`/`xdr_argpack_archive` from the serial stream-emission pass; it cannot parallelize canonical SHA-256 ingestion or ordered file emission without changing the bucket format/hash contract, and it introduces extra encoded-byte storage/copying that would eat into the already-sub-Medium budget.

The hypothesis's 3-4% projection appears to attribute too much of `addLiveBatch` or aggregate `BucketOutputIterator::put` time to level-0 XDR packing. The explicitly measured `mergeInMemory put loop` cited by the existing fail summary is about 1.21% of `applyLedger`, and the serial hash/write/finalize/adopt portions are not removable by pre-encoding. Under the optimize-soroswap reviewer objective, Low-severity optimizations must be rejected rather than downgraded.

### Lesson Learned

For live BucketList commit work, distinguish the whole synchronous `addLiveBatch` barrier from the subset actually affected by a proposed change. Parallel pre-encoding is still a localized put-loop optimization; to meet this objective's Medium bar, a bucket hypothesis must remove or overlap a larger portion of the level-0 commit path without violating the canonical byte stream, hash, durability, and snapshot contracts.
