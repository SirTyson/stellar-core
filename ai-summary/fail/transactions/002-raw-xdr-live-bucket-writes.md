# H002: Preserve Raw Soroban LedgerEntry XDR Through Live-Bucket Writes

**Date**: 2026-05-20
**Subsystem**: transactions / Soroban apply / live bucket finalization
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding redundant XDR sizing and serialization for Soroban write entries on the live-bucket path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each successful Soroban transaction, modified ledger entries should be validated, applied to `LedgerTxn`, emitted to metadata, and written to live buckets with byte-for-byte identical bucket records and hashes. If the host already produced XDR bytes for a modified `LedgerEntry`, the apply path should not need to deserialize those bytes into a `LedgerEntry` and later fully re-size and re-serialize the same entry for the level-0 live bucket, as long as any C++-side mutations such as `lastModifiedLedgerSeq` are reflected in the bytes used for the bucket record.

## Mechanism

`InvokeHostFunctionOpFrame::recordStorageChanges` receives `out.modified_ledger_entries` as XDR buffers, decodes each buffer with `xdr::xdr_from_opaque`, and stores the parsed `LedgerEntry` in the parallel ledger state. After parallel apply, `commitChangesToLedgerTxn`, `LedgerTxn::getAllEntries`, `LiveBucket::convertToBucketEntry`, `BucketOutputIterator::put`, and `XDROutputFileStream::writeOne` walk those entries again, recompute XDR sizes, serialize them into the bucket output buffer, and feed those bytes to the bucket hasher. Preserving or regenerating a post-`lastModifiedLedgerSeq` raw-XDR sidecar for modified Soroban live entries would let the bucket writer emit the already-canonical `LedgerEntry` payload inside the `BucketEntry` wrapper instead of performing a full second XDR traversal.

## Trigger

Run the accepted soroswap apply-load scenario (`soroswap, TX=2000, T=8`). The benchmark produces many SAC balance updates; each update appears in host `modified_ledger_entries`, is decoded in `recordStorageChanges`, committed to the main `LedgerTxn`, and then written into the level-0 live bucket during `finalizeLedgerTxnChanges`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — `recordStorageChanges` decodes each host-provided modified-entry XDR buffer and upserts the parsed entry.
- `src/transactions/ParallelApplyUtils.cpp:722-800` — `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn` moves dirty parallel entries into the main `LedgerTxn`.
- `src/ledger/LedgerTxn.cpp:1695-1737` — `LedgerTxn::Impl::getAllEntries` copies modified entries into `initEntries`, `liveEntries`, and `deadEntries` for bucket ingestion.
- `src/bucket/LiveBucket.cpp:380-420` — `LiveBucket::convertToBucketEntry` builds sortable bucket-entry references from the live/init/dead vectors.
- `src/bucket/BucketOutputIterator.cpp:78-165` — `BucketOutputIterator::put` buffers and flushes sorted bucket entries.
- `src/util/XDRStream.h:481-515` — `XDROutputFileStream::writeOne` recomputes `xdr_size`, serializes the object into `mBuf`, writes it, and hashes the serialized bytes.

## Evidence

Timestamp filtering against the current soroswap `applyLedger` windows shows live-bucket output is on the measured critical path: `BucketOutputIterator::put` at `bucket/BucketOutputIterator.cpp:80` overlaps `applyLedger` by 167,268,139 ns (3.20%), and `XDROutputFileStream::writeOne` at `util/XDRStream.h:485` overlaps by 126,581,415 ns (2.42%). These are descendants of `finalizeLedgerTxnChanges` / `addLiveBatch`, not TX-set construction. The structural duplication is visible in the code: the host output is already an XDR buffer, but the C++ path decodes it and later serializes the same logical entry for bucket output.

The optimization is post-host and post-budget, so it should not change Soroban metering if implemented as a physical-output shortcut only. The bucket hash remains deterministic because the writer would hash the exact record bytes it writes, in the same sorted order selected by the existing bucket-entry comparator.

## Anti-Evidence

The raw host buffer is not automatically safe to reuse: `TxParallelApplyLedgerState::upsertEntry` mutates `lastModifiedLedgerSeq`, and subsequent C++ code may distinguish INIT vs LIVE bucket-entry wrappers. A viable PoC must either create the sidecar bytes after all C++ mutations or patch/regenerate the small changed portion deterministically; blindly forwarding the host buffer would risk an incorrect bucket hash. The previous put-loop pipeline investigation was below threshold when scoped only to pipelining, so this hypothesis depends on removing serialization work itself, not merely overlapping it with existing writes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The hot path is real: host `modified_ledger_entries` are decoded in `recordStorageChanges`, applied through the parallel ledger state, committed into `LedgerTxn`, copied out by `getAllEntries`, converted into sorted `BucketEntry` objects, and synchronously written by the level-0 live-bucket path before `snapshotLedger` stores the consensus bucket-list hash. The claimed redundant serialization also exists: `XDROutputFileStream::writeOne` recomputes `xdr_size` and serializes each buffered `BucketEntry` for the live bucket file. However, the proposed shortcut can only remove the sizing/serialization portion of `writeOne`, not the synchronous sorting/merge, in-memory state, index/counter construction, record write, SHA-256 hashing, bucket adoption, or snapshot/HAS requirements. That bounds the recoverable apply-time improvement below the objective's Medium threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — `recordStorageChanges` decodes each host-provided XDR buffer with `xdr::xdr_from_opaque`, validates and meters it by buffer size, then calls `upsertLedgerEntry`.
- `src/transactions/ParallelApplyUtils.cpp:1316-1332` — `TxParallelApplyLedgerState::upsertEntry` stores the parsed `LedgerEntry` and mutates `lastModifiedLedgerSeq` to the applying ledger sequence.
- `src/transactions/ParallelApplyUtils.cpp:1123-1145` and `src/transactions/ParallelApplyUtils.cpp:1164-1196` — successful per-tx changes are promoted into thread state, preserving the new/live distinction and again ensuring `lastModifiedLedgerSeq` is current.
- `src/transactions/ParallelApplyUtils.cpp:721-800` — `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn` moves dirty parsed entries into a child `LedgerTxn` via `createWithoutLoading` or `updateWithoutLoading` before committing.
- `src/ledger/LedgerTxn.cpp:2367-2407` and `src/ledger/LedgerTxn.cpp:1695-1737` — sealing updates `lastModifiedLedgerSeq` for modified entries, then copies parsed ledger entries into init/live/dead vectors for bucket ingestion.
- `src/ledger/LedgerManagerImpl.cpp:3217-3367` and `src/ledger/LedgerManagerImpl.cpp:3371-3419` — `finalizeLedgerTxnChanges` synchronously calls `addLiveBatch`; only after it returns does `snapshotLedger` store the ledger-header bucket-list hash and advance the apply snapshot.
- `src/bucket/BucketManager.cpp:1025-1045`, `src/bucket/LiveBucketList.cpp:14-27`, and `src/bucket/BucketListBase.cpp:684-797` — live-bucket ingestion is synchronous for level 0 and must install the bucket/index before returning.
- `src/bucket/LiveBucket.cpp:380-528` — the fresh batch is converted into sorted `BucketEntry` values; INIT vs LIVE wrapper type is selected from the `LedgerTxn` state, so raw host `LedgerEntry` bytes alone are not the complete bucket record.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` merges current level-0 entries with the new batch, builds an index future, runs the put loop, waits for the index, and returns a bucket retaining in-memory entries.
- `src/bucket/BucketOutputIterator.cpp:78-165` and `src/bucket/BucketOutputIterator.cpp:167-247` — `put` still performs protocol/tombstone checks, adjacent-key deduplication, buffered entry replacement, final write, hash finalization, index selection, and bucket adoption.
- `src/util/XDRStream.h:481-515` — `writeOne` is the only directly removable second traversal: it computes `xdr_size`, serializes the XDR object into a record-framed buffer, writes those bytes, and hashes the exact record bytes.
- `src/bucket/InMemoryIndex.cpp:264-303` and `src/bucket/BucketUtils.cpp` — level-0 index/counter construction still needs parsed bucket entries and currently computes XDR sizes for offsets and entry-type byte counters.

### Why It Failed

The inefficiency exists, but it does not clear the objective's Medium acceptance floor. The hypothesis cites `BucketOutputIterator::put` at 3.20% and `XDROutputFileStream::writeOne` at 2.42% of apply time. A raw-sidecar writer cannot remove all of `put`: the live-bucket path must still sort/merge entries, preserve INIT/LIVE/DEAD semantics, maintain the buffered deduplication step, write bytes, hash the exact record stream for consensus, build usable in-memory indexes and counters, adopt the bucket, and install the bucket list before `snapshotLedger`. Even under an optimistic implementation that patches the host buffer's leading `lastModifiedLedgerSeq` and emits a raw `BucketEntry` wrapper, the addressable portion is strictly less than the 2.42% `writeOne` zone because writing and hashing the record bytes remain mandatory.

This also cannot safely reuse only the original host buffer end-to-end. The buffer is a `LedgerEntry`, while live buckets store a `BucketEntry` union whose discriminant depends on `LedgerTxn` INIT-vs-LIVE state; `lastModifiedLedgerSeq` is updated after host output; and level-0 merge output includes existing curr entries as well as new batch entries. Carrying enough sidecar state through `TxParallelApplyLedgerState`, `ThreadParallelApplyLedgerState`, `GlobalParallelApplyLedgerState`, `LedgerTxn`, `LiveBucket::convertToBucketEntry`, and `LiveBucket::mergeInMemory` would be a broad refactor for a sub-Medium maximum gain.

### Lesson Learned

Bucket writer serialization costs are real, but the accepted soroswap objective should not promote raw-XDR sidecar work unless the isolated removable serialization component is shown above 3% of total apply time. For level-0 live-bucket optimizations, `put`/`writeOne` overlap is an upper bound, not the achievable gain: consensus hashing, physical output, in-memory index/counters, wrapper semantics, and bucket-list installation remain on the critical path.
