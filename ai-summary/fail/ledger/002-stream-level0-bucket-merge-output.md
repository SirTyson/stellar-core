# H002: Stream level-0 in-memory bucket merge output without a second full pass

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Medium
**Impact**: soroswap apply-time reduction in synchronous BucketList commit
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When sealing a ledger, the synchronous level-0 Live BucketList merge should transform the changed ledger entries into the new bucket with one deterministic pass over the merged entry stream, while still producing the identical bucket file, hash, in-memory state, and index. The apply thread should not spend a second full pass copying every merged `BucketEntry` from a materialized vector into `BucketOutputIterator` if the same ordered stream can feed both the file writer/hash and the in-memory/index representation.

## Mechanism

`LiveBucket::mergeInMemory` first materializes all merged entries into `mergedEntries`, then builds an index asynchronously from that vector while the apply thread performs a second pass that calls `BucketOutputIterator::put` for every entry. For soroswap, this level-0 path is synchronous inside `addLiveBatch`, so the second pass pays per-entry copy, comparison, XDR serialization, hash, and write costs before `applyLedger` can finish. A streaming merge sink that appends to the retained in-memory vector and feeds the output iterator in the same deterministic order, or a sink that builds the index/in-memory state while writing, should remove a large part of the redundant per-entry pass without changing BucketList semantics.

## Trigger

Run the current soroswap apply-load benchmark with the reference Tracy trace and filter events that fall inside `applyLedger`. The synchronous bucket commit path shows 511k `BucketOutputIterator::put` / `writeOne` calls inside apply. A PoC should replace the `mergeInMemory` materialize-then-put loop with a single ordered sink, confirm the resulting bucket hashes and ledger hashes are unchanged, and compare repeated soroswap apply-time runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3370-3419` — `sealLedgerTxnAndStoreInBucketsAndDB` calls `finalizeLedgerTxnChanges` on the apply path before advancing the snapshot.
- `src/ledger/LedgerManagerImpl.cpp:3331-3365` — `finalizeLedgerTxnChanges` seals the `LedgerTxn`, runs `addLiveBatch`, and waits for async side work before returning.
- `src/bucket/BucketManager.cpp:1026-1046` — `addLiveBatch` synchronously adds live init/live/dead entries to the Live BucketList.
- `src/bucket/BucketListBase.cpp:193-238` — level-0 `prepareFirstLevel` uses `LiveBucket::freshInMemoryOnly` and then immediately calls `LiveBucket::mergeInMemory` synchronously.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` materializes `mergedEntries`, starts index construction on that vector, then loops over `mergedEntries` again to write/hash the bucket.
- `src/bucket/BucketOutputIterator.cpp:76-178` — `put` and `getBucket` perform per-entry buffering and XDR writes.

## Evidence

The current soroswap Tracy trace has `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` as the in-scope measurement envelope. Summing only events fully inside `applyLedger` windows shows `sealLedgerTxnAndStoreInBucketsAndDB` at 533,841,455 ns, `finalizeLedgerTxnChanges` at 518,495,252 ns, and `addLiveBatch` at 489,540,693 ns. Within that synchronous bucket work, `BucketOutputIterator::put` accounts for 244,316,437 ns over 511,439 calls, `XDRStream::writeOne` for 185,911,075 ns over 511,431 calls, `LiveBucket::mergeInMemory` for 152,122,132 ns, and `mergeInMemory put loop` for 81,543,167 ns.

Structurally, `mergeInMemory` already has all entries in sorted deterministic order from `mergeInternal`, and the output file hash is order-derived. Feeding the same ordered entries to both the retained in-memory/index construction and the output writer should preserve determinism and bucket identity while reducing copy/pass overhead in a phase that is about 10% of the traced `applyLedger` time.

## Anti-Evidence

The current design overlaps index construction with the put loop using `std::async`, so a naive single-pass rewrite could lose that overlap and regress if it serializes index construction after file writes. The PoC must preserve or replace that overlap, for example by building index state incrementally during the stream or by keeping a producer/consumer split with deterministic ordering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The synchronous path exists: `finalizeLedgerTxnChanges` calls `BucketManager::addLiveBatch`, which calls `BucketListBase::addBatch`; level 0 then performs `freshInMemoryOnly`, `LiveBucket::mergeInMemory`, and immediate `commit` before returning to `applyLedger`. However, the expensive `BucketOutputIterator::put`/`XDROutputFileStream::writeOne` work in the alleged "second pass" is not redundant materialization work: it is the required serialization, file write, byte count, and hash input for the new bucket file. The current implementation already overlaps the only clearly separable second traversal, in-memory index construction, with the output write pass using `std::async`, so a simple streaming sink would mostly move required work earlier and could lose this overlap.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3331-3367` — `finalizeLedgerTxnChanges` seals the `LedgerTxn`, launches independent in-memory Soroban-state work, then synchronously calls `addLiveBatch` before waiting for side futures.
- `src/ledger/LedgerManagerImpl.cpp:3370-3419` — `sealLedgerTxnAndStoreInBucketsAndDB` invokes `finalizeLedgerTxnChanges` inside the apply critical path before snapshot advancement.
- `src/bucket/BucketManager.cpp:1026-1046` — `addLiveBatch` directly calls `mLiveBucketList->addBatch`, so level-0 preparation is on the apply path.
- `src/bucket/BucketListBase.cpp:196-238,781-783` — live level 0 builds a memory-only snap, calls `LiveBucket::mergeInMemory` synchronously, then commits the produced in-memory bucket immediately.
- `src/bucket/LiveBucket.cpp:613-697` — `mergeInMemory` builds `mergedEntries`, starts `LiveBucketIndex` construction asynchronously from that vector, writes the bucket file by iterating `mergedEntries`, waits for the index, and adopts the bucket with the retained vector.
- `src/bucket/BucketOutputIterator.cpp:76-178,196-247` — `put` performs legality/order checks, buffer replacement, and required `writeOne` calls; `getBucket` finalizes the hash and adopts the file with either a prebuilt index or a newly-created one.
- `src/util/XDRStream.h:483-515` — `writeOne` computes XDR size, serializes into the output buffer, writes bytes, updates the bucket hasher, and accounts bytes; this work is intrinsic to producing the bucket file and hash.
- `src/bucket/InMemoryIndex.cpp:264-303` — the vector-based in-memory index pass computes offsets and counters from `mergedEntries`, and is already overlapped with the file-writing pass in `mergeInMemory`.

### Why It Failed

The proposed optimization does not remove the dominant work it attributes to the "second pass." Bucket file creation still requires every output entry to be XDR-sized, serialized, written, and hashed exactly once, regardless of whether `out.put` is called from a post-merge loop or from the merge callback. The realistically removable portion is limited to an extra vector traversal and some `BucketOutputIterator` buffering/check overhead, while the current code already overlaps index construction with serialization. That projected saving is below the optimize-soroswap objective's Medium threshold, and a naive streaming rewrite risks regressing by serializing merge, write, and index construction instead of preserving the existing overlap.

### Lesson Learned

For BucketList apply-path hypotheses, separate mandatory bucket-file production from genuinely redundant passes. Tracy time in `BucketOutputIterator::put` and `XDROutputFileStream::writeOne` is mostly required serialization/hash/write work, so a viable Medium+ optimization must either reduce synchronous bucket output volume, eliminate a blocking wait, or redesign indexing/output to preserve overlap while removing substantially more than a vector traversal.
