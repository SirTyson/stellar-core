# H006: Reuse Soroban host output XDR encoding to skip C++ re-serialization in addLiveBatch

**Date**: 2026-04-29
**Subsystem**: ledger / bucket commit
**Severity**: Medium
**Impact**: 3-7% soroswap apply-time reduction by removing redundant per-entry XDR encoding from the synchronous level-0 bucket commit on the apply critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `LedgerManagerImpl::finalizeLedgerTxnChanges` calls `BucketManager::addLiveBatch` to commit a ledger, every Soroban-modified `LedgerEntry` in `initEntries` and `liveEntries` should be written into the new level-0 bucket file using XDR bytes that were already produced by the Soroban host. The synchronous `BucketOutputIterator::put → XDROutputFileStream::writeOne` path should not re-execute a full XDR encode (`xdr::xdr_size` + `xdr_argpack_archive`) for the inner `LedgerEntry` of every Soroban entry, because the embedder just decoded those exact bytes from `out.modified_ledger_entries` a few hundred microseconds earlier. For non-Soroban entries (classic accounts/trustlines, TTL deltas), encoding is still required and behavior is unchanged.

## Mechanism

`InvokeHostFunctionOpFrame::recordStorageChanges` (`src/transactions/InvokeHostFunctionOpFrame.cpp:641-741`) decodes each `out.modified_ledger_entries` buffer with `xdr::xdr_from_opaque(buf.data, le)`, discards `buf.data`, and stores the decoded `LedgerEntry` via `upsertLedgerEntry`. Later, `addLiveBatch` flows the same entries through `BucketOutputIterator::put` (`src/bucket/BucketOutputIterator.cpp:140-165`), which buffers the BucketEntry and eventually calls `XDROutputFileStream::writeOne` (`src/util/XDRStream.h:483-515`) — and `writeOne` performs a full `xdr_size` + `xdr_argpack_archive` re-encode of the `BucketEntry`, whose payload is the same `LedgerEntry` bytes that were just discarded. The actual deviation is that the apply critical path pays full XDR-encoding CPU twice for every Soroban output entry, when the second pass could prepend the existing 4-byte BucketEntry discriminant + the already-encoded inner `LedgerEntry` bytes (still hashing them and writing them to disk, but without re-invoking `xdr_argpack_archive`).

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Each tx returns ~6 modified `CONTRACT_DATA`/`CONTRACT_CODE`/`TTL` entries via `out.modified_ledger_entries`; with ~145 tx/ledger, ~870 Soroban-modified entries flow through `recordStorageChanges` then `addLiveBatch` on the apply thread per ledger. Tracy on the current baseline shows `addLiveBatch` self-time of 295 ms (2.88% of trace) over 70 ledgers (~4.2 ms / ledger) sitting on the synchronous `finalizeLedgerTxnChanges` critical path between `applyTransactions` and the next-ledger handoff.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-741` — `recordStorageChanges` decodes `buf.data` per entry then drops the encoded buffer; this is the natural cache point for the encoded bytes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:720` — `upsertLedgerEntry(lk, le)` is the seam that pushes the decoded entry into the parallel apply state (and ultimately into the LedgerTxn entry map); it currently has no place to carry side-band encoded bytes.
- `src/bucket/BucketOutputIterator.cpp:140-200` — `put`/`getBucket` buffer `BucketEntry` and call `mOut.writeOne` in `XDROutputFileStream`.
- `src/util/XDRStream.h:480-515` — `XDROutputFileStream::writeOne<T>` always re-encodes via `xdr::xdr_size(t)` and `xdr_argpack_archive(p, t)`; a sibling overload that accepts pre-encoded bytes (with size and hash still computed) would let the bucket writer skip the encode pass for entries whose payload is already encoded.
- `src/bucket/LiveBucketList.cpp:14-27` and `src/bucket/BucketManager.cpp:1026-1041` — `addLiveBatch` is the single synchronous caller from `finalizeLedgerTxnChanges`; it receives `std::vector<LedgerEntry> const&` today but could be extended to thread parallel `vector<EncodedBytes const*>` slices alongside the decoded entries.
- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges` orchestrates the seal + `getAllEntries` + `addLiveBatch`; this is where cached encodings need to be plumbed from the LedgerTxn into the bucket batch.

## Evidence

- Tracy soroswap trace zone summary (current baseline at `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/...-soroswap-tx-2000-t-8.tracy`):
  - `applyLedger` total 5.77 s / 69 calls (~83.7 ms/ledger).
  - `finalizeLedgerTxnChanges` total 325.4 ms / 70 calls (3.18% of trace, ~4.65 ms/ledger).
  - `addLiveBatch` (`bucket/BucketManager.cpp:1031`) self-time 295 ms / 70 calls (2.88% of trace, ~4.2 ms/ledger) — synchronous.
  - `addHotArchiveBatch (async)` self-time 39 ms (already off the critical path); `updateInMemorySorobanState (async)` 2.4 ms — confirms `addLiveBatch` is the sequential bottleneck inside `finalizeLedgerTxnChanges`.
  - `recordStorageChanges` 50 ms / 3335 tx (~15 µs/tx) shows the per-entry decode side already exists as an instrumented hot spot.
  - `write xdr` 764 ms (7.46% of trace, 132,907 events) confirms XDR encoding is a measurable apply-time cost in this workload.
- `recordStorageChanges` already owns each decoded entry's source bytes via `out.modified_ledger_entries[i].data`; today those bytes are dropped on the floor immediately after `xdr_from_opaque`. The encoded `LedgerEntry` payload is byte-identical to what `xdr_argpack_archive` would later produce inside `writeOne`, because XDR encoding is canonical.
- `BucketOutputIterator::put` already has all the structural hooks (`mBuf`, `mHasher`, `mBytesPut`) to accept a pre-encoded blob: it could write `4-byte size header + 4-byte BucketEntry discriminant + cached LedgerEntry bytes` directly, then hash the same buffer that gets written to disk, preserving the on-disk byte sequence and the bucket hash exactly.
- Determinism is preserved: every node sees the same encoded bytes (XDR canonicalization), the on-disk layout is identical, the bucket hash input is identical, and the only change is which CPU op produced the bytes (host return vs. C++ re-encode).

## Anti-Evidence

- `BucketEntry` wraps `LedgerEntry` with a `LIVEENTRY`/`INITENTRY` discriminant; the cache must store only the inner-`LedgerEntry` portion and emit the discriminant separately, otherwise a wrong on-disk layout breaks the bucket hash invariant.
- Classic-modified entries (account/trustline writes during fee processing or P26 classic-from-Soroban allowlist) and TTL deltas don't necessarily flow through `recordStorageChanges`; the cached-byte path must gracefully fall back to `xdr_argpack_archive` for those entries, so a per-entry "has cached bytes" flag is required.
- The current `addLiveBatch` API takes `std::vector<LedgerEntry>` by const reference; threading encoded bytes through `LedgerTxn::getAllEntries` and into the batch requires a parallel vector or an enriched entry struct, which touches multiple bucket APIs.
- Cached encoded bytes consume transient memory (peak ~tens of MB in worst-case soroswap ledgers); they must be released as soon as the bucket file is written to avoid permanent retention.
- A subset of `addLiveBatch` time is already non-encode work (file I/O, hashing, ranged-type-offset bookkeeping, `maybeInitializeCaches`); only the encode portion is removable, so the realized win will be a fraction of `addLiveBatch`' self-time, not the whole thing.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The specific byte-reuse mechanism is not correct: the host-returned `buf.data` is not byte-identical to the `LedgerEntry` later serialized into the live bucket. `recordStorageChanges` decodes the host buffer and calls `upsertLedgerEntry`; in the parallel Soroban path this flows through `ParallelLedgerAccessHelper::upsertLedgerEntry`, `TxParallelApplyLedgerState::upsertEntry`, and `ThreadParallelApplyLedgerState::upsertEntry`, which stamp `LedgerEntry::lastModifiedLedgerSeq` with the applying ledger sequence. `LedgerTxn::Impl::maybeUpdateLastModified` also stamps modified ledger entries during seal before `getAllEntries`. Rust TTL output is explicitly encoded with `last_modified_ledger_seq: 0`, so direct reuse would write stale or zero last-modified values into bucket bytes and change bucket hashes/state.

The performance target is also less direct than stated. `addLiveBatch` enters `LiveBucketList::addBatchInternal`, then `BucketLevel<LiveBucket>::prepareFirstLevel`; the common path builds an in-memory fresh bucket, merges it with level-0 curr, and only then writes the merged output through `BucketOutputIterator::put`/`XDROutputFileStream::writeOne`. Reusing host bytes would only help entries whose final post-Core mutation bytes are known, not all merged entries, and would not remove sorting, copying into `BucketEntry`, merge logic, hashing, file writes, index construction, or fsync.

### Alternative Angle

A refined hypothesis could cache a post-stamp encoding, not the raw host encoding. Since `lastModifiedLedgerSeq` is the first XDR field of `LedgerEntry`, a safe design might patch or regenerate the first four bytes after Core stamps the applying ledger sequence, then carry the cached payload only while the entry remains unmodified. This would need explicit invalidation or replacement whenever entries are merged, TTL bumps are max-merged, `LedgerTxn` seal updates last-modified values, or any later code mutates the `LedgerEntry`.

Before promoting that refined idea, measure only the synchronous `mergeInMemory put loop`/`XDROutputFileStream::writeOne` descendant cost inside `addLiveBatch`, and estimate the share attributable to current-ledger Soroban entries that can retain valid cached bytes. The objective requires a Medium result, so the refined optimization must plausibly save at least 3% of top-line apply time after accounting for unchanged hashing/writing/indexing and the fact that old level-0 entries in the merged output do not have host-returned buffers unless cached bytes are persisted in the in-memory bucket representation too.

### Additional Code Paths

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` — decodes `out.modified_ledger_entries` and passes decoded entries to `upsertLedgerEntry`; the raw buffer is pre-Core-stamp data.
- `src/rust/src/soroban_proto_any.rs:261-297` — builds `modified_ledger_entries`; TTL entries are encoded with `last_modified_ledger_seq: 0`.
- `src/transactions/ParallelApplyUtils.cpp:358-363, 1317-1331, 1124-1133` — parallel apply upsert path stamps `lastModifiedLedgerSeq` after decoding host bytes.
- `src/transactions/ParallelApplyUtils.cpp:720-800` — final parallel changes are moved into a `LedgerTxn` with `createWithoutLoading`/`updateWithoutLoading`.
- `src/ledger/LedgerTxn.cpp:1686-1737, 2368-2406` — `getAllEntries` seals the transaction and `maybeUpdateLastModified` stamps modified ledger entries before extraction.
- `src/bucket/LiveBucket.cpp:380-527, 531-561, 613-698` — live batch conversion sorts/copies entries, creates an in-memory fresh bucket, merges with level-0 curr, and writes the merged bucket output.
- `src/bucket/BucketOutputIterator.cpp:76-180` and `src/util/XDRStream.h:481-515` — final bucket output serializes, writes, hashes, and counts bytes for each output `BucketEntry`.
