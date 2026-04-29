# H017: Cache post-stamp Soroban entry XDR bytes through `addLiveBatch` to skip `XDROutputFileStream::writeOne` re-encode

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / bucket commit critical path
**Severity**: Low
**Impact**: Eliminate the `xdr_size`+`xdr_argpack_archive` re-encode for current-ledger Soroban entries inside `BucketOutputIterator::put`/`writeOne`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `LedgerManagerImpl::sealLedgerTxnAndStoreInBucketsAndDB` calls
`finalizeLedgerTxnChanges` -> `addLiveBatch` -> `LiveBucket::fresh` ->
`BucketOutputIterator::put` -> `XDROutputFileStream::writeOne`, the
synchronous level-0 bucket file write should be able to reuse the
already-encoded bytes for current-ledger Soroban entries (CONTRACT_DATA,
CONTRACT_CODE, TTL) so it does not invoke `xdr::xdr_size(BucketEntry)` and
`xdr_argpack_archive` a second time on payloads the host had already
serialized.  Only entries that are merged from older bucket levels (i.e.,
not produced by the current ledger's host invocations) and entries that
do not have valid cached bytes (e.g. classic accounts/trustlines, post-
stamp mutations beyond `lastModifiedLedgerSeq`) should still pay the full
`writeOne` re-encode.

## Mechanism

The H006 reviewer (`fail/ledger/006-reuse-host-encoded-bytes-in-addlivebatch.md`)
noted that the host-returned `out.modified_ledger_entries` bytes are not
byte-identical to the final on-disk bytes because of two stamps:
`lastModifiedLedgerSeq` and the LedgerTxn seal `maybeUpdateLastModified`
pass.  `lastModifiedLedgerSeq` is the *first* XDR field of `LedgerEntry`,
which means a refined design could (a) accept the host bytes, (b) patch
or regenerate the leading 4-byte field after `upsertLedgerEntry` stamps
the ledger seq, and (c) plumb the cached bytes through `LedgerTxn::Impl`
into `getAllEntries` for the live-bucket batch.  The actual deviation
from the desired behavior is that today, `writeOne` re-runs the entire
canonical XDR encoder for every output entry, even when the entry's
on-disk bytes are deterministically derivable from the host buffer plus
a stamped 4-byte prefix.

## Trigger

Run the soroswap apply-load benchmark
(`soroswap, TX=2000, T=8`).  Per ledger ~870 Soroban-modified entries
flow through `recordStorageChanges` and then through `addLiveBatch` on
the apply thread; today every one of those entries is XDR-encoded twice
(once by the host on the way out, once by `writeOne` on the way to disk).

## Target Code

- `src/bucket/BucketOutputIterator.cpp:140-200` - `BucketOutputIterator::put`/`getBucket`
  buffer the `BucketEntry` and call `mOut.writeOne`.
- `src/util/XDRStream.h:480-515` - `XDROutputFileStream::writeOne<T>` always
  re-encodes via `xdr::xdr_size(t)` and `xdr_argpack_archive(p, t)`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-741` -
  `recordStorageChanges` decodes `out.modified_ledger_entries` and discards
  the encoded buffer; this is the natural cache point for the encoded bytes.
- `src/transactions/ParallelApplyUtils.cpp:358-363,1124-1133,1317-1331` -
  parallel-apply upsert path stamps `lastModifiedLedgerSeq` after decoding.
- `src/ledger/LedgerTxn.cpp:1686-1737,2368-2406` - `getAllEntries` seals
  the LedgerTxn and `maybeUpdateLastModified` stamps modified entries
  before extraction.
- `src/bucket/LiveBucket.cpp:380-561,613-698` - live batch conversion,
  fresh in-memory bucket creation, and merge with level-0 curr.

## Evidence

- Tracy soroswap trace (`ai-summary/CURRENT_STATE.md`):
  - `closeLedger` total apply time on the bench is ~313 ms median
    (`time_writes=true`, so the bench timer wraps the whole `closeLedger`,
    including `finalizeLedgerTxnChanges`).
  - `finalizeLedgerTxnChanges` total 325 ms / 70 calls = ~4.65 ms/ledger
    (3.18% of trace).
  - `addLiveBatch` (sync) and `addBatchInternal` together account for
    ~4.2 ms/ledger.
  - `writeOne` (`util/XDRStream.h:485`) total 203.8 ms / 560,061 calls
    (1.99% of trace, ~371 ns/call), of which a substantial fraction is
    the re-encode side that a post-stamp cache could elide.
- The cached-bytes design is directly addressed in the H006 reviewer's
  "Alternative Angle" suggestion; the present hypothesis is the concrete
  refinement of that angle.

## Anti-Evidence

- `closeLedger` median is ~313 ms, so even a perfect elimination of the
  full `writeOne` re-encode for current-ledger Soroban entries
  (~4.2 ms / 313 ms) is only ~1.3% of apply time - well under the 3%
  Medium floor and at the edge of benchmark noise.
- The implementation surface is non-trivial: cached bytes must be
  invalidated whenever the entry is mutated again after stamping, the
  in-memory bucket merge must thread bytes through `BucketEntryComparator`
  / `mergeInMemory put loop`, and the cache must short-circuit gracefully
  for non-Soroban or post-mutation entries.
- Old level-0 entries that get merged into the new bucket do not have
  host-returned bytes; only the *current-ledger* Soroban entries can use
  the fast path, so the realized win is bounded by the fraction of merged
  output that is current-ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS - this is the concrete refinement of the H006 reviewer's
"Alternative Angle"; not duplicated in any existing hypothesis/fail file.

### Why It Failed

Even an idealized version of this refinement caps at the full
`finalizeLedgerTxnChanges` synchronous time for current-ledger Soroban
entries, which is ~1.3% of the bench-measured `closeLedger` median.
That is below the objective's 3% Medium floor and at the boundary of
benchmark noise.  The implementation cost (post-stamp cache invalidation,
in-memory bucket merge plumbing, byte-vs-decoded dual-path inside
`BucketOutputIterator::put`) is not justified by a Low-tier improvement.

### Lesson Learned

Refinements of `addLiveBatch`-targeted hypotheses cannot escape the
~1.3-2% ceiling imposed by `finalizeLedgerTxnChanges`'s share of
`closeLedger` for soroswap.  Future bucket-write hypotheses must target
either (a) the full bucket commit pipeline including the in-memory merge
*and* the on-disk write, or (b) move the entire write off the apply
thread with a deferred join past independent next-ledger work; isolated
re-encode elimination cannot reach Medium.
