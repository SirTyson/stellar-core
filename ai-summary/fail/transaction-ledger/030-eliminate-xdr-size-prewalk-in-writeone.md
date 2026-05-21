# H030: Eliminate redundant `xdr::xdr_size` pre-walk in `XDROutputFileStream::writeOne` by encoding-then-prefix-size

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / bucket write path in apply finalize
**Severity**: Low
**Impact**: Removes one of two full XDR walks per bucket entry written during `finalizeLedgerTxnChanges`/`addLiveBatch`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`XDROutputFileStream::writeOne` (`src/util/XDRStream.h:483`) writes a single
XDR object as a length-prefixed record. The efficient path should perform one
XDR traversal of the object that simultaneously produces the encoded byte
output and lets the caller learn the encoded size to backfill the 4-byte
length prefix; rather than two full traversals (one to compute the size, one
to encode the bytes).

## Mechanism

Today `writeOne` calls `xdr::xdr_size(t)` to compute `sz`, allocates/grows
`mBuf` to `sz + 4`, encodes via `xdr_argpack_archive(p, t)` into the buffer
starting at offset 4, then writes `sz + 4` bytes through `writeBytes` and
updates the SHA256 hasher. `xdr::xdr_size` recursively walks the entire
object — so for `BucketEntry` (which can wrap a `LedgerEntry::ContractData`
containing a recursively serialized `SCVal` payload), the pre-walk does the
same recursive traversal cost as the encode pass.

A revised path can encode first into a self-growing buffer (or into a buffer
sized at an upper bound for trivially-bounded types), capture the encoded
size from `xdr_put`'s position, then back-fill the 4-byte length prefix at
offset 0 of the buffer before writing it out. This yields exactly one XDR
traversal per `writeOne` instead of two.

## Trigger

Run the soroswap apply-load benchmark (`apply-load --mode soroswap-tps`).
Inside `finalizeLedgerTxnChanges`, `addLiveBatch` calls
`mLevels[0].prepareFirstLevel` which in turn calls
`LiveBucket::freshInMemoryOnly` and writes every merged BucketEntry to a
LiveBucketOutputIterator via `BucketOutputIterator::put` →
`XDROutputFileStream::writeOne`. On the soroswap shape this is ~580 k
`writeOne` calls across the 71-ledger trace.

## Target Code

- `src/util/XDRStream.h:483-515` — `XDROutputFileStream::writeOne` performs
  `xdr::xdr_size(t)` followed by `xdr_argpack_archive` (two full walks per
  call).
- `src/bucket/BucketOutputIterator.cpp:153,177` — drives `writeOne` on each
  emitted BucketEntry during bucket-write.
- `src/bucket/LiveBucket.cpp:678-683` — `mergeInMemory put loop` invokes
  `BucketOutputIterator::put` which routes to `writeOne` on the apply thread.
- `src/bucket/BucketListBase.cpp:781-783` — `prepareFirstLevel` synchronously
  drives the put loop in apply path.

## Evidence

- Tracy self-time of `writeOne` is 75.88 ms (0.74% of trace) over 584,280
  apply-window calls; total inclusive time including `xdr_size`+`xdr_put`+
  hash add is 204.54 ms (1.99%). The descendants pulling the inclusive time
  beyond self are `xdr::xdr_size`, `xdr_argpack_archive`, and `SHA256::add`.
- The xdr_size pre-walk is structurally redundant: any modern serializer
  exposes either a known-upper-bound size or a self-growing buffer that
  yields the encoded size at end of encode.

## Anti-Evidence

- Even removing the entire pre-walk recovers at most ~half of the
  `writeOne` inclusive cost outside self, since the encode walk and the
  SHA256 add must be preserved. The realistic savings is on the order of
  ~70-100 ms across the 71-ledger trace, or ~1.0-1.4 ms/ledger
  (≤ 0.5% of the 273 ms baseline).
- The two-pass-pre-size-then-encode pattern is used pervasively across the
  codebase (XDR stream, history checkpoint files, SCP envelopes), and the
  encoder buffer is reused across calls, so the per-call buffer growth is
  amortized out; the only true CPU saving is the recursive walk itself.
- The encoded-then-prefix design needs to either pre-reserve the upper-bound
  size or use a writable archive that supports a self-growing buffer; the
  pinned XDR library does not provide a straightforward growing archive,
  so a wrapper (or an upper-bound estimate) would be needed, adding
  complexity and a small amount of code surface area.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H017 (`017-poststamp-encoded-bytes-in-addlivebatch.md`),
which proposed caching the *entire* encoded byte stream end-to-end through
addLiveBatch; this hypothesis only targets the redundant xdr_size pre-walk
inside writeOne.

### Why It Failed

Below the objective severity threshold. The realistic savings is bounded by
half of `writeOne`'s inclusive cost outside SHA256 hashing, which is on the
order of ~1.0-1.4 ms/ledger (≤ 0.5% of the 273 ms soroswap median). This
sits well below the 3% Medium floor, and the 1% Low minimum, and is at
the edge of benchmark noise. It also matches meta-pattern #18 in
`fail/transaction-ledger/summary.md`: bucket-write refinements remain
ceiling-bound by `finalizeLedgerTxnChanges`'s ~1.3-2% share of soroswap
`closeLedger`, so any single sub-step optimization within the bucket-write
pipeline cannot reach Medium.

### Lesson Learned

When the parent zone (`finalizeLedgerTxnChanges`/`addLiveBatch`) is itself
bounded under ~3% of close-ledger time, no single sub-step optimization
inside that zone can reach the Medium floor. The bucket-write pipeline as
a whole would need to be moved off the apply critical path (rejected by
H001-async-addlivebatch) or replaced with a fundamentally different bucket
representation; eliminating an individual redundant XDR walk is a clarity
win but not a performance optimization at this objective's severity bar.
