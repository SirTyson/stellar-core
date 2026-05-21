# H005: Eliminate Intermediate `mergedEntries` Vector in `mergeInMemory`

**Date**: 2026-05-05
**Subsystem**: ledger / bucket
**Severity**: Low
**Impact**: apply time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::mergeInMemory` (`src/bucket/LiveBucket.cpp:614`) merges the existing
level-0 `curr` bucket with the freshly-built in-memory snap of this ledger's
entries to produce the new level-0 `curr`. A maximally efficient implementation
would walk the two sorted input streams once and stream each merged entry
directly into the output `BucketOutputIterator::put`, with no intermediate
`std::vector<BucketEntry>` materialization. The asynchronous `LiveBucketIndex`
construction would consume entries via the same pass (e.g., via a fork-style
two-consumer pipe or via post-hoc index reconstruction from the just-written
bucket file).

## Mechanism

The current code (LiveBucket.cpp:614-688) performs `mergeInternal` to populate
a `std::vector<BucketEntry> mergedEntries`, then walks `mergedEntries` twice:
once asynchronously to build the index (line ~666 `std::async([&]{ ... })`),
and once synchronously in the `put loop` (line 678) to write to the output
file. The intermediate vector forces a full materialization of all merged
BucketEntries (XDR-copy each LedgerEntry into a vector slot) before any output
work begins, plus another pass over those entries from the put loop.

This is structurally distinct from previously failed
`002-stream-level0-bucket-merge-output.md` (which proposed eliminating the
write pass), but ends up below the Medium floor for the same underlying
reason: the dominant cost in this region is XDR encoding + SHA256 hashing per
output entry inside `BucketOutputIterator::put`, not the vector materialization.

## Trigger

Soroswap close ledger; level-0 commit on every ledger with ~4000 merged
entries written to disk.

## Target Code

- `src/bucket/LiveBucket.cpp:614-688` — `mergeInMemory` and put loop
- `src/bucket/BucketOutputIterator.cpp:78-167` — `put`/buffered write
- `src/util/XDRStream.h:483-510` — `writeOne` (encode + hash + write)

## Evidence

- `mergeInMemory` total wall ≈ 138 ms / 72 ledgers ≈ 1.92 ms / ledger ≈ 2.6%.
- The intermediate vector is 4000+ BucketEntries × ~300 bytes ≈ 1.2 MB
  per-ledger allocation that is built-and-immediately-walked. Eliminating
  it would remove ~1 ms/ledger of allocation+copy overhead — but the
  remaining wall is dominated by `BucketOutputIterator::put` self time
  (67 ms / 72 = 0.95 ms/ledger) plus `writeOne` self (76 ms / 72 = 1.07
  ms/ledger), both of which are unavoidable encode+hash work.

## Anti-Evidence

- The async `LiveBucketIndex` build needs to walk every entry; merging that
  consumer with the put-loop consumer is non-trivial without a queue
  (which would re-introduce comparable allocation overhead).
- `convertToBucketEntry` already produces the new-snap as a sorted vector;
  removing the merged-output vector would still require materializing
  entries somewhere or building the index via a second pass over the
  written bucket file (additional disk I/O).
- The structural change is invasive (touches both bucket build and index
  build) for a sub-Medium projected win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `002-stream-level0-bucket-merge-output.md`
(that hypothesis proposed eliminating the synchronous write pass, this one
proposes eliminating the intermediate vector); also distinct from
`014-defer-bucket-file-write-mergeinmemory.md` (defer the file write).

### Why It Failed

The intermediate `mergedEntries` vector adds at most ~1 ms/ledger of
allocation+copy overhead. The dominant cost in `mergeInMemory` is the
synchronous XDR-encode + SHA256-hash loop inside
`BucketOutputIterator::put`/`XDRStream::writeOne` (per-ledger ~2 ms summed
over the put-loop self time). Even fully eliminating the intermediate
vector would leave the encode+hash on the critical path; the projected
win is below the Medium 3% floor.

### Lesson Learned

For `mergeInMemory`-class hypotheses, the 3% Medium floor cannot be
reached by removing materialization-only overhead; only structural
redesigns that remove encode-or-hash work from the synchronous critical
path could plausibly clear Medium, and those have been ruled out by
`014-defer-bucket-file-write-mergeinmemory.md` (the bucket hash must be
computed synchronously to feed `snapshotLedger`).
