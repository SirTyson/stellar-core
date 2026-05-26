# H005: Single-pass XDR size + encode in `XDROutputFileStream::writeOne` to remove redundant entry traversal in bucket put loop

**Date**: 2026-05-26
**Subsystem**: ledger / bucket commit (XDR encoding)
**Severity**: Low
**Impact**: Apply-thread serial reduction in `addLiveBatch` → `mergeInMemory` put loop by eliminating one of the two full XDR traversals per bucket entry
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`XDROutputFileStream::writeOne` at `src/util/XDRStream.h:483` is called
once per bucket entry from `LiveBucketOutputIterator::put`
(`src/bucket/BucketOutputIterator.cpp:78`), which in turn is driven by
the `mergeInMemory put loop`
(`src/bucket/LiveBucket.cpp:678-683`) during every soroswap ledger's
`addLiveBatch`. For each entry, `writeOne`:

1. Calls `xdr_size(t)` (line 486) — a **full recursive traversal** of
   the `BucketEntry`'s XDR tree to compute the encoded byte length.
2. Allocates/sizes `mBuf` to `sz + 4` (line 489-492).
3. Writes the 4-byte length prefix.
4. Calls `xdr_argpack_archive(p, t)` (line 501) — a **second full
   recursive traversal** to actually serialize the entry into `mBuf`.
5. Calls `writeBytes(mBuf.data(), toWrite)` to push to the file buffer.
6. SHA256-updates the hasher with the encoded bytes.

Expected correct behavior is to produce the same length-prefixed
encoded XDR followed by the same SHA256 update. A more efficient
implementation can achieve this with a single traversal by writing the
encoded bytes into a growable buffer first, recording the actual
length, and then either (a) back-patching the length prefix into a
pre-reserved 4-byte slot, or (b) writing the length prefix to a
separate small buffer and using a 2-slice writev/hasher.add sequence.
Both eliminate the upfront `xdr_size` traversal entirely.

## Mechanism

For deeply-nested XDR types like `BucketEntry::liveEntry()` containing
`CONTRACT_DATA` with rich `SCVal` maps (the dominant entry type in the
soroswap workload), `xdr_size` walks every nested variant, vector
length field, and string/opaque length, performing nontrivial work
per node. `xdr_argpack_archive` walks the exact same tree, doing the
same node-by-node dispatch plus the actual byte writes. The two-pass
design pays the tree-walk cost twice; a single-pass encoder pays it
once. Removing one full traversal halves the C++ XDR walking cost in
the put loop without changing any output bytes, hashes, or file
contents.

## Trigger

Run the soroswap apply-load benchmark. Every ledger writes ~thousands
of `CONTRACT_DATA` entries (soroswap pair state) through
`mergeInMemory`'s put loop; each entry triggers two full XDR
traversals in `writeOne`. The redundancy is purely overhead, since the
size is consumed only to size the local buffer and prefix; the actual
size of the encoded bytes after `xdr_argpack_archive` is also known.

## Target Code

- `src/util/XDRStream.h:483-515` — `XDROutputFileStream::writeOne`:
  the two-pass `xdr_size` + `xdr_argpack_archive` site.
- `src/bucket/BucketOutputIterator.cpp:78-165` — `put` calls
  `writeOne` via `mOut.writeOne(*mBuf, ...)` for every entry flushed
  through the merge output.
- `src/bucket/LiveBucket.cpp:678-683` — `mergeInMemory put loop`:
  the soroswap-hot driver of the per-entry `writeOne` calls.
- `src/bucket/LiveBucket.cpp:511-520` — `LiveBucket::fresh` for the
  fresh-bucket path.

## Evidence

- `xdr_size` and `xdr_argpack_archive` in the libstellar-xdr template
  ecosystem are independent recursive walks over the same XDR tree;
  they share no traversal state. Eliminating one is a localized
  refactor of `writeOne` — no callers above the function need to
  change.
- The redundant first traversal exists purely to size the buffer; a
  single-pass design with buffer growth (e.g., write into
  `std::vector<char>` then back-patch length, or hash header + body
  separately) is well-understood and used in other XDR-style
  serializers.
- Recent success `002-cache-old-entry-xdr-sizes` (3.46% Medium win)
  established that eliminating redundant XDR traversals on this
  workload is a measurable lever — but on the Rust host side, not in
  the C++ bucket writer.

## Anti-Evidence

- Per failed hypothesis
  `008-cache-encoded-bytes-for-unchanged-level0-bucket-entries.md`,
  the synchronous `mergeInMemory put loop` is **1.21% of applyLedger
  total**. Even fully eliminating one of the two XDR traversals would
  recover at most ~half of the C++ XDR-walking fraction of that
  1.21% — well below the Medium 3% threshold for this objective.
- Within `writeOne`, after the XDR walks, `writeBytes` and
  `hasher->add` are inherent costs that cannot be removed; the
  recoverable share is bounded to the XDR-walking fraction of the
  put loop, not the full put loop.
- Tracy `mergeInMemory put loop` zone in the current soroswap trace
  (`9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`)
  contributes ≪ 2 ms/ledger of recoverable XDR-walking time; halving
  it yields ≪ 1 ms/ledger ≈ < 0.5% of the 207 ms baseline.
- Lesson from `008-cache-encoded-bytes-for-unchanged-level0-bucket-entries.md`
  is explicit: "Future bucket-commit hypotheses must aim at
  structural redesigns of the entire `addLiveBatch` critical path
  rather than localized optimizations of the inner XDR-encoding
  loop." This proposal is exactly the kind of inner-loop tweak
  rejected by that lesson.
- A correct single-pass implementation must preserve the exact same
  byte sequence fed to `hasher->add` (so bucket hashes match across
  nodes); any chunking change must keep hash-feeding semantics
  identical, restricting the redesign surface.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — prior bucket-commit failures targeted entry-bytes
caching (008, 010, 011) and intermediate-vector elimination (005), but
no prior hypothesis targeted the two-pass nature of
`XDROutputFileStream::writeOne` itself.

### Why It Failed

Below this objective's Medium severity threshold (3-10% apply time
reduction). Per fail
`008-cache-encoded-bytes-for-unchanged-level0-bucket-entries.md`, the
entire synchronous `mergeInMemory put loop` is 1.21% of applyLedger;
the C++ XDR-walking fraction of that is a subset, and halving it
(best case) recovers < 0.6% of apply time. That is below both the 1%
benchmark noise floor and the 3% Medium floor. The bucket-commit
critical path needs a wholesale redesign — not another inner-loop
XDR tweak — to clear the threshold.

### Lesson Learned

Reaffirms the lesson from fail 008: localized XDR-encoding
optimizations in the bucket put loop are structurally bounded by the
put loop's small share of applyLedger. Any future single-pass /
zero-copy serializer hypothesis for `writeOne` must either be
paired with a larger structural change (e.g., bypassing the per-entry
encode for unchanged in-memory entries that already carry encoded
bytes from upstream) or rejected on cost-to-impact grounds.
