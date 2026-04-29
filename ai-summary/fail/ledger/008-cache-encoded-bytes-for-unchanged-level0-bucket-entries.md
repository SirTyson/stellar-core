# H008: Cache post-stamp encoded XDR bytes for unchanged level-0 bucket entries to skip re-serialization in `mergeInMemory put loop`

**Date**: 2026-04-29
**Subsystem**: ledger / bucket commit
**Severity**: Low
**Impact**: <2% soroswap apply-time reduction by skipping XDR re-serialization of unchanged BucketEntry instances when writing the merged level-0 bucket file
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `LiveBucket::mergeInMemory` produces the new level-0 curr bucket, entries that were already present in the previous level-0 curr (and were not overwritten by entries from the freshly-applied batch) should be writable to the new bucket file using their previously-computed XDR encoding rather than re-serialized from the in-memory `LedgerEntry` representation.

## Mechanism

`LiveBucket::mergeInMemory` (`src/bucket/LiveBucket.cpp:614-698`) calls `mergeInternal` to produce a sorted `mergedEntries` vector, then iterates that vector through `out.put(e)` (`mergeInMemory put loop`), which serializes each `BucketEntry` to XDR, hashes the bytes incrementally, and writes them to the new level-0 file. Many of those entries are physically the same `BucketEntry` objects that were just shallow-copied from `oldBucket->getInMemoryEntries()` in `mergeInternal`; they were already serialized once when the previous level-0 bucket was written. Caching the encoded bytes alongside each in-memory `BucketEntry` would let the put loop skip XDR encoding for unchanged entries (only freshly-applied entries from the new batch lack a cached encoding). For freshly-applied `LedgerEntry`s, the cached encoding can be filled at first write so that entries surviving into subsequent ledger merges benefit from the cache.

## Trigger

Run the soroswap apply-load benchmark with default config. Each ledger close enters `addLiveBatch` → `prepareFirstLevel` → `mergeInMemory` and writes the merged level-0 bucket; with ~8000 entries per merged bucket and 70 merges per benchmark window, the put loop serializes ~560k entries.

## Target Code

- `src/bucket/LiveBucket.cpp:614-698` — `mergeInMemory` and the `mergeInMemory put loop` that drives `out.put(e)`.
- `src/bucket/LiveBucket.cpp:678-683` — the put loop itself.
- `src/bucket/BucketOutputIterator.cpp:80` and `src/util/XDRStream.h:485` — `put` and `writeOne` perform per-entry XDR encoding, hashing, and write; the cached-bytes path would short-circuit the XDR encoding portion only.
- `src/bucket/LiveBucket.cpp:380-484` — `convertToBucketEntry` builds `BucketEntry`s without encoded bytes today.

## Evidence

From the headline soroswap Tracy trace:
- `mergeInMemory put loop` = `69,937,029 ns` / 70 calls = ~1 ms per ledger, **1.21% of applyLedger total (5,774,332,215 ns)**.
- `writeOne` (`util/XDRStream.h:485`) total = `203,762,373 ns` / 560,061 calls = 363 ns/call (mix of hash + write + serialization-related cost).
- The merged bucket vector is constructed from `mergedEntries` whose dominant share is shallow copies from `oldBucket->getInMemoryEntries()`; those entries had their bytes computed at the previous ledger close.

## Anti-Evidence

- The `put loop` self-time is well below the Medium severity threshold for this objective. Even fully eliminating XDR encoding cost (which is impossible — hashing and file write would still need the bytes) would not reach 3% of `applyLedger`.
- Per the H006 reviewer feedback (`ai-summary/fail/ledger/006-reuse-host-encoded-bytes-in-addlivebatch.md`), the synchronous `mergeInMemory put loop`/`XDROutputFileStream::writeOne` descendant cost inside `addLiveBatch` is the relevant in-scope share, and that share was already characterized as below threshold for a Medium claim.
- Storing per-entry encoded byte buffers in the in-memory bucket vector materially increases memory footprint of the BucketList in-memory representation, which can hurt cache locality on bucket scans (a known hot path during transaction validation) — a side effect that may erase the small write-side gain.
- `BucketEntry` mutations of `lastModifiedLedgerSeq` invalidate cached encodings; the cache must be invalidated whenever the entry is touched, requiring careful coordination with `convertToBucketEntry` and any future code that mutates an in-memory `BucketEntry`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H006 (which targeted reusing Soroban host output bytes pre-stamp); this hypothesis targets cached post-stamp bucket-entry encodings on the merge path.

### Why It Failed

The synchronous `mergeInMemory put loop` is 1.21% of applyLedger total, and the Medium severity threshold for this objective is 3-10%. Even an ideal optimization that eliminated all XDR encoding work in the put loop would remain below the Medium floor; the writeOne hashing and file write costs are inherent to producing the new bucket file and cannot be avoided. Per H006 reviewer guidance, the relevant in-scope share of `addLiveBatch` is already characterized as too small to support a Medium claim, and adding per-entry cached byte buffers also imposes a working-set cost on bucket scans that further erodes the gain.

### Lesson Learned

The synchronous `mergeInMemory put loop` is below the Medium severity floor for the soroswap objective. Future bucket-commit hypotheses must aim at structural redesigns of the entire `addLiveBatch` critical path (~5% of applyLedger) rather than localized optimizations of the inner XDR-encoding loop, which is too small to produce a Medium-tier improvement on its own.
