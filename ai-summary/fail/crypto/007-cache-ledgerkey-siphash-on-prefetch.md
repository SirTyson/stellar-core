# H007: Cache LedgerKey SipHash on Soroban Prefetch to Cut InMemoryBucketState::scan Lookup Cost

**Date**: 2026-04-28
**Subsystem**: crypto / bucket
**Severity**: Medium (projected, before review)
**Impact**: reduce per-lookup `xdrComputeHash<LedgerKey>` cost in the bucket
in-memory index `scan` path during soroswap apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InMemoryBucketState::scan` should look up a `LedgerKey` in `mEntries`
(an `unordered_set` keyed by `LedgerKey` via `std::hash<LedgerKey>` →
`shortHash::xdrComputeHash`) cheaply enough that scan self-time is
dominated by equality compare and memory access, not by recomputing a
SipHash-2-4 over an XDR-serialized representation of the same key. When
the same key is repeatedly probed across multiple bucket levels in a
single Soroban operation footprint, the hash should be computed once
and reused.

## Mechanism

The current soroswap trace shows `scan,bucket/InMemoryIndex.cpp:253`
at 3.07 s self-time across 1,447,169 calls (~2.1 µs mean). Each call
evaluates `mEntries.find(searchKey)`, which hashes `searchKey` via
`std::hash<LedgerKey>` → `shortHash::xdrComputeHash` (XDR-archives the
full `LedgerKey` to a SipHash-2-4 stream). For `CONTRACT_DATA` and
`CONTRACT_CODE` keys — the dominant entry types in soroswap apply —
the same `LedgerKey` is probed once per bucket level (one
`InMemoryBucketState::scan` per level inside `BucketListSnapshot::load`),
so each footprint key incurs the SipHash cost N times. The hypothesis
was: cache the per-key SipHash on the parallel-apply `LedgerKey` set
(or on the `LedgerKeyMeta` already constructed in
`ParallelApplyUtils.cpp`) and pass it through to `scan` so each level
can skip the hash recomputation. Since `getBucketEntry` is 1.14M calls
inside apply and `scan` is its child, even a 30% reduction in scan
self-time would be ~10% of the apply window.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap scenario and
inspect `InMemoryBucketState::scan` self-time inside `applyLedger`
descendants in the captured Tracy trace.

## Target Code

- `src/bucket/InMemoryIndex.cpp:251-262` — `InMemoryBucketState::scan`
  performs `mEntries.find(searchKey)`, hashing the key via SipHash.
- `src/bucket/InMemoryIndex.h` — `InternalInMemoryBucketEntry` and the
  `unordered_set` template instantiation use `std::hash<LedgerKey>`.
- `src/crypto/ShortHash.cpp` and `src/crypto/XDRHasher.h` —
  `xdrComputeHash` walks the XDR archiver for each call.
- `src/bucket/BucketListSnapshot.cpp:174,317` — `getBucketEntry` calls
  `scan` once per bucket level until the key is found.

## Evidence

- `scan` is the largest single self-time descendant of any `applyLedger`
  child in the soroswap trace at 3.07 s self / 1.45M calls.
- `getBucketEntry,bucket/BucketListSnapshot.cpp:174` is 1.15M calls
  with mean 135 ns self — confirming `scan` is invoked from many bucket
  levels per lookup, multiplying the per-key hash cost.
- `xdrComputeHash<LedgerKey>` does walk a non-trivial XDR archive for
  Soroban keys (contract address + ScVal subtree + durability), so the
  per-call hashing cost is plausibly hundreds of nanoseconds — multiple
  hundred microseconds aggregated over millions of calls.

## Anti-Evidence

- The 2.1 µs mean of `scan` is far larger than the cost of a SipHash —
  even a complex `LedgerKey` hashes in well under 500 ns. The dominant
  cost is almost certainly the `unordered_set` bucket walk plus the
  per-entry equality compare (which itself XDR-compares the
  `LedgerKey`), not the hash.
- This is a bucket-subsystem optimization, not crypto: the hash function
  is incidental, and any genuine win would come from rethinking the
  index data structure (e.g., cheaper equality compare, denser layout,
  or hashing the encoded LedgerKey bytes once).
- Scan call counts include non-apply background bucket work (compaction,
  index build, merges); the in-apply share is materially smaller than
  the 3.07 s headline.
- The `searchKey` is constructed afresh per lookup by callers; caching
  its hash requires API changes through `BucketListSnapshot::load` and
  the parallel-apply code, which is invasive for a sub-Medium win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — LedgerKey-SipHash precomputation through the bucket
scan path was not previously investigated in crypto fail/hypothesis/
reviewed/poc records.

### Why It Failed

The cost being targeted (SipHash recomputation per `scan`) is not the
dominant component of `scan` self-time. The 2.1 µs mean is consistent
with `unordered_set` bucket traversal and XDR equality compare, not with
SipHash, which fits in the low hundreds of nanoseconds even for complex
`LedgerKey` shapes. Eliminating the hash recomputation entirely would
likely return well under 1% of apply time, below the objective's Medium
floor. Genuine wins in this code path require restructuring the
in-memory index itself (data layout, equality compare, deduplication of
multi-level lookups), which is bucket-subsystem work, not crypto.

### Lesson Learned

When a bucket lookup zone shows large self-time, attribute it to data
structure traversal and equality compare before blaming the
hash function. SipHash via `xdrComputeHash` is fast enough that
eliminating it produces sub-1% wins; the index-side cost dominates.
Crypto-subsystem hypotheses cannot reach Medium severity by targeting
hash table key derivation.
