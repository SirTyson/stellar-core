# H001: Precompute LedgerKey hash once per `BucketListSnapshot::load` and reuse across all bucket-level `InMemoryBucketState::scan` probes

**Date**: 2026-04-30
**Subsystem**: bucket / soroban
**Severity**: Medium
**Impact**: Apply-time reduction in the parallel-apply storage-read path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A single `SearchableBucketListSnapshot<LiveBucket>::load(LedgerKey const& k)`
call should hash `k` at most once. The lookup walks every level of the
BucketList (`loopAllBuckets`) — currently up to ~22 levels × 2 buckets
(curr + snap), i.e. up to ~44 per-bucket lookups for a single load — and each
of those bucket lookups eventually calls `InMemoryBucketState::scan(k)` →
`mEntries.find(k)`. The boost flat-set stores a precomputed hash on the
*entry* side (see `InternalInMemoryBucketEntry::mHash`, set once in the
ctor), but the *query* side (`k`) is rehashed by the hasher on every
`find`. Because `k` is identical across all 44 probes, the LedgerKey hash
should be computed exactly once per `load` call, then reused for every
bucket level. After the first level, scan should reduce to: pointer
compare hashes + pointer-compare equality on collision.

## Mechanism

`std::hash<LedgerKey>` is non-trivial. For a `CONTRACT_DATA` key (the
dominant key shape in soroswap) it walks the discriminant, the
`SCAddress` variant (CONTRACT vs ACCOUNT, then a 32-byte payload), the
`SCVal` key variant, and the durability enum. For TTL keys it hashes a
32-byte `keyHash`. The Tracy zone for `InMemoryBucketState::scan`
(`bucket/InMemoryIndex.cpp:253`) reports **1.915 s of self-time across
914,317 calls — 18.6 % of the trace, ~2 µs per call**. That zone body is
literally `mEntries.find(searchKey)` plus the `ZoneScoped` macro, so the
2 µs per call is dominated by `std::hash<LedgerKey>(searchKey)` and the
flat-set probe. With ~44 levels per `load` and the same `k` reused, ~43/44
of those hash computations are pure repetition — no observable effect on
behavior.

The optimization: change `InMemoryBucketState::scan` (and the index
`lookup` plumbing in `bucket/LiveBucketIndex.cpp`/`HotArchiveBucketIndex.cpp`)
to accept a *precomputed* hash alongside the key, and have
`SearchableBucketListSnapshot::load` (and `loadKeysInternal` /
`loadKeysFromBucket`) compute the hash once before entering the
per-bucket loop. boost::unordered_flat_set supports this via
`find(hash, key, equal)` (or by switching to a transparent hasher that
accepts a `(LedgerKey, size_t)` pair). The change preserves all observable
semantics: same lookup result, same iterator returned, same bucket-walk
order. It only avoids redundant hashing of an immutable input.

## Trigger

Run the apply-load matrix on the soroswap benchmark; the parallel-apply
worker threads continuously call `BucketListSnapshot::load` from the
soroban storage backend (`ParallelLedgerAccessHelper`-style reads not
already covered by the cached `ParallelApplyLedgerKey` path, plus all
`load` calls that originate outside parallel apply, e.g. classic-entry
preload and TTL reads). Tracy will show `scan` self-time drop substantially
on the worker-thread aggregate, with `applySorobanStageClustersInParallel`
shrinking proportionally on wall-clock.

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

## Target Code

- `src/bucket/InMemoryIndex.cpp:249-262` — `InMemoryBucketState::scan`; the
  hot single-line `mEntries.find(searchKey)` that pays the recomputed
  `std::hash<LedgerKey>` cost on every level.
- `src/bucket/InMemoryIndex.cpp:198-239` — `InternalInMemoryBucketEntry`
  already caches `mHash`; mirror this on the query side via a transparent
  hasher overload or `find(hash, key, equal)` on the boost set.
- `src/bucket/BucketListSnapshot.cpp:280-346` —
  `SearchableBucketListSnapshot::load` + `loopAllBuckets`; this is where
  the per-`k` hash should be computed once and threaded into `getBucketEntry`
  → `getIndex().lookup(k, hash)`.
- `src/bucket/BucketListSnapshot.cpp:166-201` — `getBucketEntry`; needs a
  `(LedgerKey, size_t hash)` overload that forwards to the index.
- `src/bucket/LiveBucketIndex.cpp` / `src/bucket/HotArchiveBucketIndex.cpp`
  — `LiveBucketIndex::lookup` / `HotArchiveBucketIndex::lookup`; these are
  the index-level entry points that currently call into
  `InMemoryBucketState::scan`. Add a hash-aware overload.
- `src/bucket/BucketListSnapshot.cpp:208-260` — `loadKeysFromBucket`; the
  bulk-key path also reuses the same `LedgerKey` across multiple buckets
  per key, so it should benefit from the same change.

## Evidence

- Tracy trace
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`
  — `scan` (`bucket/InMemoryIndex.cpp:253`) reports
  `self_total_ns = 1,915,555,231`, `count = 914,317`,
  `mean_ns ≈ 2,095` — i.e. **18.6 % of trace self-time**. The zone body is
  a single `mEntries.find` call.
- The stored entries already pre-cache their hash in
  `InternalInMemoryBucketEntry::mHash` (line 200, 203) — confirming the
  authors recognized hashing cost is significant. The asymmetry that the
  *query* side rehashes on every probe is the leftover inefficiency.
- `BucketListSnapshot::load` (line 327) and `loopAllBuckets` (line 282)
  show the per-bucket loop with no precomputed hash — the same `k` is
  passed to `getBucketEntry` for every level, and `getBucketEntry` calls
  `bucket->getIndex().lookup(k)`, which has no awareness of prior probes.
- The recently accepted optimization
  `success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md` proves
  the same pattern (caching LedgerKey hashes once per immutable input)
  yielded **2.66 % soroswap and 4.13 % max-sac** in the parallel-apply map
  layer. The bucket-list `load` path is structurally identical — same key
  reused across many hash probes — but lives at a different layer (storage
  reads, not parallel-apply bookkeeping), so the win is incremental and
  non-overlapping with #004.
- Soroswap is dominated by `CONTRACT_DATA` reads whose hash visits
  variant boilerplate; max-sac touches mostly TRUSTLINE/CONTRACT_DATA. Both
  benefit because `load` is called from every soroban storage read.

## Anti-Evidence

- Some `load` calls short-circuit early (cache hit at the first level via
  `IndexReturnState::CACHE_HIT` in `getBucketEntry`, line 184), so the
  full 22-level walk is not always exercised. The 18.6 % `scan` self-time
  measured by Tracy already integrates this short-circuit effect — it is
  the *post*-cache-hit residual cost, so the projected savings are
  measured against the actual hot path, not a hypothetical worst case.
- `boost::unordered_flat_set::find` may already cache a hash inside the
  hasher object across one call, but it cannot cache across separate
  `find` calls on different sets (each bucket has its own
  `InMemoryBucketState`). Confirmed by reading
  boost/unordered/unordered_flat_set.hpp interface in the vendored copy.
- The optimization requires a non-trivial API change (new
  hash-aware `lookup`/`scan` overload propagated through 3 layers) and
  must preserve the exact return semantics of the existing
  `find`/`scan` (same iterator, same `IndexReturnState`). Net diff is
  non-trivial but localized.
- `ParallelApplyLedgerKey` already pre-hashes the per-tx footprint keys
  for *parallel-apply maps* (success/004), but the bucket-list scan path
  still uses raw `LedgerKey`. They live in disjoint code paths.

## Projected Impact

If even 30 % of the 1.9 s `scan` self-time is the redundant key hash
(conservative — the rest is the flat-set probe + ZoneScoped overhead),
eliminating ~95 % of those hash recomputes saves
`1.9 s × 0.30 × 0.95 ≈ 540 ms` aggregated across worker threads. With 8
workers and 70 ledgers in the trace, that's
`540 ms / 8 / 70 ≈ 0.96 ms` per ledger, ≈ **1.3 % of the 73 ms apply
window**. If hash cost is closer to 50 % of the zone time (plausible for
CONTRACT_DATA keys) the savings rise to **~2.2 %**, and if the win
generalizes to other `load` callers (classic preload, TTL reads outside
the parallel-apply hot path) the total apply-time win can reach the
**Medium 3–10 %** range. Reviewer should confirm with a focused
microbenchmark or an instrumentation-pass that splits hash cost from
flat-set probe cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `004-cache-ledgerkey-hash-bucket-walk.md`
**Failed At**: reviewer

### Trace Summary

The current source still has the bucket-list point-load shape described here: `SearchableBucketListSnapshot::load` loops newest-to-oldest over buckets and calls `getBucketEntry(bucket, k)`, which calls `bucket->getIndex().lookup(k)`. For live in-memory-index buckets, `LiveBucketIndex::lookup` reaches `InMemoryIndex::scan`, and `InMemoryBucketState::scan` performs `mEntries.find(searchKey)` using a transparent hasher whose `LedgerKey` overload calls `std::hash<LedgerKey>{}(key)`. However this is substantially the same optimization already recorded as `004-cache-ledgerkey-hash-bucket-walk.md`: cache `LedgerKey` hash across the `getBucketEntry` bucket-list walk to avoid per-level rehashing. That prior investigation rejected the idea as below the optimize-soroswap severity threshold, and this hypothesis's own projection is only ~1.3-2.2% unless additional unproven callers lift it into Medium.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:24` — prior failed investigation `004-cache-ledgerkey-hash-bucket-walk.md` covers the same mechanism and rejected it as sub-1% / below threshold.
- `src/bucket/BucketListSnapshot.cpp:171-201` — `getBucketEntry` performs one index `lookup(k)` per bucket and returns cache hit, file offset, or not-found.
- `src/bucket/BucketListSnapshot.cpp:282-345` — `loopAllBuckets` and `load` reuse the same `LedgerKey const& k` across all bucket probes until the first hit.
- `src/bucket/BucketListSnapshot.cpp:210-277` — `loadKeysFromBucket` similarly passes each current key to `index.scan(indexIter, *currKeyIt)` while walking buckets.
- `src/bucket/LiveBucketIndex.cpp:223-239` — live point lookup checks the account cache for disk indexes, then delegates to either `DiskIndex::scan` or `InMemoryIndex::scan`.
- `src/bucket/LiveBucketIndex.cpp:242-257` — bulk scan delegates to the same disk/in-memory scan paths.
- `src/bucket/InMemoryIndex.h:47-62` — stored in-memory entries expose cached `mHash`, but the transparent `LedgerKey` hasher computes `std::hash<LedgerKey>{}(key)` for each query.
- `src/bucket/InMemoryIndex.cpp:198-204` — stored `InternalInMemoryBucketEntry` hash is computed once at index construction.
- `src/bucket/InMemoryIndex.cpp:249-262` — in-memory `scan` ignores the start iterator and does `mEntries.find(searchKey)`, causing the query-side hash recomputation identified by the hypothesis.
- `src/bucket/DiskIndex.cpp:59-86` — disk scan uses range-index lower-bound comparisons plus binary-fuse filter membership, so the proposed in-memory-set prehash API does not directly remove the broader disk-index search work.
- `ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md:11-13` — the separate accepted cached-footprint-key optimization averaged 2.66% soroswap improvement, but it targeted parallel-apply maps rather than bucket-index lookup and was only Low severity.

### Why It Failed

This is not novel: the same bucket-walk `LedgerKey` hash caching idea is already present in the Soroban fail summary as `004-cache-ledgerkey-hash-bucket-walk.md`. Even treating the current write-up as a refreshed version rather than a strict duplicate, it does not clear the objective-specific Medium threshold. The mechanism is real for in-memory-index buckets, but the expected savings are dominated by cheap lookup-side hashing and the hypothesis itself estimates only ~1.3-2.2% direct apply-time reduction, with the Medium-range claim depending on unproven extra callers. Under the optimize-soroswap reviewer rules, Low and sub-1% findings must be rejected rather than downgraded and accepted.

### Lesson Learned

Bucket-list point-load hypotheses should first check the condensed Soroban fail summary for prior self-rejections, especially when they target the same `SearchableBucketListSnapshot::load` → `getBucketEntry` → `LiveBucketIndex::lookup` → `InMemoryBucketState::scan` chain. For this objective, a real micro-inefficiency still needs a reproducible 3-10% apply-time projection; query-side `LedgerKey` hash reuse across bucket levels has already been judged too small without stronger measurement.
