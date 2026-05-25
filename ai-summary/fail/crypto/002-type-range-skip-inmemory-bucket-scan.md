# H002: Skip In-Memory Bucket Scans for Entry Types Absent from a Bucket

**Date**: 2026-05-25
**Subsystem**: crypto / bucket
**Severity**: Medium
**Impact**: reduce apply-path `LedgerKey` hash/equality probes by avoiding impossible live-bucket point lookups
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Looking up a `LedgerKey` in a live bucket should return `NOT_FOUND` immediately when the bucket index already knows that the bucket contains no entries of that key's `LedgerEntryType`. This should preserve exact lookup results, bloom-miss behavior, cache-hit behavior, bucket shadowing order, and deterministic ledger output, because a bucket with no range/counter for a type cannot contain a key of that type.

## Mechanism

`LiveBucketIndex::lookup` delegates every in-memory point lookup to `InMemoryIndex::scan`, which in turn calls `mEntries.find(searchKey)` and pays `std::hash<LedgerKey>` plus heterogeneous equality even when `mTypeRanges`/`BucketEntryCounters` show the bucket has no entries of `searchKey.type()`. Soroswap footprint loading repeatedly queries `CONTRACT_DATA`, `TTL`, and occasional `CONTRACT_CODE` keys across every bucket level until a match is found or all buckets are exhausted. Adding a cheap type-presence guard before the in-memory `scan` would bypass entire impossible hash-table probes rather than trying to make each probe's crypto hash cheaper.

## Trigger

Run the current soroswap apply-load Tracy trace and timestamp-filter `InMemoryBucketState::scan` against `applyLedger` windows. The current diagnostic trace shows apply-overlapping `scan` at `bucket/InMemoryIndex.cpp:253` with 2.345813854 s self-time over 958,911 calls and `getBucketEntry` at `bucket/BucketListSnapshot.cpp:174` with 2.450755839 s total over 808,910 calls. A PoC should add counters for `lookup` calls skipped because `getRangeForType(k.type())`/counters are absent, split by `CONTRACT_DATA`, `TTL`, and `CONTRACT_CODE`, then verify the skipped share is large enough after `NUM_CLUSTERS` normalization.

## Target Code

- `src/bucket/LiveBucketIndex.cpp:223-239` - `LiveBucketIndex::lookup` always calls `mInMemoryIndex->scan(...)` for in-memory indexes.
- `src/bucket/LiveBucketIndex.cpp:285-295` - `getRangeForType` already exposes per-type presence/ranges for both disk and in-memory indexes.
- `src/bucket/InMemoryIndex.h:120-169` - `InMemoryIndex` stores `mTypeRanges` and exposes `getRangeForType`, but `scan` does not use it.
- `src/bucket/InMemoryIndex.cpp:241-262` - `InMemoryBucketState::scan` performs the hot `unordered_set` lookup.
- `src/ledger/LedgerHashUtils.h:162-182` - `std::hash<LedgerKey>` performs type-specific hashing, including `shortHash::xdrComputeHash` over variable `CONTRACT_DATA` keys.

## Evidence

This targets a different failure mode than the rejected SipHash and hash-cache variants: it skips whole impossible lookups rather than replacing or caching the hash inside a lookup that must occur. The necessary metadata is already maintained when building `InMemoryIndex`: `processEntry` updates type start/end offsets, `mTypeRanges` is finalized in both constructors, and `getRangeForType` returns `std::nullopt` for absent types. The hot trace row is apply-relevant through the same `applyLedger` descendant chain as footprint loading (`parallelApply` -> `InvokeHostFunctionOpFrame::addReads` -> `ThreadParallelApplyLedgerState::getLiveEntryOpt` -> `LedgerStateSnapshot::loadLiveEntry` -> `BucketListSnapshot::load` -> `LiveBucketIndex::lookup`).

## Anti-Evidence

If almost every live bucket in the soroswap run contains all hot entry types (`CONTRACT_DATA`, `TTL`, and `CONTRACT_CODE`), the guard will rarely fire and the effect will fall below Medium. The optimization also must be placed carefully: disk indexes already have bloom/range behavior, and cache-hit checks for disk-backed live buckets must remain unchanged. The PoC needs skip-rate counters before code review can distinguish a dominant structural skip from another sub-threshold `LedgerKey` hashing micro-optimization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: an in-memory live-bucket point lookup calls `LiveBucketIndex::lookup`, then `InMemoryIndex::scan`, then `InMemoryBucketState::scan`, which hashes the searched `LedgerKey` and probes `mEntries` even if `mTypeRanges` has no range for that key type. However, the claimed Soroswap hot key path is wrong for p23+ parallel apply: `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` reads are routed to `InMemorySorobanState::get`, not `BucketListSnapshot::loadLiveEntry`. The remaining bucket-list point-load surface is non-in-memory/classic lookup work, and the entire cited in-memory scan row is below the optimize-soroswap Medium floor after the required 200-ledger and 8-cluster normalization; a type-absent guard can only remove a subset of that row.

### Code Paths Examined

- `src/bucket/LiveBucketIndex.cpp:223-239` - disk indexes keep the cache and disk scan path; in-memory indexes unconditionally call `mInMemoryIndex->scan(mInMemoryIndex->begin(), k)`.
- `src/bucket/InMemoryIndex.cpp:249-262` - `InMemoryBucketState::scan` performs `mEntries.find(searchKey)`, which invokes the heterogeneous `LedgerKey` hash and equality path.
- `src/bucket/InMemoryIndex.cpp:163-195` and `src/bucket/InMemoryIndex.cpp:264-356` - both in-memory constructors populate `mTypeRanges` via `processEntry` and `buildTypeRangesMap`; `getRangeForType` returns `std::nullopt` for absent types.
- `src/bucket/BucketListSnapshot.cpp:166-201` and `src/bucket/BucketListSnapshot.cpp:313-345` - point `load` iterates buckets newest-to-oldest and calls `index.lookup(k)` until a bucket returns an entry.
- `src/ledger/LedgerHashUtils.h:136-203` - `std::hash<LedgerKey>` is non-trivial, especially for `CONTRACT_DATA`, which hashes the SCVal key with `shortHash::xdrComputeHash`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` - thread-level p23+ Soroban reads check `InMemorySorobanState::isInMemoryType` and send `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys to `mInMemorySorobanState.get(key)`.
- `src/ledger/InMemorySorobanState.cpp:146-150`, `src/ledger/InMemorySorobanState.cpp:206-238`, and `src/ledger/InMemorySorobanState.cpp:412-446` - the in-memory Soroban state handles those three key types directly; TTL entries are synthesized from embedded TTL data.
- `src/ledger/InMemorySorobanState.cpp:448-535` and `src/bucket/BucketListSnapshot.cpp:653-690` - initial Soroban-state population uses type scans, and those already call `getRangeForType(type)` before scanning a bucket.
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.log` - the diagnostic run contains 200 measured soroswap ledgers at 8 clusters with p50 close time about 209.9 ms.

### Why It Failed

The proposed guard would be correct for in-memory live-bucket point lookups, but it does not address the hypothesis's claimed `CONTRACT_DATA`/`TTL`/`CONTRACT_CODE` footprint path because those lookups bypass BucketListDB during parallel apply. It also cannot meet the objective severity threshold on the remaining point-load surface: even treating the whole cited 2.345813854 s `InMemoryBucketState::scan` self-time as removable gives about `2.3458s / 200 / 8 = 1.47 ms` per ledger, roughly 0.7% of the 207-210 ms soroswap baseline and well below the 3% Medium floor. Since the type-presence check can only skip absent-type misses, not every in-memory scan, the realistic impact is smaller still.

### Lesson Learned

Do not attribute live-bucket point-lookup trace totals to Soroban `CONTRACT_DATA`, `CONTRACT_CODE`, or `TTL` footprint reads without checking the `InMemorySorobanState::isInMemoryType` branch. Type ranges are already used for bulk type scans, so future bucket-index hypotheses need direct skip-rate counters on the remaining non-Soroban point-load callers and must show Medium-scale wall-clock savings after cluster normalization.
