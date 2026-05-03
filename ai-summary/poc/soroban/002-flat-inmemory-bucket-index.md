# H002: Flat Cache-Local InMemory Bucket Index for Residual `scan` Cost

**Date**: 2026-05-03
**Subsystem**: soroban / bucket / ledger apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in BucketList point loads used by fee processing and parallel Soroban reads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Small live buckets that are fully resident in memory should answer `BucketListSnapshot::load` probes with the same newest-entry/tombstone semantics and the same deterministic ledger output as today, but the lookup should be cache-local. A point lookup should not chase an `std::unordered_set` node, then chase a `shared_ptr<BucketEntry const>`, and then compare through scattered bucket-entry storage for every bucket level probed.

## Mechanism

The accepted `001-inmemory-bucket-scan-polymorphic-wrapper` success removed the old per-query heap allocation and virtual-dispatch wrapper, but the current `InMemoryBucketState` still stores entries in `std::unordered_set<InternalInMemoryBucketEntry>` (`src/bucket/InMemoryIndex.h:79-98`) and performs `mEntries.find(searchKey)` for every `scan` (`src/bucket/InMemoryIndex.cpp:249-262`). Each stored element is a node allocation containing a cached hash plus a `shared_ptr` to the bucket entry, so high-volume soroswap loads still pay hash-table bucket indirection, node pointer chasing, poor locality, and `LedgerKey` equality on collision.

A flat index representation can preserve the current external API while replacing the node hash table with cache-local vectors built once at bucket-index construction. For example, store per-entry records `{cached_hash, entry_ptr}` grouped by `LedgerEntryType` and sorted by `(cached_hash, ledger-key-order tie-breaker)`, then implement `scan` as a lower-bound over the relevant type vector followed by exact `keyEquals` checks for matching hashes. This is not the rejected hash-only optimization: the proposed win is removing the residual unordered-set node walk and improving locality for every in-memory bucket probe, while still computing the query hash once and doing exact key comparison before returning an entry.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) with the diagnostic trace from `ai-summary/CURRENT_STATE.md`. Fee-source/account loads and BucketList-backed reads enter `SearchableBucketListSnapshot::load`, which walks live bucket levels and calls `getBucketEntry`; for small buckets below the default in-memory-index cutoff, `LiveBucketIndex::scan` reaches `InMemoryBucketState::scan` for each probed level.

## Target Code

- `src/bucket/InMemoryIndex.h:19-98` — `InternalInMemoryBucketEntry` and `InMemoryBucketState`; replace the unordered node set with a flat per-type index while retaining exact entry pointers and `keyEquals` checks.
- `src/bucket/InMemoryIndex.cpp:241-262` — `InMemoryBucketState::insert` and `scan`; build/search the flat representation instead of `mEntries.find(searchKey)`.
- `src/bucket/InMemoryIndex.cpp:291-303` and `305-340` — in-memory index constructors already see bucket entries in bucket order and can populate/sort the flat vectors once.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` consumes `IndexReturnT` from `scan`; the proposed representation must return identical cache-hit/not-found states.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point-load bucket walk that makes residual `scan` cost visible during `applyLedger`.

## Evidence

The current soroswap diagnostic trace reports `scan` at `bucket/InMemoryIndex.cpp:253` with **1,951,942,732 ns self-time across 926,932 calls**, and `load` / `getBucketEntry` remain visible descendants of the apply path (`BucketListSnapshot.cpp:317` and `:174`). This is after the prior polymorphic-wrapper success; the old query allocation no longer exists in source, so the remaining self-time is attributable to the current hash-table representation, hashing/equality, and memory locality rather than the already-fixed wrapper.

Source inspection confirms that the residual hot lookup is a single `std::unordered_set::find` over node-allocated `InternalInMemoryBucketEntry` objects (`InMemoryIndex.h:81-87`, `InMemoryIndex.cpp:253-258`). `scan` ignores its `start` iterator for in-memory indexes, so the caller-visible iterator contract is already degenerate; a flat vector implementation can keep returning `begin()` and preserve the existing `LiveBucketIndex::scan` interface. This is distinct from rejected `004-cache-ledgerkey-hash-bucket-walk.md` and `001-bucketlist-load-precomputed-hash.md`, which only tried to reduce hash recomputation, and from `023-bucketlistsnapshot-perkey-cache.md`, which added a cache layer above an already-hot lookup rather than replacing the lookup representation.

## Anti-Evidence

The current `scan` self-time is spread across apply-thread work and parallel Soroban worker threads, so aggregate CPU time will not translate one-for-one into wall-clock apply-time savings. A sorted-vector lower-bound can also lose to hashing for large in-memory buckets unless grouping and cache locality dominate; the PoC should compare against representative bucket sizes and may need a hybrid threshold that keeps the unordered representation for very large in-memory indexes. If most residual cost is exact `LedgerKey` hashing/equality rather than hash-table locality, the prior hash-only failure suggests the impact may fall below Medium.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The residual lookup path exists as described: `SearchableBucketListSnapshot::load` walks buckets newest-to-oldest, `getBucketEntry` calls `LiveBucketIndex::lookup`, and in-memory-index buckets route to `InMemoryBucketState::scan`, whose hot body is still `mEntries.find(searchKey)`. The stored representation is a node-based `std::unordered_set` of `InternalInMemoryBucketEntry` values containing a cached hash and `shared_ptr<BucketEntry const>`, so every in-memory bucket probe pays hash-table bucket indirection and node pointer chasing after the prior wrapper-removal optimization. One correction to the hypothesis is that current Soroban `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` reads usually bypass BucketList through `InMemorySorobanState`; the relevant bucket-scan hot path is therefore mostly classic fee/source/account/trustline and non-Soroban fallback reads during `closeLedger`, plus any live-snapshot reads for non-in-memory types. That correction narrows the target but does not eliminate the hot path: the current diagnostic still reports roughly 927k `scan` calls and 1.95s aggregate self-time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` runs per transaction during ledger close and can trigger classic account/source loads through the root ledger transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban stages run in parallel workers; their non-Soroban fallback reads can still reach the live snapshot, but Soroban storage keys are normally diverted before BucketList.
- `src/ledger/LedgerTxn.cpp:3669-3724` — `LedgerTxnRoot::Impl::getNewestVersion` checks `InMemorySorobanState::isInMemoryType` first, then loads non-offer, non-Soroban entries through `LedgerStateSnapshot::loadLiveEntry`.
- `src/ledger/LedgerStateSnapshot.cpp:438-449` — live entry and live-key loads delegate directly to `SearchableLiveBucketListSnapshot`.
- `src/transactions/ParallelApplyUtils.h:74-81` and `src/transactions/ParallelApplyUtils.cpp:1084-1120` — thread parallel apply reads Soroban entries from `InMemorySorobanState` and only falls back to `mLCLSnapshot.loadLiveEntry` for non-in-memory key types.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — read-only Soroban footprint preload likewise uses `InMemorySorobanState` for Soroban keys, confirming BucketList scan is not the dominant contract-data read path.
- `src/ledger/InMemorySorobanState.cpp:146-151` and `206-238` — `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys are classified as in-memory and served from the Soroban state cache.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` consumes the index result and returns cache hits directly, so a new in-memory representation can preserve the existing `IndexReturnT` contract.
- `src/bucket/BucketListSnapshot.cpp:210-277` — bulk loads call `index.scan(indexIter, *currKeyIt)`; because in-memory `scan` already ignores `start`, a degenerate iterator remains compatible.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point loads perform the bucket walk that fans out into repeated per-bucket index lookups.
- `src/bucket/LiveBucketIndex.cpp:28-60` and `src/main/Config.cpp:186-188` — buckets below the default 20 MB cutoff use `InMemoryIndex`.
- `src/bucket/LiveBucketIndex.cpp:223-257` — live point and bulk lookup route in-memory indexes to `InMemoryIndex::scan`.
- `src/bucket/InMemoryIndex.h:19-118` — current in-memory state is a `std::unordered_set` of node-allocated `InternalInMemoryBucketEntry` records and exposes iterator types only for interface compatibility.
- `src/bucket/InMemoryIndex.cpp:198-262` — stored-entry hashes are cached once, equality is exact and type-specific, and the hot lookup remains a single unordered-set `find`.
- `src/bucket/InMemoryIndex.cpp:264-343` — both constructors already observe all bucket entries once and can build grouped/sorted flat vectors during index construction.
- `ai-summary/fail/soroban/summary.md:20-24,52-56` and `ai-summary/success/soroban/001-inmemory-bucket-scan-polymorphic-wrapper.md:146-157` — related prior work covered wrapper allocation, query-hash reuse, bulk loading, and per-key cache layers, but not replacing the residual node-based in-memory index representation.

### Findings

The inefficiency exists and remains in a hot apply-path lookup. The current in-memory index no longer has the old per-query allocation or virtual dispatch, but it still uses a node hash table even though the index is immutable after construction and all entries are already resident. For a workload producing hundreds of thousands of in-memory bucket probes per trace, replacing nodes with type-grouped contiguous records is a plausible Medium optimization: even a 30-50% reduction of the 1.95s aggregate `scan` self-time would be in the range that can clear the 3% soroswap threshold if the saved work is concentrated in sequential fee/source-load portions of `closeLedger`; the PoC must confirm the wall-clock share because parallel-worker aggregate CPU does not map directly to apply time.

Existing optimizations do not cover this exact mechanism. The live bucket random-eviction cache is intentionally skipped for `mInMemoryIndex`, the ledger-entry cache only helps after a miss has already walked the bucket indexes, Soroban in-memory state removes contract-data/code/TTL reads from this path rather than optimizing this path, and prior rejected bucket hypotheses targeted query-hash reuse or an additional cache layer above `scan`. This proposal is therefore novel relative to the checked fail/success records.

The proposed fix is correctness-preserving if implemented carefully. It must preserve `getBucketLedgerKey` identity semantics for INIT/LIVE/DEAD entries, return tombstones as cache hits so newer deletes still shadow older live entries, perform exact `keyEquals` checks for every matching hash to handle collisions, and keep duplicate-key detection during index construction. Because sorted-vector lower-bound trades hash-table node chasing for `O(log n)` hash comparisons, the PoC should measure representative bucket sizes and use a hybrid cutoff if the flat representation loses on larger in-memory buckets.

### PoC Guidance

- **Target code**: `src/bucket/InMemoryIndex.h` and `src/bucket/InMemoryIndex.cpp`, especially `InternalInMemoryBucketEntry`, `InMemoryBucketState::insert`, `InMemoryBucketState::scan`, and the two `InMemoryIndex` constructors; `src/bucket/LiveBucketIndex.cpp` and `src/bucket/BucketListSnapshot.cpp` should not need semantic changes if the existing API is preserved.
- **Change description**: replace `InMemoryBucketState::mEntries` with a flat immutable representation grouped by `LedgerEntryType`, sorted by cached `std::hash<LedgerKey>` with an exact key-order tie-breaker or duplicate check, and searched by lower-bound over the relevant type vector followed by exact `keyEquals` on all equal hashes. Preserve `IndexReturnT(IndexPtrT)` on hits and `IndexReturnT()` on misses, and keep the in-memory iterator contract degenerate because callers already cannot rely on ordered progress.
- **Correctness check**: existing bucket index coverage in `src/bucket/test/BucketIndexTests.cpp` should exercise in-memory index construction, lookup, cutoff behavior, equality, type ranges, and cache-hit semantics. Add focused tests only if the representation introduces new collision or hybrid-threshold branches that existing tests do not cover.
- **Benchmark focus**: run the soroswap apply-load matrix multiple times against the `ai-summary/CURRENT_STATE.md` baseline, and inspect Tracy for `bucket/InMemoryIndex.cpp:253` or the updated `scan` zone. The PoC should report both top-line median apply time and normalized `scan` self-time/call; promotion requires a reproducible 3-10% apply-time improvement, not just lower aggregate CPU in parallel worker threads.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:20-104` — replaced the node-based `std::unordered_set` storage with a contiguous vector of `InternalInMemoryBucketEntry` records plus per-`LedgerEntryType` index ranges; retained the degenerate iterator API used by callers.
- `src/bucket/InMemoryIndex.cpp:24-53` and `195-209` — added type-to-range indexing and a sort comparator that orders entries by type, cached hash, then exact bucket-entry identity ordering.
- `src/bucket/InMemoryIndex.cpp:246-335` — cached each entry's type with its hash, changed insertion to append to the flat vector, finalized the immutable index by sorting and duplicate-checking, and implemented `scan` as a lower-bound over the matching type range followed by exact `keyEquals` checks for hash collisions.
- `src/bucket/InMemoryIndex.cpp:338-422` — finalized the flat index in both in-memory constructors after all bucket entries are observed, with reservation for vector-backed construction from an existing entry vector.

### Demonstration

The optimization removes the per-lookup `std::unordered_set` bucket and node walk from in-memory bucket probes while preserving the existing `IndexReturnT` cache-hit/not-found contract. Bucket entries remain owned by shared pointers and every candidate returned by the hash lower-bound is still verified with exact key identity, so tombstones, INIT/LIVE entries, and hash collisions retain the same lookup semantics.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran the focused bucket-index tests plus the full suite. Focused `[bucket][bucketindex]` passed 366489 assertions in 12 test cases; `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
