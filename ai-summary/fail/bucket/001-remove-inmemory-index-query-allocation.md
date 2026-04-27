# H001: Remove Per-Lookup Heap Allocation From In-Memory Bucket Index Queries

**Date**: 2026-04-27
**Subsystem**: bucket
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing BucketListDB lookup overhead in the apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During soroswap ledger apply, repeated live-bucket snapshot lookups should query small in-memory bucket indexes with a single deterministic hash/equality probe and no heap allocation. A lookup that misses or hits an in-memory bucket should return the same `IndexReturnT` as today, preserve BucketList shadowing order, and not change ledger-entry contents, bucket hashes, or observable transaction results.

## Mechanism

`InMemoryBucketState::scan` constructs a temporary `InternalInMemoryBucketEntry(searchKey)` for every query, and that wrapper allocates a `QueryKey` via `std::make_unique` behind a virtual `AbstractEntry` interface. Equality also calls virtual `copyKey()` on both sides, so hot apply-path lookups pay allocation, virtual dispatch, and key-copy overhead before the actual `unordered_set` probe. Replacing this with C++20 heterogeneous lookup or an equivalent allocation-free key probe should remove a large fraction of the `scan` self-time while preserving deterministic lookup semantics.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) on the current baseline trace. The hot path is triggered by Soroban footprint/account lookups during `applyLedger`, especially when thread-local apply state falls through to `ApplyLedgerStateSnapshot::loadLiveEntry` and then to `SearchableBucketListSnapshot::load` / `getBucketEntry`.

## Target Code

- `src/bucket/InMemoryIndex.h:26-133` — `InternalInMemoryBucketEntry` stores either a value or query key through a heap-allocated virtual object.
- `src/bucket/InMemoryIndex.cpp:55-76` — `InMemoryBucketState::scan` constructs the temporary query wrapper on every lookup and ignores the `start` iterator.
- `src/bucket/InMemoryIndex.cpp:78-117` — vector-backed in-memory index construction inserts entries into the same allocation-heavy wrapper set.
- `src/bucket/InMemoryIndex.cpp:119-160` — file-backed in-memory index construction uses the same representation for buckets rebuilt from disk.
- `src/bucket/BucketListSnapshot.cpp:170-200` — `getBucketEntry` calls `index.lookup(k)` for every bucket examined during a point lookup.
- `src/ledger/LedgerStateSnapshot.cpp:438-442` and `src/transactions/ParallelApplyUtils.cpp:1084-1120` — apply-time fallback path that reaches live bucket snapshot point lookups.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` shows `scan,bucket/InMemoryIndex.cpp,67` as a major bucket hotspot. Full-trace self-time is `3,139,848,749 ns` over `1,445,421` calls, but the TX-set-construction trap was checked with `csvexport -u`: `502,934` of those calls, totaling `129,669,050 ns`, occur fully inside `applyLedger` wall-clock windows. The same apply-window check shows in-memory index construction also inside apply: `InMemoryIndex,bucket/InMemoryIndex.cpp,82` totals `65,153,938 ns` and `InMemoryIndex,bucket/InMemoryIndex.cpp,123` totals `58,707,962 ns`. Together these zones are roughly `253 ms` of apply-window bucket-index work in a trace whose `applyLedger` total is `4,591,086,908 ns`, so an allocation-free representation that removes most query-wrapper overhead has a plausible Medium-tier impact.

The code structurally supports the profile: `InternalInMemoryBucketEntry(LedgerKey const&)` allocates `QueryKey` for every lookup, and `operator==` compares through virtual `copyKey()` calls. This is pure index machinery, not consensus data transformation, so the optimization can be made determinism-preserving by returning the same entry pointer/NOT_FOUND result for the same key.

## Anti-Evidence

The full `scan` aggregate includes substantial work outside `applyLedger`; only the apply-window subset should be credited to this objective. Also, changing the in-memory index representation risks memory growth if implemented as a separate `LedgerKey -> BucketEntry` map, so the PoC should prefer heterogeneous lookup or another representation that avoids duplicating every key unless benchmark results justify the memory tradeoff.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.4, high
**Novelty**: PASS — no prior bucket or cross-subsystem fail/success records were present for this hypothesis
**Failed At**: reviewer

### Trace Summary

The traced apply path is real: `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls through to `LedgerStateSnapshot::loadLiveEntry`, which calls `SearchableBucketListSnapshot::load`, and that walks buckets until `getBucketEntry` asks `LiveBucketIndex::lookup` for each candidate bucket. For small live buckets, `LiveBucketIndex::lookup` dispatches to `InMemoryIndex::scan`, which does allocate a temporary `InternalInMemoryBucketEntry(searchKey)` and pays the virtual `AbstractEntry`/`copyKey()` indirection described in the hypothesis. But the apply-window evidence in the hypothesis itself only credits `scan` with `129,669,050 ns` out of `4,591,086,908 ns` total `applyLedger` time, an upper bound of about `2.83%`, and the proposed query-focused change cannot remove all of that self time. The rest of the cited ~253 ms comes from separate `InMemoryIndex` construction zones that run during bucket/index build paths, so the current Medium claim depends on costs outside the stated lookup mechanism.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — parallel apply misses the thread map and falls back to `mLCLSnapshot.loadLiveEntry(key)`.
- `src/ledger/LedgerStateSnapshot.cpp:438-442` — `loadLiveEntry` forwards directly to the live bucket snapshot.
- `src/bucket/BucketListSnapshot.cpp:171-200` — `getBucketEntry` calls `bucket->getIndex().lookup(k)` for each bucket examined.
- `src/bucket/BucketListSnapshot.cpp:315-345` — point lookup loops buckets newest-to-oldest until a hit is found.
- `src/bucket/LiveBucketIndex.cpp:29-39,223-239` — buckets smaller than `BUCKETLIST_DB_INDEX_CUTOFF` (default 20 MB) use `InMemoryIndex`, and lookup dispatches to `mInMemoryIndex->scan(...)`.
- `src/bucket/InMemoryIndex.h:19-25,26-133` — the stored/query wrapper uses `std::unique_ptr<AbstractEntry>` with virtual `copyKey()` / `hash()` / `get()`.
- `src/bucket/InMemoryIndex.cpp:65-76` — each lookup constructs a temporary query wrapper and probes `unordered_set::find`.
- `src/bucket/BucketListBase.cpp:225-237` and `src/bucket/LiveBucket.cpp:614-697` — level-0 close-ledger work also rebuilds an in-memory index once per merge, which is a distinct cost center from per-lookup probing.
- `src/main/Config.cpp:186-188` — default cutoff is 20 MB, limiting this path to the small-bucket subset.

### Why It Failed

The inefficiency exists, but the hypothesis does not clear this objective's Medium floor. The only apply-window time directly tied to the lookup path is the `scan` zone (`129,669,050 ns / 4,591,086,908 ns ≈ 2.83%`) and a lookup-only fix would recover only part of that upper bound, not all of it. Reaching the claimed Medium range requires also counting constructor-time index-build zones, but those are separate once-per-build costs and are not eliminated by the stated per-query heap-allocation fix. Under the optimize-soroswap reviewer rules, this is below objective severity threshold (Low not accepted).

### Lesson Learned

For bucket-index performance hypotheses, separate steady-state lookup cost from bucket/index construction cost before projecting severity. A follow-up hypothesis would need to target the full `InternalInMemoryBucketEntry` representation end-to-end, and then show that both lookup and build-side savings together produce at least a 3% apply-time reduction.
