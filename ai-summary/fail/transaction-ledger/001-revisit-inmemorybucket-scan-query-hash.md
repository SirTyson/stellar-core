# H001: Re-evaluate Apply-Window Cost of `InMemoryBucketState::scan` After Warm-up-Inflation Fail and Cached-Hash Success

**Date**: 2026-05-23
**Subsystem**: bucket / transaction-ledger
**Severity**: Medium (projected; needs in-apply call-count split)
**Impact**: classic-entry read path for fee accounts, trustlines, and any
classic footprint loads during soroswap apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each call to `InMemoryBucketState::scan(start, searchKey)`
(`src/bucket/InMemoryIndex.cpp:251-262`) is an `unordered_set::find` on a
single `LedgerKey`. With the now-cached `mHash` on the stored
`InternalInMemoryBucketEntry`, the only remaining per-call cost is
(a) hashing the *query-side* `LedgerKey` (recomputed on every call) and
(b) the per-probe `bucketEntryKeyEqual` comparison. For account/trustline
keys this should be a few hundred nanoseconds total, not microseconds.
When the same logical query key is looked up many times across the same
ledger (e.g. fee-source account, common trustline counterparties on
soroswap) the query-side hash should not be paid more than once.

## Mechanism

The Tracy soroswap trace at
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/...soroswap-tx-2000-t-8.tracy`
shows `scan` (`bucket/InMemoryIndex.cpp:253`) at **2.245 s self-time across
956 502 calls** — **21.8% of total trace self-time** — at a mean of
**2.35 µs/call**. With the `InMemoryIndex` H001 success already merged (the
stored side caches `mHash`), the residual per-call cost is dominated by
(i) the query-side `std::hash<LedgerKey>` computation per call (no caller
cache) and (ii) the heterogeneous-lookup machinery (transparent functors,
`unordered_set::find` probe + equality call).

For soroswap's apply window: hundreds of classic loads per tx × hundreds
of txs per ledger generate the bulk of these calls. If even half of the
956 502 calls (≈ 478 k) fall inside `applyLedger` (the rest being module
cache rebuild, finalize, or BucketList housekeeping outside the measured
window), that is ≈ 6 700 in-apply calls per ledger × ~2 µs ≈ **13 ms /
ledger ≈ 6 % of close time** — a clear Medium opportunity. Even a
quarter of the calls being in-apply still clears the 3 % Medium floor.

Two structural improvements compound:

1. **Heterogeneous-lookup with caller-supplied pre-hashed `LedgerKey`**:
   the BucketListSnapshot read paths (`getBucketEntry`,
   `loadKeysFromBucket`) call `scan` repeatedly across the bucket levels
   with the same query key; they should hash the key **once** and pass a
   `{LedgerKey&, size_t precomputedHash}` pair through the index API so
   each per-level `find` does an O(1) probe with a single equality check
   rather than re-hashing for each of the ~22 levels probed per logical
   lookup.

2. **Eliminate Tracy `ZoneScoped` per scan call**: the `scan` function is
   trivial (one `unordered_set::find`); the `ZoneScoped` macro
   (`InMemoryIndex.cpp:253`) adds ~100-200 ns per call. At 956 k calls
   that is ~100-200 ms across the trace. Replace with a coarser zone at
   the caller (`getBucketEntry` / `loadKeysFromBucket`) which already
   exists. This only helps Tracy traces, not non-Tracy benchmark runs,
   so it is bundled only for trace-fidelity, not for the apply-time win.

The prior rejection
(`001-eliminate-polymorphic-inmemorybucketstate-scan-overhead.md`) was
"warm-up inflation in `benchmarkModelTxTpsSingleLedger`"; the
**apply-load** trace path (`scripts/run_apply_load_matrix.py`) does not
share that warm-up call structure, and the cached-hash success
(`success/soroban/001-inmemory-bucket-scan-polymorphic-wrapper.md`) only
addressed the stored-side hash recomputation — the query-side per-call
hash work and cross-level redundancy are still present.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap scenario at the
benchmark settings (`tx=2000, t=8`). Per-ledger BucketList classic reads
during apply (fee-source accounts, ops sources, soroswap-leg trustlines)
generate thousands of `InMemoryBucketState::scan` calls per ledger across
all in-memory bucket levels.

## Target Code

- `src/bucket/InMemoryIndex.cpp:251-262` — `InMemoryBucketState::scan`,
  the hot zone.
- `src/bucket/InMemoryIndex.h:47-74` —
  `InternalInMemoryBucketEntryHash` / `InternalInMemoryBucketEntryEqual`
  transparent functors; extend to accept a pre-hashed key wrapper.
- `src/bucket/LiveBucketIndex.cpp:223-257` — `LiveBucketIndex::lookup`
  and `LiveBucketIndex::scan` are the natural place to compute the
  query-side `std::hash<LedgerKey>` once and forward it down through the
  bucket levels.
- `src/bucket/BucketListSnapshot.cpp:166-200, 208-300` —
  `getBucketEntry` and `loadKeysFromBucket` iterate the bucket levels;
  hoist the query hash computation outside the per-level loop.
- `src/ledger/LedgerHashUtils.h:136-203` — `std::hash<LedgerKey>` whose
  per-call cost we want to amortize across bucket levels.

## Evidence

- Tracy csvexport on the current soroswap trace
  (`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`):
  `scan` self = 2 245 315 546 ns over 956 502 calls = **2.35 µs mean**;
  total share **21.8 %** of trace self-time.
- The cached-hash success (`success/soroban/001-...`) confirms the
  *stored-side* hash is already cached, leaving only the *query-side*
  per-call work and per-probe equality as remaining cost — a smaller but
  still material slice.
- `getBucketEntry` and `LiveBucketIndex::lookup` walk multiple bucket
  levels for the same query key, paying the hash on every level even
  though the key is identical.
- The previous rejection was specifically about the wrong measurement
  (warm-up inflation in a *different* benchmark binary); the apply-load
  trace path used here is the objective's authoritative measurement
  surface.

## Anti-Evidence

- **Call-site mix unverified**: the 956 502 figure is total trace
  self-time, not split by whether each event is inside the measured
  `applyLedger` window vs. outside (e.g. bucket finalize, module-cache
  rebuild). Tracy unwrap mode is required to split this before promoting
  the hypothesis past reviewer. If <25 % of events are in-apply, the
  saving falls below Medium.
- The Tracy `ZoneScoped` overhead itself accounts for a large fraction of
  the per-call cost. Removing the macro is a Tracy-only win — non-Tracy
  benchmark runs (the authoritative measurement per meta-pattern 17)
  would not see it. The hash-hoisting change is the load-bearing part.
- Heterogeneous-lookup API extension touches a stable BucketList
  internal interface; reviewer may push back on surface-area expansion
  unless paired with a measured win.
- Meta-pattern 1 ("Benchmark Warm-up Inflation") cautions that the prior
  rejection of this area was due to wrong-binary measurement; this
  hypothesis specifically *re-targets* the right binary
  (`run_apply_load_matrix.py`), but the orchestrator should confirm the
  apply-window split before PoC.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to the prior warm-up-inflation `InMemoryBucketState::scan` rejection, but this narrower query-side cached-hash / prehash mechanism was not found as an exact prior verdict in transaction-ledger fail or success records
**Failed At**: reviewer

### Trace Summary

The remaining query-side hashing inefficiency is real: `InMemoryBucketState::scan` still calls heterogeneous `unordered_set::find(searchKey)`, which invokes `std::hash<LedgerKey>` for the query while stored entries already carry cached `mHash`. The reachable close-ledger path is through source/data prefetch and cache-miss classic entry loads: `applyLedger` prefetches classic source/apply keys, `LedgerTxnRoot::prefetch` bulk-loads them from the apply snapshot, and later `LedgerTxnRoot::getNewestVersion` only calls `loadLiveEntry` on entry-cache misses. Soroban `CONTRACT_DATA`/`CONTRACT_CODE`/`TTL` keys bypass this BucketList path through `InMemorySorobanState`, offers use SQL when BucketListDB is active, and repeated classic reads are damped by `mEntryCache` plus global/thread parallel-apply maps. Prior transaction-ledger sizing records place the whole synchronous BucketList snapshot lookup/prefetch envelope below Medium, so the query-side hash subset cannot clear the objective threshold.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:10` — prior scan-related failure was specifically warm-up inflation in `benchmarkModelTxTpsSingleLedger`, not an exact duplicate of this query-side hash-hoisting mechanism.
- `ai-summary/fail/transaction-ledger/summary.md:78,82,136` — existing transaction-ledger failures size the relevant BucketList snapshot/prefetch envelope as sub-Medium: total prefetch around 1.25 ms/ledger, `BucketListSnapshot::load` inside apply around 1.5 ms/ledger before any worker normalization, and bucket point loads below Medium.
- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches fee-source keys, processes fees/sequence numbers, then enters transaction apply.
- `src/ledger/LedgerManagerImpl.cpp:2443-2480` — source-account and transaction-data prefetch collect declared classic keys and call `AbstractLedgerTxnParent::prefetch`.
- `src/ledger/LedgerTxn.cpp:3100-3155` — `LedgerTxnRoot::Impl::prefetch` rejects Soroban/TTL keys, filters entries already in `mEntryCache`, then bulk-loads remaining keys with `ApplyLedgerStateSnapshot::loadLiveKeys`.
- `src/ledger/LedgerTxn.cpp:3670-3728` — `LedgerTxnRoot::Impl::getNewestVersion` first checks `mEntryCache`; Soroban in-memory types use `InMemorySorobanState::get`, offers use SQL when applicable, and only remaining cache misses call `getLedgerStateSnapshot().loadLiveEntry`.
- `src/ledger/LedgerStateSnapshot.cpp:438-449` — apply snapshots delegate `loadLiveEntry` / `loadLiveKeys` to `SearchableLiveBucketListSnapshot`.
- `src/bucket/BucketListSnapshot.cpp:170-201,313-345` — point loads loop over buckets newest-to-oldest and call `getBucketEntry`, which calls `LiveBucketIndex::lookup`.
- `src/bucket/BucketListSnapshot.cpp:209-277,445-453` — bulk loads loop over buckets and keys, calling `LiveBucketIndex::scan` for each searched key in each bucket.
- `src/bucket/LiveBucketIndex.cpp:223-257` — live index lookup/scan dispatches to disk or in-memory index; the in-memory branch calls `InMemoryIndex::scan`.
- `src/bucket/InMemoryIndex.h:47-74` and `src/bucket/InMemoryIndex.cpp:198-204,249-262` — stored entries cache `mHash`, but `scan` still hashes the query `LedgerKey` in `mEntries.find(searchKey)` and has a per-call `ZoneScoped`.
- `src/ledger/LedgerHashUtils.h:136-203` — `std::hash<LedgerKey>` is type-sensitive and may hash nested key fields such as trustline assets or contract-data keys.
- `src/transactions/ParallelApplyUtils.cpp:386-428,600-718` — parallel Soroban setup copies modified classic entries and preloads Soroban read-only entries into the global map; worker execution generally reads from global/thread/tx maps rather than repeatedly walking BucketList levels for Soroban keys.

### Why It Failed

The optimization target is a real micro-inefficiency, but it is a subset of an already-small synchronous apply envelope. The cited 956,502 `scan` calls are total trace events and are not split to the measured `applyLedger` critical path; prior transaction-ledger records already size the relevant in-apply `BucketListSnapshot::load` and prefetch work at roughly a few milliseconds per ledger combined. Even eliminating the entire BucketList snapshot lookup/prefetch envelope would not reliably clear the objective's 3% Medium floor, and this hypothesis can only remove the query-side hash portion plus a Tracy-only `ZoneScoped` cost. In non-Tracy authoritative benchmarks, the `ZoneScoped` removal contributes nothing, leaving a sub-threshold hash-hoisting change with non-trivial BucketList index API churn.

### Lesson Learned

After stored-side in-memory bucket hashes are cached, further `InMemoryBucketState::scan` work must be sized against the timestamp-filtered apply-window BucketList lookup envelope, not total trace self-time. Soroswap's Soroban state is mostly served from `InMemorySorobanState` and parallel-apply maps, while classic BucketList reads are prefetched and cached; query-side hash amortization across bucket levels is too narrow to justify a Medium-severity optimization without a new measurement showing the complete in-apply BucketList lookup path itself exceeds the 3% floor.
