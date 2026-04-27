# H002: Avoid LedgerTxnRoot Cache-Hit Relookup and Per-Hit Entry Allocation

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing repeated root-cache overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `LedgerTxnRoot` serves a hot prefetched ledger entry during apply, it should perform one cache lookup and return an immutable entry representation with minimal per-call allocation. Repeated source-account and classic-entry reads during fee processing, validation, and apply should reuse the cached payload rather than rehashing the same key and copying the entry on every cache hit.

## Mechanism

`LedgerTxnRoot::Impl::getNewestVersion` checks `mEntryCache.exists(key)` and then calls `getFromEntryCache(key)`, whose `mEntryCache.get(key)` path performs a second unordered-map lookup through `RandomEvictionCache::maybeGet`. On every non-null cache hit, `getFromEntryCache` also allocates a fresh `shared_ptr<InternalLedgerEntry const>` and copies the cached `LedgerEntry`. Replacing the `exists` + `get` pair with a single `maybeGet`-style lookup, and either caching an `InternalLedgerEntry` payload or otherwise avoiding the per-hit `InternalLedgerEntry` allocation/copy, should reduce hot root-cache time while preserving the same immutable returned value.

## Trigger

Run the current soroswap apply-load benchmark. In the baseline Tracy trace `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`, `getNewestVersion` at `ledger/LedgerTxn.cpp:3672` has 376,748 total calls and 238.525 ms total time; 334,704 calls and 199.258 ms occur inside `applyLedger` windows. This is enough aggregate apply time for a Medium hypothesis if the duplicate lookup and allocation/copy account for most of the zone.

## Target Code

- `src/ledger/LedgerTxn.cpp:3669-3724` — `LedgerTxnRoot::Impl::getNewestVersion` performs cache existence check, miss handling, persistent load, and cache insertion.
- `src/ledger/LedgerTxn.cpp:3778-3803` — `getFromEntryCache` performs the second cache lookup and allocates/copies an `InternalLedgerEntry` on hit.
- `src/util/RandomEvictionCache.h:158-174` and `src/util/RandomEvictionCache.h:206-224` — existing comments explicitly note that `maybeGet` saves a second hash lookup compared with `exists` followed by `get`.

## Evidence

The hot zone is inside the measured apply path rather than transaction-set construction: event-overlap analysis found 199.258 ms of `getNewestVersion` events within `applyLedger` intervals. The source has a direct structural inefficiency in the cache-hit path: `exists()` hashes and probes `mValueMap`, then `get()` calls `maybeGet()` and hashes/probes again. The cached value already contains a `shared_ptr<LedgerEntry const>`, so the current code pays an additional allocation and full `InternalLedgerEntry` copy for every hit even though callers receive an immutable result.

## Anti-Evidence

The upper bound is the whole 199.258 ms aggregate inside apply, roughly 4.3% of the trace's `applyLedger` total, so this must remove a large fraction of the zone to remain above the objective's Medium threshold. `RandomEvictionCache` hit/miss counters and `mPrefetchHits` accounting must remain semantically equivalent, and returning cached `InternalLedgerEntry` objects must not expose mutable state or stale lifetime assumptions across cache eviction.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The claimed cache-hit inefficiency exists: `LedgerTxnRoot::Impl::getNewestVersion` probes `mEntryCache` with `exists()` and then `getFromEntryCache()` calls `mEntryCache.get()`, which re-enters `maybeGet()` and performs a second hash-table lookup. On non-null hits, `getFromEntryCache()` also allocates a new `InternalLedgerEntry const` and copies the cached `LedgerEntry`. However, the traced close-ledger paths show this is a bounded micro-optimization: prefetched entries are copied into `LedgerTxn` state on first mutable `load()`, later reads at that transaction level hit `mEntry`, and protocol-23+ parallel Soroban host execution uses `ParallelLedgerAccessHelper`/thread state rather than repeatedly calling `LedgerTxnRoot`.

### Code Paths Examined

- `src/ledger/LedgerTxn.cpp:3669-3728` — `LedgerTxnRoot::Impl::getNewestVersion` handles root cache hit/miss, persistent load, cache insert, and returns a freshly allocated `InternalLedgerEntry` on miss.
- `src/ledger/LedgerTxn.cpp:3778-3803` — `getFromEntryCache` uses `mEntryCache.get(key)` after the caller already ran `exists(key)`, then allocates/copies `InternalLedgerEntry` for non-null hits.
- `src/util/RandomEvictionCache.h:158-174,206-237` — `exists()` only checks `mValueMap.find`, while `get()` calls `maybeGet()` and repeats the lookup; comments explicitly recommend `maybeGet()` to avoid the second lookup.
- `src/ledger/LedgerTxn.cpp:1938-1964` — mutable `LedgerTxn::Impl::load` copies a loaded root entry into the child transaction map, so subsequent reads are not root-cache hits and a separate mutable copy remains necessary.
- `src/ledger/LedgerTxn.cpp:2216-2235` and `src/ledger/LedgerTxnEntry.cpp:256-282` — `loadWithoutRecord` still copies the returned `InternalLedgerEntry` into `ConstLedgerTxnEntry::Impl`, limiting the benefit of removing only the root-side copy.
- `src/ledger/LedgerManagerImpl.cpp:1655-1688,2303-2400,2443-2480,2784-2824` — close-ledger prefetch, fee/sequence processing, and transaction apply call into the root cache, but metadata is disabled in the benchmark config and fee processing operates on the parent `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:151-207,431-467,925-1001` and `src/transactions/ParallelApplyUtils.cpp:328-342` — p26 pre-parallel checks use snapshots for classic-key comparison, while parallel Soroban execution reads from thread/global state via `ParallelLedgerAccessHelper`, not from `LedgerTxnRoot`.
- `docs/apply-load-benchmark-sac.cfg:13-24` — the apply-load benchmark configuration disables Soroban metrics and transaction metadata, removing some paths where root-returned entries would otherwise feed metadata copies.

### Why It Failed

This falls below the optimize-soroswap objective's Medium severity threshold. The entire `getNewestVersion` overlap cited by the hypothesis is only about 4.3% of `applyLedger`, so a Medium result would require eliminating most of that zone. The proposed change can remove the duplicate cache lookup and one root-side allocation/copy on cache hits, but it cannot remove required LedgerTxn/ConstLedgerTxnEntry copies, miss handling, counters, tracing, caller-side work, or the non-root parallel Soroban access path. The realistic saving is therefore a fraction of 199.258 ms and is projected below the required 3% apply-time reduction.

### Lesson Learned

Root cache-hit cleanup is a reasonable code-quality micro-optimization, but in the soroswap apply path it should not be promoted without direct evidence that it removes at least 3% of total apply time. For this objective, hypotheses whose own upper bound barely clears Medium must identify a mechanism that removes nearly the whole measured zone, not just a subset of per-call overhead.
