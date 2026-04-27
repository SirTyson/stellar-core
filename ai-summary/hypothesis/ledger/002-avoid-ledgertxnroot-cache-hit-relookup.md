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
