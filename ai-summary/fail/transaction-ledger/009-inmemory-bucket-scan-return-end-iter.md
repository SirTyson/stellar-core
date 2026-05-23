# H009: Avoid `mEntries.begin()` Materialization in `InMemoryBucketState::scan`

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (bucket integration with apply-path loads)
**Severity**: Low
**Impact**: Apply-path bucket-snapshot scan cost reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InMemoryBucketState::scan(IterT start, LedgerKey const& searchKey) const`
in `src/bucket/InMemoryIndex.cpp:251` should perform a hash lookup
(`mEntries.find(searchKey)`) and return only the meaningful payload to the
caller, doing no additional unordered_set traversal work. The `IterT`
returned in the `(IndexReturnT, IterT)` pair is unused by the caller
when the backing container is an unordered set, because the iterator carries
no ordering information that the next call could use to bound its search.

The caller in `SearchableBucketListSnapshot::loadKeysFromBucket`
(`src/bucket/BucketListSnapshot.cpp:228`) stores the returned iterator into
`indexIter` and passes it as `start` to the next `index.scan` invocation. For
an in-memory (unordered) bucket index, the `start` parameter is ignored
(see the comment "start is ignored for in-memory indexes"), so the
returned iterator value has no observable effect on the next iteration.

## Mechanism

Today both code branches in `InMemoryBucketState::scan` materialize
`mEntries.begin()` and return it inside the result pair, even on the
not-found path and on every hit. For libstdc++/libc++ `unordered_set`,
`begin()` is required to walk the bucket vector forward to the first
non-empty bucket. Real-world in-memory bucket indexes for soroswap
contain tens of thousands of contract-data entries with a default load
factor; `begin()` is not free per call, although it is amortized over
a bucket scan. With ~956k `scan` calls visible in the diagnostic Tracy
trace and a 2.3 us mean self-time, materializing the iterator on each
call contributes a non-zero but small fraction of the scan cost.

The change is local: replace `mEntries.begin()` with `mEntries.end()`
in both return statements (or hoist a single `mEntries.end()` value
before the find). `mEntries.end()` is a constant-time call that does
not walk buckets, so per-call work decreases by the bucket-walk cost.
Behaviour is preserved because callers do not consume the returned
iterator for in-memory buckets.

## Trigger

Run `apply-load --mode soroswap-tps` and capture a Tracy trace; observe
`scan` self-time inside the `applyLedger` window via the diagnostic
trace at `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/`.

## Target Code

- `src/bucket/InMemoryIndex.cpp:251-262` — `InMemoryBucketState::scan`
  returns `mEntries.begin()` in both branches.
- `src/bucket/BucketListSnapshot.cpp:208-277` —
  `SearchableBucketListSnapshot::loadKeysFromBucket` consumes the
  returned iterator but ignores its value for in-memory bucket
  indexes (the `scan` body documents this).

## Evidence

- Diagnostic Tracy soroswap trace shows `scan` total self-time of
  2.245 s across 956,502 calls (mean 2.35 us). Tracy zone is at
  `bucket/InMemoryIndex.cpp:253`.
- The implementation explicitly ignores the `start` parameter, so
  the iterator value carries no information that subsequent calls
  could use.
- `mEntries.end()` is O(1) on `unordered_set`; `mEntries.begin()`
  walks bucket vector to first non-empty bucket.

## Anti-Evidence

- The 2.245 s `scan` total is dominated by tx-set construction /
  surge pricing calls (`TxSetUtils::getInvalidTxListWithErrors` and
  related zones in the trace). Apply-window-resident `scan` work is
  bounded by `BucketListSnapshot::load` (~233 ms total = ~3.3 ms /
  ledger) plus a small prefetch contribution; both fall well below
  the 3% Medium floor (~6.5 ms / ledger).
- Even the per-call savings are small: the bucket walk for a
  reasonably-loaded `unordered_set` is dominated by hashing
  `LedgerKey` (especially `CONTRACT_DATA` keys with embedded
  `ScVal`), not by `begin()` traversal.
- The 1% Low floor (~2.2 ms / ledger) also requires removing
  ~70% of the apply-window scan time, which the `begin()`
  materialization is not by itself.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — `InMemoryBucketState::scan` `begin()` materialization
not previously investigated. The closely-related
`001-eliminate-polymorphic-inmemorybucketstate-scan-overhead.md` failure
targeted a different mechanism (virtual dispatch and `LedgerKey` copy
overhead) and was rejected because `benchmarkModelTxTpsSingleLedger`'s
`warmAccountCache()` inflated apply-window attribution, not because of
`begin()`. The current candidate targets the `apply-load` benchmark
where there is no warm-up inflation, but is still sub-threshold.

### Why It Failed

The candidate is below the objective's Medium severity threshold and
also below the Low (1–3%) noise floor. The apply-window-resident
`scan` time on the soroswap shape is bounded by `BucketListSnapshot::load`
(~3.3 ms / ledger), and the per-call removable share from skipping
`mEntries.begin()` materialization is a small fraction of the scan
self-time. With Tracy `scan` mean self-time of 2.35 us per call, the
typical `unordered_set::begin()` walk is sub-100 ns on a well-loaded
table — bucket walks dominate only on extremely sparse tables. Soroswap
in-memory state at steady state is dense, so the practical per-call
savings are sub-microsecond. Across the apply window the upper bound
is well under 0.5 ms / ledger (under 0.25% of the 218 ms soroswap
baseline), placing this firmly inside benchmark noise.

### Lesson Learned

Returning unused iterators from hash-set lookups carries a small but
real cost (bucket-walk for `begin()`); however, for soroswap apply
loads on the in-memory bucket index, the apply-window-resident `scan`
total (~3.3 ms / ledger) is far less than the aggregate Tracy total
(which is dominated by tx-set construction calls outside the
`applyLedger` window). Any further bucket-scan optimization must
either reduce `LedgerKey` hashing cost (the dominant per-call work),
batch multiple lookups into a single hash-table pass, or eliminate
the scan calls entirely — micro-fixes inside `scan` are bounded
below 1%.
