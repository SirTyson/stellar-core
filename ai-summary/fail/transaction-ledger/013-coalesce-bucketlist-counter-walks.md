# H013: Coalesce three redundant per-ledger BucketList counter walks in addLiveBatch

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / bucket reporting
**Severity**: Low
**Impact**: Per-ledger bucket-walk overhead inside `BucketManager::addLiveBatch`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each ledger close performs `BucketManager::addLiveBatch` once. Inside, the
LiveBucketList is walked to (1) sum per-bucket entry counts for cache-size
heuristics, (2) report bucket entry counts/sizes to medida, and (3) report
LiveBucket index cache metrics. These three walks read the same per-bucket
`BucketEntryCounters` from the same indexes; they should be combinable into a
single sweep that produces both the total accounts-size needed by
`maybeInitializeCaches` and the per-type reporting numbers.

## Mechanism

`LiveBucketList::addBatch` (`src/bucket/LiveBucketList.cpp:14-26`) calls
`maybeInitializeCaches`, which calls `sumBucketEntryCounters` (walks all 22
levels × {curr, snap} and accumulates a `BucketEntryCounters`).
`BucketManager::addLiveBatch` (`src/bucket/BucketManager.cpp:1025-1046`)
then calls `reportBucketEntryCountMetrics` which calls
`sumBucketEntryCounters` *again* (same walk, recomputed), and
`reportLiveBucketIndexCacheMetrics` (`src/bucket/BucketManager.cpp:353-396`)
which walks all 44 buckets a third time, calling
`bucket->getBucketEntryCounters()` per bucket. The three walks each return
or copy a `BucketEntryCounters` containing two `std::map<LedgerEntryTypeAndDurability, size_t>`;
`operator+=` (`src/bucket/BucketUtils.cpp:339-351`) and the by-value return
imply heap allocation per walk. A single combined walk could (a) eliminate
two of the three sweeps and (b) avoid the `std::map` copy by using a
`std::array<size_t, NUM_TYPES>` representation since the type space is fixed.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) using the
trace at `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`.
`addLiveBatch` is called once per ledger close inside
`sealLedgerTxnAndStoreInBucketsAndDB`.

## Target Code

- `src/bucket/LiveBucketList.cpp:14-68` — `addBatch`, `sumBucketEntryCounters`, `maybeInitializeCaches`.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch` driver.
- `src/bucket/BucketManager.cpp:353-396` — `reportLiveBucketIndexCacheMetrics` walks every bucket.
- `src/bucket/BucketManager.cpp:1930-1963` — `reportBucketEntryCountMetrics` calls `sumBucketEntryCounters` a second time.
- `src/bucket/BucketUtils.cpp:339-351` — `BucketEntryCounters::operator+=` iterates two `std::map` instances per add.
- `src/bucket/BucketUtils.h:197-216` — data structure uses `std::map` despite a fixed enum type space.

## Evidence

The three walks structurally redundantly read the same per-bucket counters,
each constructed at index-build time and stored on the bucket index. Walking
22 levels × 2 buckets × 3 calls = 132 bucket visits per ledger plus the
`std::map` copy/return overhead per walk. Eliminating two-thirds of these
sweeps and converting the counters to `std::array` would shrink the
per-ledger reporting overhead.

## Anti-Evidence

- Tracy `-e` self-time analysis on the current soroswap trace shows
  `addLiveBatch` self-time = 495 µs / 66 calls (~7.5 µs/call) and
  `LiveBucketList::addBatch` self-time = 880 µs / 66 calls (~13 µs/call).
  The total per-ledger bucket-reporting overhead is therefore well under
  100 µs/ledger — far below the 18 ms-per-ledger Medium threshold.
- The 502 ms total time of `addLiveBatch` is dominated by descendants
  (`addBatchInternal` → `prepareFirstLevel` → `mergeInMemory` and the
  underlying merge/put work), not by the reporting walks.
- Even reducing the reporting work to zero would save ~100 µs/ledger
  (≈0.017% of the 596 ms baseline), an order of magnitude below benchmark
  noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — prior `addLiveBatch`-related failure (`001-async-addlivebatch`) targeted async-offloading the whole call, not in-call walk consolidation; reporting/counter-walk consolidation is a distinct angle that has not been investigated.

### Why It Failed

Self-time profiling of the actual `BucketManager::addLiveBatch` and
`LiveBucketList::addBatch` zones in the soroswap baseline shows that the
combined non-child-zone work (which is where the reporting walks live) is
~1–2 µs per call summed across 66 ledgers — total well under 100 µs of
apply time per benchmark run, far below the objective's 1% noise floor and
the 3% Medium threshold. The visually large `addLiveBatch` *total* time
(502 ms) is descendant-time inside `addBatchInternal` →
`prepareFirstLevel` → `mergeInMemory` and the underlying merge work, not
the reporting walks. Eliminating all three walks would save effectively
zero apply-window time.

### Lesson Learned

When evaluating bucket-path optimizations, distinguish CSV `total` columns
from `-e` self-time columns: a function whose total time is large because
of descendants offers no win when only its self-time can be reduced.
Always check `addLiveBatch` self vs total before targeting its body.
