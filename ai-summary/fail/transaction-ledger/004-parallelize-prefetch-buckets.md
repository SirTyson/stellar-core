# H004: Parallelize per-bucket loadKeysFromBucket inside prefetch across LiveBucket levels

**Date**: 2026-05-02
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: shorten the synchronous prefetch step inside applyLedger by parallelizing per-bucket scans
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerTxnRoot::prefetchInternal` (Tracy zone `prefetch`,
`ledger/LedgerTxn.cpp:3103`) loads a batch of LedgerKeys from the
LiveBucketList by walking buckets level-by-level and calling
`loadKeysFromBucket` per bucket sequentially. Each `loadKeysFromBucket`
runs an `IndexT::scan` (in-memory or disk index) over the bucket's
sorted entries. The bucket scans are read-only, independent of one
another (only the merge of per-bucket results matters), and the
LiveBucketList during apply is immutable. A correctly tuned
implementation would dispatch the per-bucket scans to the existing
worker pool (capped at NUM_CLUSTERS = 8), then merge the per-bucket
results back into `mEntryCache` on the calling thread, reducing
critical-path duration from sum(per-bucket scan times) to
max(per-bucket scan times).

## Mechanism

Tracy `prefetch` zone shows 89.2ms total over 142 calls (= 2 prefetch
calls per ledger × 71 ledgers ≈ 0.63ms/ledger). The scan cost is
spread across all `LiveBucket` levels (typically ~11 levels × 2
sub-buckets = up to 22 buckets per scan). If parallelized 8-wide, the
critical-path reduction is at most a factor of `min(8, num_buckets) ≈
8`, giving an upper bound of ~0.55ms/ledger savings (≈ 0.75% of
applyLedger Tracy window or ≈ 0.2% of the 278ms benchmark median).
Real savings would be lower because (a) the smallest buckets dominate
in the cache-miss-free case, (b) thread dispatch overhead per bucket is
non-trivial relative to <50µs scans, and (c) merging results requires
synchronization on `mEntryCache`.

## Trigger

Standard soroswap apply-load benchmark. The change would split the
inner loop of `LedgerTxnRoot::prefetchInternal` into per-bucket tasks
posted to the existing worker pool.

## Target Code

- `src/ledger/LedgerTxn.cpp:3103` — `prefetch` Tracy zone, calls
  `loadKeysFromBucket` per bucket sequentially.
- `src/bucket/BucketListSnapshot.cpp:loadKeysFromBucket` — per-bucket
  scan logic invoked sequentially today.

## Evidence

- `prefetch` Tracy total = 89.2ms / 142 calls confirms small per-call
  cost (≈ 0.63ms each).
- Per-bucket work is read-only against an immutable BucketList, so
  parallel scans are determinism-safe.

## Anti-Evidence

- Total prefetch work is only ~1.25ms/ledger combined — already small.
- 8-wide parallelism is bounded by Amdahl-style overhead (thread
  dispatch + result-merge cost) for tasks of <100µs each; realistic
  savings likely well below the 0.55ms/ledger upper bound.
- BucketListSnapshot calls have a per-call medida `TimeScope` that
  itself has overhead under contention.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail/hypothesis/reviewed/poc dirs

### Why It Failed

Total `prefetch` zone cost is ~1.25ms/ledger across both prefetch
calls. Even an idealised 8× speedup yields ≤ 1.1ms/ledger savings ≈
0.4% of the benchmark median — well below the 3% Medium floor and
inside benchmark noise. Per-bucket scan tasks are sub-100µs, so
worker-pool dispatch overhead would erode much of the theoretical win.

### Lesson Learned

`prefetch` zones in the Tracy trace are already small relative to
applyLedger; further parallelization of the prefetch internals is
not a productive optimization target on the soroswap benchmark. Any
future prefetch-related hypothesis should target reducing call
count or eliminating it entirely (e.g. via in-memory state) rather
than parallelizing the scans.
