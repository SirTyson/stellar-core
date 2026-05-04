# H003: Bulk-Preload Read-Only Classic Footprint Entries at ThreadParallelApplyLedgerState Construction

**Date**: 2026-05-03
**Subsystem**: transaction-ledger (parallel apply / bucket lookup)
**Severity**: Low
**Impact**: Worker classic-key load path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a `ThreadParallelApplyLedgerState` is constructed at
`LedgerManagerImpl::applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2548`), it should pre-collect every classic
read-only footprint key the cluster's transactions will consult, then issue a
single bulk `BucketListSnapshot::loadKeysFromBucket`-backed call (or equivalent
`loadKeysInternal` against `mLCLSnapshot`) so that each individual
`mLCLSnapshot.loadLiveEntry(key)` invocation inside `LedgerAccessHelper` /
`getLiveEntryOpt` becomes a hash-table hit instead of a fresh
`BucketListSnapshot::load` walking the bucket levels.

## Mechanism

`getLiveEntryOpt` and the `LedgerAccessHelper` chain repeatedly call
`mLCLSnapshot.loadLiveEntry(k)` for classic footprint keys (accounts,
trustlines) of every Soroban tx in the cluster. Each call lands in
`BucketListSnapshot::load`, which walks `loopAllBuckets` (curr + snap of
every level) until the entry is found and pays per-call `mPointTimers.find`
+ `getBucketEntry` + `scan` cost. The proposal is to bulk-load all such keys
at thread setup so each subsequent per-tx lookup is served from a local map
(O(1)) rather than re-traversing the BucketList.

## Trigger

Soroswap apply-load benchmark (8 clusters, ~200 txs/ledger). Workers in each
cluster repeatedly fetch the same handful of classic accounts / trustlines
(swap source, pair contract instance, token issuer SAC config) from
`mLCLSnapshot`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel`
  (where `ThreadParallelApplyLedgerState` is constructed serially)
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState`
  constructor
- `src/transactions/ParallelApplyUtils.cpp:1084-1118` — `getLiveEntryOpt` LCL-snapshot fallback
- `src/bucket/BucketListSnapshot.cpp:315` — `load` (per-key bucket walk)

## Evidence

- `BucketListSnapshot::load` self+children total = 2.32 s aggregate across the
  trace; `getBucketEntry` self = 2.05 s, `scan` self = 1.95 s.
- Soroswap clusters share source accounts and pair contract entries across
  many txs, suggesting hot-key reuse.

## Anti-Evidence

- Prior fail H010 (clean-entry-cache for LCL classic snapshot reads in cluster)
  measured the apply-window-only ceiling for this exact angle at ~1.5%
  (~107 ms / 8 / 71 = ~0.19 ms / ledger of LCL snapshot work that lives inside
  `applyLedger`, not the full 2.32 s figure). The 2.32 s `load` total is
  dominated by TX-set construction (`commonValidPreSeqNum`), which is OUT OF
  SCOPE per the meta-pattern "Tracy Trap".
- The `BucketListSnapshot::loadKeysInternal` bulk path is itself O(per-bucket-scan
  per key) — replacing N point lookups with one bulk that still scans buckets
  saves only the per-call ZoneScoped/timer overhead, not the actual bucket
  traversal.
- `ThreadParallelApplyLedgerState` construction is on the stage critical path
  (constructed serially before each `std::async`); adding a bulk-preload step
  there would push setup work onto the critical path it is trying to relieve.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct mechanism from H010 (bulk preload vs per-key cache),
but lands on the same saturated quantity.

### Why It Failed

The apply-window-only quantity of work spent in `mLCLSnapshot.loadLiveEntry`
during cluster execution is ≤ ~1.5% of the soroswap median apply time
(established by H010). Below the Medium severity threshold (3%). The
2.32 s aggregate `BucketListSnapshot::load` figure is mostly TX-set
construction, not `applyLedger` descendants. Bulk-preload at thread-setup time
also competes with the same critical path it tries to relieve, eroding any
gain.

### Lesson Learned

Apply-window LCL snapshot reads in cluster workers are bounded under ~1.5% on
the soroswap shape. Future hypotheses targeting `BucketListSnapshot::load`
inside `applyLedger` must size the apply-window-only subset (filtering by the
parent zone), not the full Tracy total which is dominated by TX-set
construction.
