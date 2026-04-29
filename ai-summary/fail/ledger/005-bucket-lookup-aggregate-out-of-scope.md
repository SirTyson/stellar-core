# H005: Bucket lookup aggregate hotspots are not apply-ledger descendants

**Date**: 2026-04-29
**Subsystem**: ledger / BucketList snapshot lookup
**Severity**: Medium
**Impact**: suspected BucketList lookup apply-time reduction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Only BucketList lookup work that occurs inside `applyLedger` windows can reduce the soroswap apply-time benchmark. If `BucketListSnapshot::load`, `getBucketEntry`, or `InMemoryIndex::scan` are hot primarily during transaction-set construction, validation, or other out-of-window phases, optimizing them should not be promoted as a ledger apply-path hypothesis.

## Mechanism

The aggregate Tracy profile initially made BucketList point lookups look attractive: `scan`, `getBucketEntry`, and `load` had large total/self times. Timeline overlap analysis showed those events almost never occur inside `applyLedger` in the current soroswap trace, so the apparent bottleneck is a profile-scope artifact rather than an apply critical-path cost.

## Trigger

Run `csvexport-release -e` on the current soroswap Tracy trace and sort by self-time. `bucket/InMemoryIndex.cpp:scan` and `bucket/BucketListSnapshot.cpp:getBucketEntry` appear as aggregate hotspots, but comparing their individual event windows against `applyLedger` windows shows negligible overlap.

## Target Code

- `src/bucket/BucketListSnapshot.cpp:166-201` — `SearchableBucketListSnapshot::getBucketEntry` point lookup wrapper.
- `src/bucket/BucketListSnapshot.cpp:313-345` — `SearchableBucketListSnapshot::load` searches buckets for a single key.
- `src/bucket/InMemoryIndex.cpp:249-262` — `InMemoryBucketState::scan` hash lookup used by bulk lookup paths.

## Evidence

Aggregate self-time showed `scan` at `1,732,122,001 ns` over 857,848 calls and `getBucketEntry` total time at `1,822,350,935 ns` over 707,847 calls. Direct overlap analysis against `applyLedger` windows found only `101,450 ns` of `scan` time overlapped `applyLedger` (`0.01%`), only `170,834 ns` of `getBucketEntry` time overlapped (`0.01%`), and `BucketListSnapshot::load` had `0 ns` of overlap in this trace.

## Anti-Evidence

The only in-scope BucketList commit work found in this pass was `addLiveBatch` / `addBatchInternal` / `mergeInMemory`, not point lookup. Those are distinct synchronous commit paths and should be investigated separately from snapshot lookup micro-optimizations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a Tracy-overlap rejection for these lookup zones

### Why It Failed

The hot lookup zones are aggregate process hotspots, not meaningful descendants of the measured `applyLedger` windows for the current soroswap benchmark. Optimizing them would target out-of-scope work and is unlikely to reduce the objective's apply-time metric.

### Lesson Learned

For Tracy apply-load profiles, BucketList lookup zones must be timeline-checked against `applyLedger`; high aggregate bucket lookup time is not sufficient evidence of an apply-path bottleneck.
