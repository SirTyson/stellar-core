# H053: In-Memory Bucket Bulk Lookup Specialization

**Date**: 2026-05-21
**Subsystem**: crypto / bucket index hashing
**Severity**: Low
**Impact**: BucketList lookup CPU reduction below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Bulk footprint loads should find in-memory bucket entries with the same shadowing semantics as the current ordered bucket traversal: for each key, the newest bucket entry wins, tombstones suppress older values, and the returned entries remain deterministic.

## Mechanism

`SearchableBucketListSnapshot::loadKeysFromBucket` is written around sorted disk-index scans, but `InMemoryBucketState::scan` ignores the start iterator and performs an independent `unordered_set::find` for every remaining key in every in-memory bucket. A specialized in-memory bulk path could avoid repeated scan-interface overhead by batching lookups against the in-memory set or by maintaining a key-indexed representation.

## Trigger

Run the current soroswap apply-load case and inspect bucket lookup zones in the diagnostic trace.

## Target Code

- `src/bucket/BucketListSnapshot.cpp:loadKeysFromBucket:210-276` — generic bulk loader repeatedly calls `index.scan`.
- `src/bucket/InMemoryIndex.cpp:InMemoryBucketState::scan:249-262` — ignores the ordered start iterator and calls `mEntries.find(searchKey)`.
- `src/bucket/InMemoryIndex.h:InMemoryBucketState:79-98` — in-memory set representation used for heterogeneous lookup.

## Evidence

The whole-trace aggregate `scan` zone at `bucket/InMemoryIndex.cpp:253` is large: 1,951.943 ms / 926,932 calls, and `getBucketEntry` totals 2,048.197 ms. The source also shows a real impedance mismatch between the disk-index scan API and the in-memory hash-set implementation.

## Anti-Evidence

Unwrap containment against the current `applyLedger` windows shows only 78.403 ms of `InMemoryIndex::scan`, 76.968 ms of `getBucketEntry`, and 107.742 ms of `BucketListSnapshot::load` are inside apply. This is below the objective's 3% Medium floor, and prior records already warn that most global bucket/index scan time is outside soroswap apply.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — this specific bulk-loader/in-memory API mismatch was checked against the current trace

### Why It Failed

The apparent hotspot is mostly outside the measured apply window; the apply-contained portion is too small to justify a Medium hypothesis even before subtracting work that a safe implementation would still need to perform.

### Lesson Learned

Bucket/index zones must be timestamp-filtered against `applyLedger`; whole-process scan totals are dominated by pre-apply, setup, or background work and cannot be used directly for soroswap apply-time severity.
