# H014: Bucket Snapshot In-Memory Index Scans During Apply

**Date**: 2026-05-04
**Subsystem**: transactions, bucket
**Severity**: Low
**Impact**: apply-path bucket lookup optimization below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Bulk and point loads from `BucketListSnapshot` during soroswap apply should locate footprint ledger keys without repeated expensive index probes. If in-memory bucket index scans were a dominant apply descendant, batching or caching these lookups should reduce apply time while returning the same newest live entry or tombstone-shadowing result for every key.

## Mechanism

The global Tracy self-time view showed `scan` in `bucket/InMemoryIndex.cpp` as a large 1,951,942,732 ns hotspot and `BucketListSnapshot::load` as a visible lookup path, suggesting repeated BucketList index probes might be apply-blocking. If those scans occurred primarily under `applyLedger`, a batch lookup redesign could plausibly reduce synchronous footprint-load cost. Timestamp-filtering against actual `applyLedger` windows shows this is not the case for the current soroswap trace.

## Trigger

Run the current accepted soroswap Tracy trace and compare unfiltered self-time hotspots with timestamp-filtered descendants of `applyLedger`, focusing on `scan` and `load` zones.

## Target Code

- `src/bucket/InMemoryIndex.cpp:249-262` — `InMemoryBucketState::scan` performs an in-memory hash lookup for a requested `LedgerKey`.
- `src/bucket/BucketListSnapshot.cpp:203-277` — `loadKeysFromBucket` scans one bucket index while destructively removing loaded keys from the remaining key set.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point `load` loops buckets and calls `getBucketEntry`.

## Evidence

Unfiltered self-time from the current trace reports `scan,bucket/InMemoryIndex.cpp,253` at 1,951,942,732 ns across 926,932 calls and `load,bucket/BucketListSnapshot.cpp,317` at 215,450,009 ns across 521,715 calls. These looked large enough to investigate as a possible footprint-loading bottleneck.

## Anti-Evidence

After exporting individual `applyLedger`, `scan`, and `load` events and counting only events fully contained inside `applyLedger` windows, `scan` at `bucket/InMemoryIndex.cpp:253` accounts for only 78,403,366 ns and `BucketListSnapshot::load` for only 107,742,256 ns across the full 5,230,315,999 ns apply trace. Even complete elimination of either path is below the 156,909,480 ns Medium threshold, and realistic batching would recover only a fraction of that.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — bucket snapshot lookup overlap was not separately recorded in the transactions fail summary

### Why It Failed

The large unfiltered `InMemoryIndex::scan` number is mostly outside the measured apply window. Within `applyLedger`, bucket snapshot scans are a sub-3% slice of current soroswap close time, so this is below the objective severity threshold.

### Lesson Learned

Bucket lookup zones need timestamp filtering just like validation and tx-set construction zones. A large global bucket index self-time is not sufficient evidence of apply-path impact unless the events fall inside `applyLedger` windows and clear the Medium threshold after realistic recoverability bounds.
