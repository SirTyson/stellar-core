# H001: Thread-State Cache for Classic Snapshot Reads

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Classic BucketList point-load reduction in parallel Soroban apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated non-Soroban `LedgerKey` reads during one cluster should avoid repeated live-snapshot bucket walks by caching clean classic entries in `ThreadParallelApplyLedgerState`, while preserving deterministic transaction ordering and keeping dirty writes in the existing thread/global entry maps.

## Mechanism

`ThreadParallelApplyLedgerState::getLiveEntryOpt` only caches entries already present in `mThreadEntryMap`; if a non-Soroban key is absent, it falls through to `mLCLSnapshot.loadLiveEntry(key)` and returns the adopted entry without inserting it into the thread map. A read-through cache for clean classic ACCOUNT/TRUSTLINE entries could avoid repeated `BucketListSnapshot::load` / `InMemoryIndex::scan` work when a cluster repeatedly reads the same classic key.

## Trigger

Run the soroswap apply-load benchmark with clusters that repeatedly touch the same classic keys through fee-source, source-account, or SAC-adjacent reads.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1084-1120` - `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls through to `mLCLSnapshot.loadLiveEntry(key)` for non-Soroban keys and does not remember clean snapshot hits.
- `src/bucket/BucketListSnapshot.cpp:313-345` - `SearchableBucketListSnapshot::load` walks bucket levels for each point load.
- `src/bucket/InMemoryIndex.cpp:249-262` - `InMemoryBucketState::scan` performs the per-bucket hash lookup used by point loads.

## Evidence

The process-wide Tracy aggregate initially looked attractive: `BucketListSnapshot::load` at `BucketListSnapshot.cpp:317` totals 2.646s and `InMemoryIndex::scan` at `InMemoryIndex.cpp:253` totals 2.245s. The source also shows that non-Soroban fallback reads in `getLiveEntryOpt` do not populate `mThreadEntryMap`, so a cache could be correct for clean reads.

## Anti-Evidence

After unwrapping timestamps and intersecting events with the 71 `applyLedger` windows from the current soroswap trace, only 115.3ms of `BucketListSnapshot::load` and 82.7ms of `InMemoryIndex::scan` fall inside measured apply. That is about 2.58% and 1.85% of the diagnostic apply window before subtracting cache overhead, hit-rate uncertainty, and mandatory copies, so it does not meet the objective's Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS - this specific thread-state read-through-cache framing was not present as a pending hypothesis, though it is adjacent to prior bucket-cache investigations

### Why It Failed

The target bucket point-load work is mostly outside the measured soroswap apply window in the current trace. The in-apply remainder is below the 3% Medium threshold even before implementation overhead.

### Lesson Learned

For bucket zones in apply-load Tracy traces, always unwrap and intersect events with `applyLedger`; process-wide bucket totals can be dominated by benchmark setup or TX-set construction and are not automatically apply-time bottlenecks.
