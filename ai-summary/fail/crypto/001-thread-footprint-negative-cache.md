# H001: Cache Thread-Local Snapshot Misses for Soroswap Footprint Loads

**Date**: 2026-05-25
**Subsystem**: crypto / bucket / transactions
**Severity**: Medium
**Impact**: reduce repeated apply-path `LedgerKey` hashing/equality and live-bucket scans for missing or first-touched Soroban footprint entries
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During parallel Soroban apply, a thread should observe the same initial live-snapshot value for a footprint key every time it asks for that key until the thread explicitly writes or erases it. If a read-write footprint key is absent from the live snapshot, repeated checks in the same thread should consistently return `std::nullopt`, preserve `isNew` behavior when the host later creates the entry, and avoid changing ledger output, metadata ordering, rent accounting, or restore semantics.

## Mechanism

`ThreadParallelApplyLedgerState::getLiveEntryOpt` first probes `mThreadEntryMap`, but when a key is absent there it loads from `mInMemorySorobanState` or `mLCLSnapshot.loadLiveEntry(key)` and returns a scoped optional without inserting that clean positive or negative result into `mThreadEntryMap`. Soroswap read-write keys are then looked up again from later phases such as `InvokeHostFunctionOpFrame::addReads`, `commitChangeFromSuccessfulTx`, metadata extraction, or TTL-bump flushing until a dirty write is installed. Caching the clean snapshot result, including null entries, on the first miss would collapse repeated `LedgerKey` hashing/equality and BucketList point scans while preserving deterministic per-thread state transitions.

## Trigger

Run the current accepted soroswap apply-load trace from `ai-summary/CURRENT_STATE.md` (`/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`) and timestamp-filter live-bucket lookup zones against `applyLedger`. The current trace shows apply-overlapping `scan` at `bucket/InMemoryIndex.cpp:253` with 2.345813854 s self-time over 958,911 calls, `getBucketEntry` at `bucket/BucketListSnapshot.cpp:174` with 2.450755839 s total over 808,910 calls, and `load` at `bucket/BucketListSnapshot.cpp:317` with 2.738513678 s total over 553,628 calls. A PoC should instrument `ThreadParallelApplyLedgerState::getLiveEntryOpt` to count repeated same-thread live-snapshot misses/hits for read-write `CONTRACT_DATA` and `TTL` keys before adding the cache.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` returns a live-snapshot result without memoizing it in `mThreadEntryMap`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-534` — `addReads` calls `getLedgerEntryOpt` for footprint data and TTL entries before host execution.
- `src/transactions/ParallelApplyUtils.cpp:1164-1195` — `commitChangeFromSuccessfulTx` calls `getLiveEntryOpt` again to classify old vs new entries.
- `src/bucket/BucketListSnapshot.cpp:315-345` — point `load` searches buckets for each requested key.
- `src/bucket/InMemoryIndex.cpp:249-262` — `InMemoryBucketState::scan` performs the hot heterogeneous `unordered_set::find(searchKey)` over `LedgerKey` hashes/equality.

## Evidence

The source path is a descendant of `applyLedger`: `LedgerManagerImpl::applyThread` calls `TransactionFrame::parallelApply`, which calls `InvokeHostFunctionOpFrame::doParallelApply`, which calls `InvokeHostFunctionApplyHelper::addReads`, then `ParallelLedgerAccessHelper::getLedgerEntryOpt`, and finally `ThreadParallelApplyLedgerState::getLiveEntryOpt`. The hot trace rows line up with this structure: `applySorobanStageClustersInParallel` is an `applyLedger` child, and the timestamp-filtered live-bucket lookup rows overlap those apply windows at much higher cost than the local SHA256 or verifySig ceilings. The existing `mThreadEntryMap` representation already supports clean optional entries and preserves `mIsNew` through `upsertEntry`/`eraseEntry`; the missing piece is populating it after a live-snapshot fallback rather than only from global preloading or dirty writes.

## Anti-Evidence

The trace rows are aggregate worker time from the parallel apply phase, so projected wall-clock savings must be normalized by the configured cluster count. If most `getLiveEntryOpt` fallbacks are first-and-only lookups, memoizing them will save only an insertion cost and will not clear Medium. The implementation also has to avoid converting a clean cached `nullopt` into an observable deletion: it must remain a read-through cache entry until an explicit host modification marks it dirty.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The no-memoization claim is real: `ThreadParallelApplyLedgerState::getLiveEntryOpt` checks `mThreadEntryMap` and then reads from either `mInMemorySorobanState` or `mLCLSnapshot` without installing a clean positive or negative entry. The proposed bucket-scan mechanism is not viable for the claimed Soroban `CONTRACT_DATA`/`TTL` target, because those key types are explicitly routed to `InMemorySorobanState::get` rather than `BucketListSnapshot::load` in the p23+ parallel apply path. The remaining bucket-list point-load surface is for non-in-memory types, and even eliminating the entire cited `BucketListSnapshot::load` trace total would be below the objective's Medium floor after per-ledger and 8-cluster normalization.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2470-2575` — `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster and runs `applyThread` on worker futures.
- `src/ledger/LedgerManagerImpl.cpp:2673-2710` — `applySorobanStages` builds `GlobalParallelApplyLedgerState`, applies each stage, then commits dirty global entries to `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — `getLiveEntryOpt` does not memoize fallback results, but sends `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys to `mInMemorySorobanState.get(key)`.
- `src/ledger/InMemorySorobanState.cpp:206-238` and `src/ledger/InMemorySorobanState.cpp:412-446` — Soroban data/code and TTL lookups are in-memory map lookups; TTL entries are synthesized from embedded TTL data, not loaded from buckets.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-534` — `addReads` calls `getLedgerEntryOpt` for TTL and live entries before invoking the host, setting `mRwKeyExisted` for read-write keys.
- `src/transactions/TransactionMeta.cpp:384-452` and `src/transactions/ParallelApplyUtils.cpp:1164-1195` — metadata extraction and `commitChangeFromSuccessfulTx` re-read the previous thread/live value for modified keys.
- `src/bucket/BucketListSnapshot.cpp:313-345` and `src/bucket/InMemoryIndex.cpp:249-262` — bucket point loads and in-memory bucket index scans exist, but are not the fallback path for Soroban `CONTRACT_DATA`/`TTL` keys in `ThreadParallelApplyLedgerState`.
- `ai-summary/CURRENT_STATE.md:54-64` and `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.log` — baseline soroswap medians are about 207-210 ms; the Tracy run contains 200 measured soroswap ledgers at 8 clusters.

### Why It Failed

The traced optimization target is mis-attributed. Caching clean thread entries could remove repeated `InMemorySorobanState::get` calls and some non-Soroban snapshot loads, but it cannot remove the cited live-bucket scans for read-write `CONTRACT_DATA`/`TTL` keys because those keys do not call `BucketListSnapshot::load`. The cited `BucketListSnapshot::load` total of 2.7385 s over the 200-ledger Tracy run is at most about 13.7 ms aggregate worker time per ledger, or about 1.7 ms wall time at 8 clusters, roughly 0.8% of a 207-210 ms soroswap apply. Since only a repeated subset of those loads is removable, the realistic impact is below the objective severity threshold (Low/Informational, not Medium).

### Lesson Learned

For p23+ Soroban parallel apply, distinguish `InMemorySorobanState` footprint lookups from BucketListDB point loads before attributing `BucketListSnapshot` or `InMemoryIndex` Tracy totals to `CONTRACT_DATA`/`TTL` footprint caching. Any future thread-local clean-entry cache hypothesis needs direct per-key repeat counts from `ThreadParallelApplyLedgerState::getLiveEntryOpt`, split by `InMemorySorobanState` vs `mLCLSnapshot`, and must preserve `mIsNew=true` for cached clean `nullopt` entries if they later become dirty creations.
