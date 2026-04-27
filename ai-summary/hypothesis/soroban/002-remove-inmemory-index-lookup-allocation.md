# H002: Remove Per-Lookup Allocation from InMemoryIndex Footprint Reads

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: Medium
**Impact**: soroswap apply-time reduction in classic footprint loading from BucketList snapshots
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban parallel apply should load classic footprint entries from the LCL BucketList snapshot with O(1) hash lookups that do not allocate or dispatch virtually for every missed or found key. The lookup should return exactly the same `BucketEntry` or miss as today, and it should not alter ordering, hashing semantics, or any ledger-entry state transition.

## Mechanism

When a parallel Soroban transaction asks for a classic footprint key that was not preloaded into the thread map, `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls through to `mLCLSnapshot.loadLiveEntry(key)`. For small in-memory buckets, `BucketListSnapshot::load` reaches `InMemoryBucketState::scan`, which constructs `InternalInMemoryBucketEntry(searchKey)` for every lookup; that wrapper owns a heap-allocated polymorphic `QueryKey`, and equality/hash dispatch through virtual methods that repeatedly materialize/copy keys from stored bucket entries. Replacing the query wrapper with a non-allocating representation (for example a tagged/variant key view, or C++20 heterogeneous lookup when available) should remove allocator and virtual-dispatch cost from the hottest BucketList lookup path while preserving deterministic lookup results.

## Trigger

Run the current soroswap benchmark (`scripts/run_apply_load_matrix.py --tracy`, soroswap TX=4000, T=8). The reference trace reports `scan` at `bucket/InMemoryIndex.cpp:67` with **3,139,848,749 ns self-time** over 1,445,421 calls and `BucketListSnapshot::load` at `bucket/BucketListSnapshot.cpp:317` with **3,629,312,941 ns total time** over 669,582 calls. This path is exercised during `applyLedger` when `InvokeHostFunctionOpFrame::addReads` materializes contract footprints for parallel Soroban execution.

## Target Code

- `src/bucket/InMemoryIndex.h:26-133` — `InternalInMemoryBucketEntry` stores either `ValueEntry` or `QueryKey` behind `std::unique_ptr<AbstractEntry>`, forcing heap allocation for lookup keys and virtual hash/equality.
- `src/bucket/InMemoryIndex.cpp:63-76` — `InMemoryBucketState::scan` constructs a query wrapper and calls `mEntries.find(...)` for every lookup.
- `src/bucket/BucketListSnapshot.cpp:313-340` — `SearchableBucketListSnapshot::load` loops through buckets and calls `getBucketEntry`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls through to `mLCLSnapshot.loadLiveEntry(key)` for non-in-memory classic footprint keys.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:381-535` — `addReads` requests every footprint entry before invoking the Rust host.

## Evidence

The zone is an applyLedger descendant by source path: `applyLedger` calls `applyTransactions`, parallel phases call `applySorobanStages`, workers call `InvokeHostFunctionOpFrame::doParallelApply`, `doApply` calls `addFootprint`/`addReads`, and `addReads` calls the parallel ledger access helper for each footprint key. For classic keys absent from `mThreadEntryMap`, `ThreadParallelApplyLedgerState::getLiveEntryOpt` calls `mLCLSnapshot.loadLiveEntry`, which reaches `BucketListSnapshot::load`, `getBucketEntry`, and then `InMemoryIndex::scan`. Tracy shows `InMemoryIndex::scan` as the largest self-time candidate in the current trace, and its implementation is a tiny lookup wrapper dominated by avoidable per-call allocation/virtual dispatch rather than unavoidable ledger semantics.

## Anti-Evidence

The current design explicitly avoids storing a second copy of large ledger keys in an auxiliary map, so a fix that simply duplicates all keys could increase memory enough to be unacceptable. The safer optimization is to keep the existing `unordered_set` storage layout while making query keys non-allocating, or otherwise prove that any auxiliary index is bounded to the small-bucket in-memory cutoff and does not regress memory-sensitive workloads.
