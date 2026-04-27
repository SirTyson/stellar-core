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

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed allocation exists exactly on the lookup path: `InMemoryBucketState::scan` constructs a temporary `InternalInMemoryBucketEntry(searchKey)`, whose constructor heap-allocates a polymorphic `QueryKey`, before every `unordered_set::find`. The path is reachable from parallel Soroban apply through `InvokeHostFunctionOpFrame::addReads` and `ParallelLedgerAccessHelper::getLedgerEntryOpt`; classic footprint entries that are not modified in the current ledger are not preloaded into the thread/global maps and fall through to the LCL live BucketList snapshot. For small live buckets, `LiveBucketIndex` deliberately uses `InMemoryIndex`, so `BucketListSnapshot::load` reaches the allocating `scan` path once per bucket probe. Existing preloads and caches do not eliminate this waste for unmodified classic live-snapshot lookups.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` runs each Soroban cluster transaction and calls `TransactionFrame::parallelApply`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` and `src/ledger/LedgerManagerImpl.cpp:2672-3029` — parallel Soroban stages construct `ThreadParallelApplyLedgerState` objects, launch worker threads, and execute the stage inside ledger apply.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:175-188` — parallel apply dispatches the single Soroban operation to `InvokeHostFunctionOpFrame::doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — the helper's `apply()` calls `addFootprint()` before invoking the Rust host; the parallel op constructs that helper and returns its result.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:381-535` — `addReads` iterates every footprint key and calls `getLedgerEntryOpt(lk)` for classic keys and live Soroban keys before serializing any found entries.
- `src/transactions/ParallelApplyUtils.cpp:337-342` and `src/transactions/ParallelApplyUtils.cpp:1084-1120` — `ParallelLedgerAccessHelper::getLedgerEntryOpt` delegates to `ThreadParallelApplyLedgerState::getLiveEntryOpt`, which falls through to `mLCLSnapshot.loadLiveEntry(key)` for non-Soroban keys missing from `mThreadEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:386-428`, `src/transactions/ParallelApplyUtils.cpp:470-523`, and `src/transactions/ParallelApplyUtils.cpp:925-1000` — global/thread preloading only copies entries already modified below the LedgerTxn root, plus selected Soroban read-only entries; unmodified classic footprint entries can still be fetched from the live snapshot during `addReads`.
- `src/ledger/LedgerStateSnapshot.cpp:438-442` — `loadLiveEntry` delegates to the searchable live BucketList snapshot.
- `src/bucket/BucketListSnapshot.cpp:170-201` and `src/bucket/BucketListSnapshot.cpp:313-345` — snapshot point lookup loops buckets and calls each bucket's index lookup until a hit or exhaustion.
- `src/bucket/LiveBucketIndex.cpp:28-60` and `src/bucket/LiveBucketIndex.cpp:223-239` — live buckets below `BUCKETLIST_DB_INDEX_CUTOFF` use `InMemoryIndex`; their lookup calls `InMemoryIndex::scan`.
- `src/bucket/InMemoryIndex.h:26-133` and `src/bucket/InMemoryIndex.cpp:63-76` — `InternalInMemoryBucketEntry` stores `ValueEntry`/`QueryKey` behind `std::unique_ptr<AbstractEntry>`; `scan` constructs the query wrapper on every lookup and then calls `mEntries.find`.
- `src/util/types.h:146-159` and `src/ledger/LedgerHashUtils.h:136-202` — stored bucket entries currently materialize a `LedgerKey` for hash/equality, and lookup hashing must remain semantically identical to `std::hash<LedgerKey>`.

### Findings

The inefficiency is real: every in-memory bucket lookup allocates a `QueryKey`, copies the searched `LedgerKey` into it, dispatches through virtual `hash`/`operator==`, and destroys the allocation immediately after `find`. This is not amortized by a pool or cache, and the comment in `InMemoryIndex.h` explicitly notes that heterogeneous lookup would simplify the class once the project can use C++20.

The path is hot for this objective. `BucketListSnapshot::load` is part of `closeLedger` during parallel Soroban apply, and the supplied trace shows `InMemoryBucketState::scan` at roughly 3.14 seconds self-time over 1.45 million calls. The current global/thread map preloading avoids some repeated reads, but it intentionally does not preload unmodified classic entries from the root snapshot, so those reads still probe the BucketList snapshot from `addReads`.

The proposed direction is correctness-preserving if it only changes the lookup wrapper representation. A stack-only query view or tagged `std::variant`/manual union can keep the same `std::unordered_set<InternalInMemoryBucketEntry, InternalInMemoryBucketEntryHash>` storage and return the same `IndexReturnT` results, while avoiding per-query heap allocation and virtual dispatch. The fix should not introduce a second full key map unless memory impact is explicitly measured, because the existing index design avoids duplicating large ledger keys.

Severity is Medium rather than High. The trace makes this a credible 3-10% apply-time candidate if allocation/dispatch dominates the `scan` body, but the fix will not remove the entire `BucketListSnapshot::load` cost because hashing, bucket iteration, and result copying remain.

### PoC Guidance

- **Target code**: `src/bucket/InMemoryIndex.h` and `src/bucket/InMemoryIndex.cpp`, especially `InternalInMemoryBucketEntry`, `InternalInMemoryBucketEntryHash`, and `InMemoryBucketState::scan`.
- **Change description**: Replace `std::unique_ptr<AbstractEntry>` plus `ValueEntry`/`QueryKey` polymorphism with a non-allocating representation. A safe shape is an entry object tagged as either stored value (`IndexPtrT`) or query view (`LedgerKey const*` valid only for the `find` call), with `hash()` and equality dispatching via `switch`/helpers rather than virtual calls. Preserve the existing set storage layout and the `get()` behavior for stored entries; query entries must never be returned from the set.
- **Correctness check**: Existing bucket-index coverage should still pass, especially `src/bucket/test/BucketIndexTests.cpp` point-lookup and in-memory-index cases, plus `src/bucket/test/BucketListTests.cpp` snapshot lookup coverage. Soroban parallel apply behavior is covered through existing invoke-host-function and parallel apply tests that exercise footprint loading.
- **Benchmark focus**: Measure allocation count and self-time in `InMemoryBucketState::scan`, then run the soroswap apply-load matrix repeatedly. The expected improvement is reduced scan self-time and a 3-10% reduction in top-line soroswap apply time if the allocator/virtual wrapper is indeed the dominant component of the observed scan cost.
