# H002: Bulk Preload Classic Footprint Entries for Parallel Soroban Apply

**Date**: 2026-05-24
**Subsystem**: soroban-env / parallel apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing repeated per-key live BucketList lookups for classic SAC transfer footprint entries with deterministic per-cluster bulk loads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During each Soroban parallel-apply cluster, every transaction should observe the same ledger entries it observes today: modified classic entries from earlier sequential phases should still come from `GlobalParallelApplyLedgerState`, Soroban contract-data/code/TTL entries should still come from `InMemorySorobanState`, and cluster-local read/write entries should still be isolated and merged in deterministic cluster order. However, classic entries that are in the cluster footprint but absent from the global map should not be loaded one key at a time from the live BucketList snapshot when the full cluster footprint is already known before worker execution starts.

## Mechanism

`ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` currently copies only entries already present in the global map. Later, `ThreadParallelApplyLedgerState::getLiveEntryOpt` falls back to `mLCLSnapshot.loadLiveEntry(key)` for any non-Soroban key missing from the thread map, which performs a point lookup through every relevant bucket index for each account/trustline key. The soroswap workload performs high-volume SAC transfers involving classic account/trustline state; collecting the unique missing non-Soroban footprint keys for a cluster and loading them via the existing sorted `ApplyLedgerStateSnapshot::loadLiveKeys` / `SearchableBucketListSnapshot::loadKeysInternal` path would scan bucket indexes once per cluster key-set instead of repeating point lookups during transaction execution, while inserting the results into the existing thread-local map preserves deterministic merge behavior.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`TX=2000,T=8`). The apply path builds Soroban stages and clusters, constructs a `ThreadParallelApplyLedgerState` for each cluster, then SAC transfer execution reads classic account/trustline footprint entries through `ParallelLedgerAccessHelper::getLedgerEntryOpt`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:924-986` — cluster thread-state setup scans every footprint key but only copies entries already present in the global map.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — missing non-Soroban entries fall back to point `mLCLSnapshot.loadLiveEntry(key)` lookups.
- `src/transactions/ParallelApplyUtils.cpp:337-342` — `ParallelLedgerAccessHelper::getLedgerEntryOpt` exposes this lookup path to `InvokeHostFunctionOpFrame::addReads`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534` — per-transaction footprint loading calls `getLedgerEntryOpt` for TTL/data entries and serializes returned entries for the Rust host.
- `src/ledger/LedgerStateSnapshot.h:197-199` and `src/ledger/LedgerStateSnapshot.cpp:444-449` — apply snapshots already expose `loadLiveKeys`.
- `src/bucket/BucketListSnapshot.cpp:348-381` — `loadKeysInternal` bulk-loads sorted keys by scanning each bucket index once and removing shadowed hits.
- `src/bucket/BucketListSnapshot.cpp:313-345` — current point `load` path repeatedly calls `getBucketEntry` for one key at a time.

## Evidence

The current Tracy trace shows this is apply-path work, not TX-set construction: unwrap containment gives 859,746 `load` events inside `applyLedger` totaling 599,178,501 ns, plus 174,464 apply-contained `getBucketEntry` events totaling 82,154,788 ns and 325,127 apply-contained `scan` events totaling 84,957,468 ns. The source already has a deterministic bulk lookup primitive (`loadLiveKeys`) that operates on a sorted key set and returns the same live snapshot entries; using it during cluster setup targets a different path from the rejected `InMemoryIndex::scan` micro-optimization, because the goal is to replace many repeated point lookups with one cluster-level bulk load and local map insertion.

This is also distinct from the rejected shared read-only Soroban-state hypothesis: that investigation focused on copying already-preloaded Soroban read-only entries from the global map. This hypothesis targets missing non-Soroban classic account/trustline entries that still fall through to live BucketList point lookups during SAC transfer apply.

## Anti-Evidence

The full `BucketListSnapshot::load` total is an upper bound: some point loads may be for unique keys that bulk loading cannot reduce, and serializing loaded entries into Cxx buffers remains mandatory. A viable PoC must ensure bulk preloading does not introduce cross-cluster sharing of mutable classic entries, must preserve `mIsNew` and deletion semantics in `ThreadParallelApplyEntry`, and should cap work to the cluster's actual footprint so it does not increase memory pressure or exceed `NUM_CLUSTERS` parallelism.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The traced close-ledger path constructs a `ThreadParallelApplyLedgerState` for each Soroban cluster, then each transaction's `InvokeHostFunctionOpFrame` loads its footprint through `ParallelLedgerAccessHelper::getLedgerEntryOpt`. Global parallel state already captures classic entries modified by pre-parallel/sequential phases and preloads Soroban read-only entries, but unmodified classic account/trustline keys in the cluster footprint are absent from `mThreadEntryMap` and fall through to `ApplyLedgerStateSnapshot::loadLiveEntry` one key at a time. The soroswap swap generator places two classic trustline keys in every swap read-write footprint, so this point-lookup path is hot in the measured apply window. Existing `ApplyLedgerStateSnapshot::loadLiveKeys` and `SearchableBucketListSnapshot::loadKeysInternal` provide a sorted bulk-load primitive with the same shadowing semantics, making a per-cluster preload a behavior-preserving way to replace many point lookups.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:386-428` — global state is created inside `applySorobanStages` and initially reflects the LCL snapshot plus pre-parallel classic modifications.
- `src/transactions/ParallelApplyUtils.cpp:440-467` — for protocol 26+, pre-parallel apply runs first, then modified classic entries are collected into the global map.
- `src/transactions/ParallelApplyUtils.cpp:601-644` — `collectModifiedClassicEntries` scans all non-Soroban footprint keys but inserts only entries found below the `LedgerTxn` root, i.e. entries changed during earlier sequential phases; unchanged live BucketList account/trustline entries are not cached here.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — Soroban read-only entries and TTLs are preloaded separately, confirming this hypothesis targets a remaining non-Soroban gap rather than the already-reviewed shared read-only Soroban path.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — each cluster's thread state is built immediately before its async worker starts, so a preload here remains bounded by stage cluster count and does not introduce cross-cluster mutable sharing.
- `src/transactions/ParallelApplyUtils.cpp:924-986` — cluster setup scans read-write and read-only footprints and only copies entries present in `globalEntryMap`; missing classic keys are left uncached.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — `getLiveEntryOpt` checks the thread map, then uses `InMemorySorobanState` for Soroban types and `mLCLSnapshot.loadLiveEntry(key)` for everything else, producing repeated live BucketList point lookups for missing classic keys.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534` — `addReads` calls `getLedgerEntryOpt` for every live classic footprint key before building CXX buffers for the Rust host, so the lookup happens per transaction under `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-765` — after host execution, `recordStorageChanges` may write classic `ACCOUNT`/`TRUSTLINE` read-write entries in protocol 26; `mRwKeyExisted` depends on the earlier footprint read result, so preloaded entries must preserve existence and `mIsNew` semantics.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point `load` looks up one key through buckets until a hit is found.
- `src/bucket/BucketListSnapshot.cpp:203-277` and `src/bucket/BucketListSnapshot.cpp:348-381` — bulk load copies the input set, scans each bucket index in sorted order, erases found keys to avoid shadowed lower-bucket entries, and returns only live non-tombstone entries.
- `src/ledger/LedgerStateSnapshot.h:197-199` and `src/ledger/LedgerStateSnapshot.cpp:444-449` — `ApplyLedgerStateSnapshot` already exposes `loadLiveKeys`, so no new BucketList API is required.
- `src/simulation/ApplyLoad.cpp:3447-3475` — soroswap swap footprints include repeated Soroban read-only entries plus two classic trustline read-write keys per transaction; the latter are the target keys for bulk preloading.

### Findings

The inefficiency exists and is in the objective's hot path. Classic footprint reads in `addReads` are part of `InvokeHostFunctionOpFrame::doParallelApply`, which is invoked by `LedgerManagerImpl::applyThread` inside `applySorobanStageClustersInParallel` during `closeLedger`. For classic keys not already present in the global/thread maps, the current path performs a full `SearchableBucketListSnapshot::load` point lookup each time the transaction setup or commit-delta logic needs the old entry.

The proposed fix is correctness-preserving if it is implemented as a cluster-local preload of only missing non-Soroban footprint keys after copying global entries. Existing global entries must continue to win because they represent pre-parallel/sequential modifications or prior-stage dirty state. Live snapshot hits can be inserted as clean `ThreadParallelApplyEntry` values with `mIsNew=false`; if the PoC also caches live misses to avoid repeated absent-key point loads, those clean null entries must carry `mIsNew=true` so a later upsert in the same cluster is still committed as `INIT` rather than `LIVE`.

The existing bulk loader has the right shadowing semantics for live BucketList state: it iterates buckets from newest to oldest, removes keys once found, and skips tombstones while still preventing lower shadowed entries from being returned. That matches the point-load behavior needed for the LCL snapshot. The change should not alter Rust host budget accounting because the serialized footprint entries and CXX buffers delivered to `invoke_host_function` remain identical; it only changes how C++ obtains the same ledger entries before metering disk-read resources.

Impact is plausibly Medium under this objective. Unlike rejected Soroban map or host-object micro-optimizations, the cited trace isolates apply-contained live BucketList point-load work and the source shows a structural replacement from hundreds of thousands of per-key lookups to one sorted key-set load per cluster. The full `load` total remains an upper bound and must be confirmed by benchmark, but the apply-contained point-load envelope is large enough that replacing the bucket-index traversal component has a credible 3-10% apply-time ceiling.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyUtils.cpp`, primarily `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`; use `ApplyLedgerStateSnapshot::loadLiveKeys` from the thread state's `mLCLSnapshot` or equivalent cluster-local snapshot copy.
- **Change description**: While scanning the cluster footprint, first copy global entries exactly as today. For missing non-Soroban keys, collect a sorted `std::set<LedgerKey, LedgerEntryIdCmp>` of unique keys capped to the cluster footprint. Bulk-load those keys once, insert returned live entries into `mThreadEntryMap` as clean entries with `mIsNew=false`, and leave global entries untouched. Consider caching null misses only if their `mIsNew` handling is explicit and covered.
- **Correctness check**: Existing parallel Soroban apply tests and ledger-delta tests should cover `mIsNew`, classic creation/update, deletion, and deterministic merge behavior. Pay particular attention to protocol 26 classic `ACCOUNT`/`TRUSTLINE` creations from Soroban output and to failed transactions, where clean preloaded entries must not commit.
- **Benchmark focus**: Run the soroswap apply-load matrix and compare median apply time across multiple non-Tracy runs. The expected metric improvement is reduced `BucketListSnapshot::load` / `getBucketEntry` / index-scan time inside `applyLedger`, with no change in resource metering, modified ledger entries, or emitted events.
