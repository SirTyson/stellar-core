# H002: Commit Soroban parallel-apply changes from dirty journals instead of rescanning clean maps

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban parallel apply commit
**Severity**: Medium
**Impact**: 3-10% apply-time reduction by reducing serial post-worker merge and final LedgerTxn commit work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After each Soroban stage finishes, Core should merge successful worker changes into the global parallel-apply state in a deterministic stage/cluster/key order, preserve `mIsNew`, restored-entry tracking, and read-only TTL max-merge semantics, and finally write exactly the dirty ledger entries to the parent `LedgerTxn`. Clean entries preloaded only to serve reads should remain available for later stages but should not be repeatedly scanned as candidate writes.

## Mechanism

The current merge path uses maps as both read caches and write journals. `commitChangesFromThreads` first rebuilds a per-stage read-write key set by scanning every transaction's RW footprint and synthesizing TTL keys, then iterates every entry in every thread map, even though many entries are clean values copied from `mGlobalEntryMap` only to satisfy reads. At phase end, `commitChangesToLedgerTxn` scans the entire global map again and filters on `mIsDirty` before writing to `LedgerTxn`.

The proposed optimization is to add explicit dirty journals: append keys when `ThreadParallelApplyLedgerState::upsertEntry`, `eraseEntry`, and read-only TTL bump flushes first dirty an entry; merge only those dirty keys back to global state; maintain a global dirty-key journal for final `commitChangesToLedgerTxn`; and precompute each stage's RW/TTL set when building `ApplyStage`/`TxBundle` data rather than rebuilding it during commit. Determinism is preserved by consuming journals in the same stage order and cluster index order currently used by `threadStates`, and read-only TTL bumps remain deterministic because their `std::max` merge is commutative and the existing write-conflict rules still route non-commuting writes into the same cluster.

## Trigger

Run the current apply-load workload `soroswap, TX=2000, T=8`. Each transaction has five RW footprint entries and several repeated RO entries; worker setup and execution keep clean read-cache entries in thread/global maps, while only a smaller subset of entries become dirty writes. The post-worker commit phase then serially rebuilds stage RW sets, scans thread maps, and scans the global map before the final `LedgerTxn` commit.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:104-132` - `getReadWriteKeysForStage` rebuilds a hash set of RW and TTL keys for every stage during commit.
- `src/transactions/ParallelApplyUtils.cpp:721-801` - `commitChangesToLedgerTxn` scans `mGlobalEntryMap`, skips clean entries, and writes dirty entries to an inner `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:821-891` - `maybeMergeRoTTLBumps` and `commitChangeFromThread` define the deterministic dirty merge rules that a journal must preserve.
- `src/transactions/ParallelApplyUtils.cpp:893-921` - `commitChangesFromThreads` serially scans every thread map after worker futures complete.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` - `collectClusterFootprintEntriesFromGlobal` preloads clean entries into thread maps for read access, increasing the amount of clean data later scanned by commit.
- `src/transactions/ParallelApplyUtils.cpp:1123-1195` - thread upsert/erase paths are the natural point to record first-dirty keys without changing ledger-entry semantics.
- `src/ledger/LedgerManagerImpl.cpp:2653-2664` and `src/ledger/LedgerManagerImpl.cpp:2706-2714` - apply timing treats thread-to-global commit and final global-to-`LedgerTxn` commit as serial subphases after worker execution.
- `src/simulation/ApplyLoad.cpp:3381-3505` - soroswap footprints repeat the same RO router/SAC/code entries and use five RW entries per swap.

## Evidence

The current diagnostic soroswap trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` reports `applyLedger` total 5,230,315,999 ns at `ledger/LedgerManagerImpl.cpp:1484`; the commit-related zones are descendants of `applySorobanStage`/`applySorobanStages`, which are called inside `applyParallelPhase`. The trace reports `commitChangesFromThreads` total 60,823,040 ns at `transactions/ParallelApplyUtils.cpp:913`, `getReadWriteKeysForStage` total 52,483,925 ns at `transactions/ParallelApplyUtils.cpp:107`, and `commitChangesToLedgerTxn` total 27,289,325 ns at `transactions/ParallelApplyUtils.cpp:724`.

The apply-load phase table from the same run shows a larger end-to-end benchmark signal for this serial region: `commit_from_thrds` median 7.65 ms and `commit_to_ltx` median 4.28 ms, for about 11.9 ms per soroswap ledger, roughly 4% of the current soroswap median apply time. This is a different scope from the prior rejected inner-`LedgerTxn` cleanup: the proposed journal targets the full dirty merge/final commit scan, the stage RW-set rebuild, and clean-map rescans rather than only removing the inner `LedgerTxn`.

## Anti-Evidence

Some of the phase time is unavoidable: dirty entries must still be moved into `LedgerTxn`, restored entries must still be recorded, and clean entries must remain queryable for later stages. A dirty journal can regress if it duplicates hash lookups, records the same key many times, or disrupts cache locality; it must record first-dirty keys compactly and preserve `mIsNew` across later overwrites. The Tracy aggregate for the narrow instrumented commit zones is smaller than the phase-table region, so a PoC must verify with repeated non-Tracy matrix runs that the whole journal design, not just a micro-optimization inside `commitChangesToLedgerTxn`, reaches the Medium threshold.
