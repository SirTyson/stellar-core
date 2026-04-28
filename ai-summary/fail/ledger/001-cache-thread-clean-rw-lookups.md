# H001: Cache thread-local clean RW lookups during Soroban result commit

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: High
**Impact**: soroswap apply-time reduction by shortening the dominant parallel Soroban stage tail
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a parallel Soroban stage, each worker should spend most of its wall time in host execution (`TransactionFrame::parallelApply` / `InvokeHostFunctionOpFrame::doParallelApply`) and then perform only minimal, linear bookkeeping to fold each successful transaction result into its thread-local ledger state. Repeated reads of the same read-write footprint key while committing a transaction result should be served from thread-local state once the key has been looked up, without re-entering `InMemorySorobanState` or the BucketList snapshot for the same clean pre-state.

## Mechanism

`ThreadParallelApplyLedgerState::getLiveEntryOpt` returns a scoped copy from `mInMemorySorobanState.get(key)` or `mLCLSnapshot.loadLiveEntry(key)` when a key is not already in `mThreadEntryMap`, but it does not cache that clean lookup in `mThreadEntryMap`. `commitChangeFromSuccessfulTx` and `flushRemainingRoTTLBumps` call `getLiveEntryOpt` while committing Soroban results after the host has returned, so soroswap's repeated CONTRACT_DATA and TTL updates can pay repeated hash/copy/snapshot lookup costs in the worker-tail section that the apply thread waits for. Caching clean non-dirty entries or otherwise carrying the prior-existence/pre-state result through the per-tx commit path should preserve deterministic output while reducing the longest-stage tail.

## Trigger

Run the current soroswap apply-load benchmark (`TX=4000, T=8`) with Tracy enabled and inspect the largest `applySorobanStageClustersInParallel` event. The stage contains 1,458 `TransactionFrame::parallelApply` child events, but the parent remains open for about 718.8 ms after the last such child event ends, indicating substantial uninstrumented worker post-processing before the futures return. A PoC should add focused zones around `commitChangesFromSuccessfulTx`, `flushRemainingRoTTLBumps`, and `ThreadParallelApplyLedgerState::getLiveEntryOpt`, then cache clean read-write/TTL lookups in the thread map and compare repeated soroswap runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches workers and waits for each future, so worker-tail bookkeeping directly extends apply time.
- `src/ledger/LedgerManagerImpl.cpp:2498-2520` — `applyThread` calls `parallelApply`, then `commitChangesFromSuccessfulTx`, then `flushRemainingRoTTLBumps` before returning the thread state.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` loads clean misses from in-memory Soroban state or the LCL snapshot without inserting the clean result into `mThreadEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — successful tx result commit repeatedly calls `getLiveEntryOpt` for modified entries and RO TTL bumps.

## Evidence

The current soroswap Tracy trace shows `applyLedger` as an in-scope top-level zone at `ledger/LedgerManagerImpl.cpp:1484`. Inside those windows, `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` accounts for 1,700,913,221 ns over 37 calls, with a single max event of 1,663,036,113 ns. For that max event, the summed `TransactionFrame::parallelApply` child time is 4,723,469,177 ns across worker threads, but the largest per-thread sum is only 931,089,473 ns and the parent interval extends roughly 718,815,519 ns after the last `TransactionFrame::parallelApply` child event. This points to worker-side post-host bookkeeping, not host execution itself, as a large part of the stage tail.

Structurally, read-only Soroban entries were recently preloaded into the global map (`ParallelApplyUtils.cpp:646-718`), but read-write entries still fall through `ThreadParallelApplyLedgerState::getLiveEntryOpt` unless already dirty in the thread map. Soroswap swaps repeatedly mutate pool/asset CONTRACT_DATA and TTL entries, so this path is plausibly hot and the optimization is thread-local: caching a clean value in the thread map does not alter merge order, dirty-bit semantics, or ledger output.

## Anti-Evidence

Some of the 718.8 ms tail may be host work in Rust zones that do not have a `TransactionFrame::parallelApply` name, transaction meta bookkeeping, or uneven cluster execution rather than repeated `getLiveEntryOpt` misses. Also, `collectClusterFootprintEntriesFromGlobal` already preloads any key present in the global map, so this only helps keys absent from global state, primarily first-touch read-write Soroban entries and TTLs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster, launches `applyThread` with `std::async`, and waits for all futures before returning, so any worker post-processing is on the apply critical path. Each worker flushes pending RO TTL bumps for the current transaction, runs `TransactionFrame::parallelApply`, commits the returned transaction entry map into the thread map, and finally flushes remaining RO TTL bumps. `ThreadParallelApplyLedgerState::getLiveEntryOpt` does indeed load clean misses from `InMemorySorobanState` or the LCL snapshot without caching them, but successful RW commits immediately dirty-cache the key in `mThreadEntryMap`, and read-only Soroban keys and TTLs are already preloaded into the global/thread maps before execution.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` calls `flushRoTTLBumpsInTxWriteFootprint`, `TransactionFrame::parallelApply`, `commitChangesFromSuccessfulTx`, and final `flushRemainingRoTTLBumps` before returning its thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches cluster workers and synchronously waits on every future, so returned thread-state work is in scope for apply time.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — `GlobalParallelApplyLedgerState::collectModifiedClassicEntries` already preloads Soroban read-only footprint entries and associated TTLs into the global entry map.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — each thread copies only keys present in the global map into `mThreadEntryMap`; clean RW Soroban keys absent from global state can still miss through to `InMemorySorobanState` or the LCL snapshot.
- `src/transactions/ParallelApplyUtils.cpp:1004-1063` — RO TTL bump flushing loads a TTL entry only when a buffered bump must be materialized, then calls `upsertEntry`, so the TTL becomes dirty-cached after flush.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `getLiveEntryOpt` checks `mThreadEntryMap` first, then loads from `InMemorySorobanState` or `mLCLSnapshot` without inserting a clean cache entry.
- `src/transactions/ParallelApplyUtils.cpp:1123-1162` — `upsertEntry` and `eraseEntry` insert or replace the thread-map entry and preserve first-touch `mIsNew`, so successful modifications cache the key for later transactions in the same cluster.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — successful tx commit reads old state via `getLiveEntryOpt`, then either buffers RO TTL bumps or dirty-caches the modified/deleted entry in the thread map.
- `src/transactions/ParallelApplyUtils.cpp:1294-1340` — transaction-local reads fall through to the thread state when the tx map lacks the key, and transaction-local upserts are dirty in `mTxEntryMap`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-500,690-765` — Soroban apply reads footprint entries and TTLs before host execution and later upserts or erases returned write entries through `ParallelLedgerAccessHelper`.
- `src/transactions/TransactionFrame.cpp:2436-2448` and `src/transactions/TransactionMeta.cpp:384-452` — invariant delta and metadata paths may also call `getLiveEntryOpt`, but invariant checks are gated and metadata returns early when disabled.

### Why It Failed

The proposed repeated-clean-lookup mechanism is real only for first-touch clean RW keys, not for the repeated soroswap updates emphasized by the hypothesis. Once a successful transaction modifies a key, `commitChangeFromSuccessfulTx` calls `upsertEntry` or `eraseEntry`, placing a dirty entry in `mThreadEntryMap`; later transactions in the same cluster hit that map, and later stages copy dirty global entries into their thread maps. Remaining RO TTL bumps are accumulated by key and materialized once, and common read-only Soroban entries/TTLs are already preloaded. A clean-cache change could remove some duplicate first-touch loads, including the host read followed by the commit-time old-state read, but it does not plausibly explain or eliminate the cited 718 ms stage tail and is projected below the optimize-soroswap Medium threshold.

### Lesson Learned

For parallel Soroban apply optimizations, distinguish first-touch clean snapshot lookups from repeated updates after a key becomes dirty in the thread/global maps. A large apparent worker-tail gap needs focused zones before promotion; source tracing shows that this specific cache idea targets a limited subset of commit bookkeeping rather than the dominant repeated-update path.
