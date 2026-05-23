# H001: Cache hot classic entries for Soroban apply

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated BucketList point loads and XDR materialization for ACCOUNT/TRUSTLINE entries used by SAC-heavy Soroban transactions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During soroswap apply, classic ACCOUNT and TRUSTLINE entries referenced by Soroban footprints should be loaded from the immutable LCL snapshot once per ledger/stage and then served from deterministic in-memory state for every pre-apply and worker access. The final ledger state, per-transaction results, and metadata should be identical to the current path: entries still begin from the LCL snapshot, worker writes are merged through `GlobalParallelApplyLedgerState`, and writeback order remains the existing deterministic transaction/stage order.

## Mechanism

The current apply path has an in-memory fast path for Soroban entries, but non-Soroban keys still fall through to BucketList snapshot point loads and LedgerTxn root cache misses. In the current soroswap trace, verified under `applyLedger`, `load` at `bucket/BucketListSnapshot.cpp:317` accounts for 233,981,556 ns / 551,218 calls in the trace, with additional classic-account helpers such as `loadAccount` at `transactions/TransactionUtils.cpp:358` accounting for 78,119,828 ns / 152,887 calls and `loadTrustLine` at `transactions/TransactionUtils.cpp:396` accounting for 14,650,847 ns / 36,000 calls. Extending the existing deterministic in-memory snapshot model to hot classic ACCOUNT/TRUSTLINE entries can remove repeated BucketList lookup and XDR copy work on the soroswap SAC path, while keeping writes serialized through the current global merge.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current soroswap workload (`soroswap-tx-2000-t-8`) and inspect the Tracy trace under `applyLedger`. Transactions that transfer SAC balances repeatedly touch user accounts and trustlines in footprints; those accesses miss `InMemorySorobanState::isInMemoryType` and reach BucketList snapshot point loads instead of a ledger-scoped hot classic cache.

## Target Code

- `src/ledger/LedgerTxn.cpp:3670-3706` — `LedgerTxnRoot::Impl::getNewestVersion` uses `InMemorySorobanState` only for Soroban in-memory types and otherwise falls back to `getLedgerStateSnapshot().loadLiveEntry(key)`.
- `src/transactions/ParallelApplyUtils.cpp:601-644` — `GlobalParallelApplyLedgerState::collectModifiedClassicEntries` discovers classic footprint keys but immediately loads each through the root LedgerTxn path.
- `src/transactions/ParallelApplyUtils.cpp:646-714` — Soroban read-only entries are explicitly preloaded into `mGlobalEntryMap`; the same stage-level preloading pattern can be applied to hot classic ACCOUNT/TRUSTLINE keys.
- `src/ledger/InMemorySorobanState.h:314` — existing deterministic in-memory state model that could be generalized or paired with a classic hot-entry cache.
- `src/bucket/BucketListSnapshot.h:170-172` and `src/ledger/LedgerStateSnapshot.cpp:438-442` — point-load API reached by classic keys not served from in-memory state.

## Evidence

The current code already treats Soroban LCL state as safe to serve from in-memory structures and already propagates preloaded read-only Soroban entries into `mGlobalEntryMap` to avoid repeated worker lookups. Soroswap is SAC-heavy, so the same ledger contains many repeated ACCOUNT/TRUSTLINE accesses from fee processing, source-account handling, and SAC balance movement. The observed `load`/`loadAccount`/`loadTrustLine` call counts are high enough that eliminating the duplicated immutable-snapshot path plausibly crosses the Medium threshold if the cache is populated once from collected footprints and updated from committed ledger changes.

## Anti-Evidence

Prior narrower ideas around source-account-only caches and BucketList point-load micro-optimizations were below threshold, so this hypothesis depends on caching the broader hot classic working set, not only fee-source accounts. The design must avoid nondeterministic worker mutation: the cache should be populated before parallel execution from a deterministic key set and writes should continue to flow through `GlobalParallelApplyLedgerState::commitChangesFromThreads` and the existing ledger transaction commit order.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related BucketList aggregate and prefetch investigations exist, but this specific classic ACCOUNT/TRUSTLINE footprint-cache proposal has not been previously reviewed
**Failed At**: reviewer

### Trace Summary

The inefficiency is real: non-Soroban footprint keys that are not already represented in `mGlobalEntryMap` fall back to `ApplyLedgerStateSnapshot::loadLiveEntry`, which delegates to `SearchableLiveBucketListSnapshot::load`. The parallel-apply setup already copies classic entries modified below root into `mGlobalEntryMap`, and it preloads Soroban read-only entries, but unchanged classic ACCOUNT/TRUSTLINE entries from the LCL remain uncached and may be point-loaded repeatedly during read-only pre-apply and worker `addReads`. However, the hypothesis's own measured ceiling is too small for this objective: `BucketListSnapshot::load` is 233,981,556 ns across the trace, while `run_apply_load_matrix.py` benchmarks 200 ledgers and recent soroswap medians are hundreds of milliseconds per ledger, so eliminating all such point-load time would be well below the 3% Medium floor.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches source accounts, processes fees/sequence numbers, then enters `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2823-2863` — transaction-data prefetch runs before apply, but `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` is empty for Soroban operations, so Soroban footprints are not batch-prefetched through the root cache.
- `src/ledger/LedgerManagerImpl.cpp:2967-3029` — parallel phases build `ApplyStage`s and enter `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:386-429` — `GlobalParallelApplyLedgerState` is created once for the parallel phase and calls `preParallelApplyAndCollectModifiedClassicEntries`.
- `src/transactions/ParallelApplyUtils.cpp:151-208, 440-467` — p26 setup checks whether classic source/footprint keys differ between current LedgerTxn state and the LCL snapshot; unchanged classic keys still require snapshot point loads during this check.
- `src/transactions/ParallelApplyUtils.cpp:601-644` — `collectModifiedClassicEntries` inserts only classic footprint keys that exist below root in the current `LedgerTxn`; unmodified LCL classic entries are intentionally not inserted into `mGlobalEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:646-714` — Soroban read-only footprint entries are preloaded into `mGlobalEntryMap`, confirming a structurally similar cache pattern exists, but it applies only to Soroban keys.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — thread state copies only entries present in `mGlobalEntryMap`; absent classic entries are not cached during cluster-state construction.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — worker `getLiveEntryOpt` returns thread-map entries when present, otherwise uses `InMemorySorobanState` for Soroban key types and `mLCLSnapshot.loadLiveEntry` for classic key types.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` calls `getLedgerEntryOpt` for every live classic footprint key before encoding it into the host input buffers.
- `src/ledger/InMemorySorobanState.cpp:146-150, 206-235` — the in-memory fast path is explicitly limited to `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL`.
- `src/ledger/LedgerStateSnapshot.cpp:438-442` and `src/bucket/BucketListSnapshot.cpp:313-346` — classic snapshot misses reach the BucketList point-load loop.

### Why It Failed

This is below the optimize-soroswap objective's Medium severity threshold. Even granting the optimistic assumption that a cache eliminates all measured `BucketListSnapshot::load` time under `applyLedger`, the cited 233.98 ms is an aggregate trace total, not a per-ledger saving; amortized over the benchmark ledgers it is far below the required 3-10% apply-time reduction. The helper zones cited for `loadAccount` and `loadTrustLine` are also wrappers around ledger-entry loading and are not independent additive savings. A PoC would still pay one deterministic preload plus `LedgerEntry` copies into global/thread maps, so the realistic improvement is smaller than the already sub-Medium ceiling.

### Lesson Learned

Classic footprint caching is architecturally plausible, but reviewer promotion for this objective needs trace evidence that the remaining uncached classic LCL loads are at least Medium-sized after amortizing aggregate Tracy time over benchmark ledgers. BucketList point-load call count alone is not enough; compare total removable nanoseconds against top-line soroswap apply time before proposing another cache.
