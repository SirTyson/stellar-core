# H001: Parallel Commit of Thread Apply State Into Global State

**Date**: 2026-05-21
**Subsystem**: transactions
**Severity**: Medium
**Impact**: apply-time reduction in post-worker Soroban parallel apply commit, strongest on max-sac
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After every Soroban apply stage, dirty entries from independent cluster thread states should be merged back into `GlobalParallelApplyLedgerState` without making the main apply thread perform all key-set construction and all per-thread entry merges serially. The resulting global entry map, restored-entry sets, and read-only TTL bump maxima should be identical to the current serial merge for the same `ApplyStage`.

## Mechanism

`GlobalParallelApplyLedgerState::commitChangesFromThreads` currently builds the stage read-write key set and then calls `commitChangesFromThread` for every thread state in a serial loop. The max-sac Tracy trace shows this apply-descendant region as a Medium-sized serial slice: total `commitChangesFromThreads` at `transactions/ParallelApplyUtils.cpp:913` is 108,664,602 ns across 28 apply windows, with `getReadWriteKeysForStage` at line 107 contributing 38,066,612 ns and `commitChangesFromThread` at line 898 contributing 43,495,098 ns. Because clusters in the same stage are independent except for commutative RO TTL max merges, the merge can be sharded across at most `ledgerMaxDependentTxClusters` / `LEDGER_CLOSE_WORKER_THREADS` workers into deterministic temporary shards, then installed in a fixed key/thread order.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the current max-sac scenario (`sac, TX=6000, T=8`) and inspect the apply-descendant zones. The issue is triggered by stages with many dirty per-thread entries after parallel SAC transfers; the main thread waits for workers, then serially constructs the stage RW key set and folds each thread map into the global map before moving to the final LedgerTxn commit.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:getReadWriteKeysForStage:104-132` — serial rebuild of all stage RW and TTL keys.
- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState::commitChangesFromThreads:908-921` — serial fold over all thread states.
- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState::commitChangeFromThread:857-905` — per-entry dirty filtering, RO TTL max merge, and restored-entry aggregation.
- `src/ledger/LedgerManagerImpl.cpp:LedgerManagerImpl::applySorobanStage:2653-2664` — apply-stage barrier where this merge is on the critical path.

## Evidence

The SAC trace confirms these zones are inside the measured apply path: `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` totals 2,722,490,387 ns, `applySorobanStage` totals 1,442,717,000 ns, and `commitChangesFromThreads` is called directly from `applySorobanStage` after `applySorobanStageClustersInParallel`. A perfect removal of the current serial merge region is about 4.0% of max-sac `applyLedger`, so a bounded parallel deterministic merge that removes most of the key-set construction and per-thread fold has Medium-tier headroom. Soroswap shows a smaller but same-shaped region (`commitChangesFromThreads` total 60,823,040 ns, `getReadWriteKeysForStage` self 30,727,987 ns), so the change should not be max-sac-only.

## Anti-Evidence

The merge mutates `mGlobalEntryMap`, which is not currently thread-safe, and RO TTL bumps require exact `max` semantics when multiple clusters touch the same TTL key read-only. A viable implementation must avoid concurrent writes to the global map directly, must not exceed configured cluster parallelism, and must perform a deterministic reduce so ledger output and meta remain independent of OS scheduling.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`LedgerManagerImpl::applySorobanStages` constructs one `GlobalParallelApplyLedgerState`, applies each Soroban stage, and only commits the accumulated global state to the `LedgerTxn` after all stages complete. Within each `applySorobanStage`, worker execution finishes first in `applySorobanStageClustersInParallel`; then the apply thread synchronously calls `checkAllTxBundleInvariants`, `GlobalParallelApplyLedgerState::commitChangesFromThreads`, and only after that destroys the returned thread states. `commitChangesFromThreads` builds the stage RW/TTL key set serially and then serially folds every `ThreadParallelApplyLedgerState` entry map into `mGlobalEntryMap`, so the cited work is on the apply critical path rather than a worker-aggregate zone.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` starts one async worker per stage cluster and returns thread states in cluster order after all futures complete.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` waits for workers, runs invariant checks, then synchronously calls `globalParState.commitChangesFromThreads` before clearing thread states.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` executes stages sequentially and writes the global parallel state to `LedgerTxn` only after all stage merges are complete.
- `src/transactions/ParallelApplyUtils.cpp:104-132` — `getReadWriteKeysForStage` serially scans every tx in the stage and inserts each RW key plus Soroban TTL key into an unordered set.
- `src/transactions/ParallelApplyUtils.cpp:857-921` — `commitChangeFromThread`, `commitChangesFromThread`, and `commitChangesFromThreads` serially deactivate each thread scope, filter dirty entries, rescope entries into global scope, merge RO TTL bumps by `max`, add restored entries, and update `mGlobalEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — each thread state copies prior global restored entries and preloads cluster footprint entries from global state before worker execution.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — successful tx results update only the owning thread state; RO TTL bumps are accumulated separately and restored-entry sets are added to the thread state.
- `src/ledger/LedgerTxn.cpp:254-288` — `RestoredEntries::addRestoresFrom` asserts disjoint restores, matching the stage-clustering invariant that restore writes cannot overlap across thread states.
- `src/herder/ParallelTxSetBuilder.cpp:400-426` and `src/herder/TxSetFrame.cpp:2328-2340` — parallel stages contain data-independent clusters and enforce the `ledgerMaxDependentTxClusters` cap.

### Findings

The inefficiency exists: after parallel Soroban workers finish, `commitChangesFromThreads` performs both stage RW-key construction and all thread-state merging on the apply thread. This is a hot path for the objective because it is called once per Soroban stage inside `applySorobanStage`, which is inside `applySorobanStages` and therefore inside ledger apply.

The correctness model supports a parallel reduce if it is implemented carefully. Stage clusters are constructed to be independent except for read-only TTL bumps, which are already handled with commutative `max` semantics in `maybeMergeRoTTLBumps`; restored entries should be disjoint across thread states and the existing `RestoredEntries::addRestoresFrom` asserts that invariant. A correct implementation must not concurrently mutate `mGlobalEntryMap`; it should build per-worker temporary dirty-entry / RO-TTL / restore shards, then perform a deterministic final reduce and installation.

The impact is plausibly Medium for max-sac and worth a PoC under this objective. Unlike worker-internal zones, this region is not divided by the cluster count: it runs after the worker barrier on the apply thread. The cited max-sac bound is about 4.0% of `applyLedger`; a PoC must prove that enough of the 38 ms key-set construction plus 43 ms per-thread fold can move off the serial path to clear the 3% objective floor. The same shape appears in soroswap, though the soroswap-only headroom may be smaller.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyUtils.cpp:getReadWriteKeysForStage`, `GlobalParallelApplyLedgerState::commitChangesFromThreads`, `commitChangesFromThread`, and any small helper types needed near those functions; call site remains `src/ledger/LedgerManagerImpl.cpp:applySorobanStage`.
- **Change description**: Build stage RW/TTL key sets and per-thread dirty merge shards in bounded worker tasks, capped by `min(stage.numClusters(), ledgerMaxDependentTxClusters, LEDGER_CLOSE_WORKER_THREADS)` or the existing cluster count. Do not write `mGlobalEntryMap` concurrently. Reduce RO TTL bumps with exact `max`, preserve first-stage `mIsNew`, add restored entries with the existing disjointness assertions, and install final results in a deterministic order independent of worker completion.
- **Correctness check**: Existing parallel Soroban apply tests and invariant checks should cover ledger/meta equivalence; add focused tests only if the implementation introduces new helper behavior for RO TTL merging or deterministic shard reduction. Preserve the current thread-state scope deactivation/adoption rules when moving entries between `ThreadParApply` and `GlobalParApply` scopes.
- **Benchmark focus**: Measure `scripts/run_apply_load_matrix.py` non-Tracy apply time across repeated max-sac and soroswap runs, and use Tracy only to confirm that `commitChangesFromThreads`, `getReadWriteKeysForStage`, and per-thread fold self-time moved off the apply-thread serial region. The PoC should target at least a reproducible 3% max-sac apply-time reduction to remain Medium.
