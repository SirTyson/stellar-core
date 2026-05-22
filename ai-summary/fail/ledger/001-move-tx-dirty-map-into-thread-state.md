# H001: Move successful tx dirty maps into thread state without second-pass old-entry lookups

**Date**: 2026-05-22
**Subsystem**: ledger / parallel Soroban apply
**Severity**: High
**Impact**: Reduce soroswap apply time by shrinking the dominant `applySorobanStageClustersInParallel` critical path after each host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban transaction, Core should make the host-produced modified entries visible to the next transaction in the same cluster with the minimum deterministic work required: preserve the transaction order inside the cluster, preserve old/new entry classification for metadata and final commit, and avoid re-reading or re-copying entries whose pre-state was already observed during transaction application.

## Mechanism

The current parallel worker returns a `ParallelTxSuccessVal` from `parallelApply`, then performs a second C++ merge pass in `ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx`. That pass rebuilds the read-only TTL set, iterates every modified entry, calls `getLiveEntryOpt` to recover the old value/existence, re-adopts the scoped entry from tx scope to thread scope, and then upserts or erases in the thread map. In the current soroswap trace, `applySorobanStageClustersInParallel` totals 3.427s under `applyLedger`; unwrap analysis shows large stage-tail gaps after the last `parallelApply` event and before the stage future returns (52.6ms, 130.2ms, 256.0ms, 332.1ms, 385.5ms, and 450.2ms on the final large stages), which points at this uninstrumented post-invocation merge path rather than Rust host execution.

## Trigger

Run the soroswap apply-load benchmark at the current baseline (`TX=2000`, `T=8`). The issue is triggered by successful invoke-host-function transactions that write Soroswap pool/token entries and TTLs: each transaction first records modified entries into `TxParallelApplyLedgerState::mTxEntryMap` during `recordStorageChanges`, then pays a second per-entry merge cost before the next transaction in the same cluster can observe those writes.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` invokes `parallelApply`, then synchronously calls `threadState->commitChangesFromSuccessfulTx` before continuing the cluster.
- `src/transactions/ParallelApplyUtils.cpp:1164-1195` — `ThreadParallelApplyLedgerState::commitChangeFromSuccessfulTx` calls `getLiveEntryOpt` for each modified key to recompute old-entry presence and then upserts/erases in the thread map.
- `src/transactions/ParallelApplyUtils.cpp:1241-1251` — `ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx` rebuilds `roTTLSet` and copies each tx-scoped modified entry into thread scope.
- `src/transactions/ParallelApplyUtils.cpp:1392-1401` — `TxParallelApplyLedgerState::takeResult` currently moves the tx map into an intermediate result instead of committing or annotating it with pre-state information.

## Evidence

The current accepted trace reports `applyLedger` at 5.075s total and `applySorobanStageClustersInParallel` at 3.427s total. For the largest soroswap stages, host invocation work does not explain the full stage wall time: stage #42 has only 109 `InvokeHostFunctionOpFrame doParallelApply` events with a max per-worker host total of about 25.6ms, but the stage window remains open for about 490ms and has a 450ms gap after the last `parallelApply` event. The unzoned code immediately after `parallelApply` in `applyThread` is the successful-tx merge and remaining TTL flush path, making the dirty-map merge a plausible High-impact target.

A concrete implementation direction is to record old-entry existence and RO-TTL classification while `TxParallelApplyLedgerState::upsertEntry` / `eraseEntryIfExists` are called, then move dirty entries directly into the thread map on success without calling `getLiveEntryOpt` again for every key. This preserves cluster transaction order and does not add parallelism, so determinism is unchanged.

## Anti-Evidence

The tail attribution is inferred from Tracy gaps because `commitChangesFromSuccessfulTx` is not currently instrumented. A PoC should first add temporary zones or counters to separate dirty-map movement from RO-TTL flushing and thread teardown. Some old-entry lookups are semantically necessary for create-vs-update and RO-TTL bump decisions; the optimization is only viable if that metadata can be captured during the first touch without changing rollback behavior on failed host invocations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact per-success tx merge mechanism
**Failed At**: reviewer

### Trace Summary

The claimed code path is real: `LedgerManagerImpl::applyThread` runs each cluster transaction sequentially, calls `parallelApply`, and on success immediately merges the returned `ParallelTxSuccessVal` into the cluster-local thread state. That merge builds a per-tx RO-TTL set, rescopes each dirty tx entry, and calls `ThreadParallelApplyLedgerState::getLiveEntryOpt` to recover old-entry presence before updating `mThreadEntryMap` or `mRoTTLBumps`. However, this is small per-modified-entry bookkeeping inside already-parallel worker execution; the cited wrapper gaps do not isolate this work and can only bound a mixture of final-tx merge, remaining RO-TTL flushes, metadata/invariant-disabled scaffolding, and slowest-worker wait behavior.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` executes each transaction in cluster order, flushes interfering RO-TTL bumps, calls `parallelApply`, commits successful tx changes, then flushes remaining RO-TTL bumps before returning the thread state.
- `src/ledger/LedgerManagerImpl.cpp:2531-2575` — `applySorobanStageClustersInParallel` launches one future per cluster and waits for all futures; its wall time includes worker execution and slowest-worker waits, not just post-host merge work.
- `src/transactions/TransactionFrame.cpp:2428-2448` — `parallelApply` wraps operation apply and only builds invariant deltas when invariant checks are enabled; metadata change construction is called but returns immediately when metadata is disabled.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1030,1358-1377` — `InvokeHostFunctionOpFrame doParallelApply` includes footprint reads, host invocation, storage-change recording, event/refund processing, success finalization, and `takeResult`; it does not include the later thread-state commit.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-765` — `recordStorageChanges` decodes modified entries, tracks RW-footprint coverage and creation state with `mRwKeyExisted`, writes through the ledger-access helper, and erases absent RW entries.
- `src/transactions/ParallelApplyUtils.cpp:1003-1064` — RO-TTL bumps are deferred in `mRoTTLBumps` and flushed before conflicting writes or at cluster end, so tail time after the last operation is not attributable solely to dirty-map movement.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` first checks `mThreadEntryMap`; only missing keys fall back to `InMemorySorobanState` or the LCL snapshot and copy the entry into a scoped optional.
- `src/transactions/ParallelApplyUtils.cpp:1164-1251` — `commitChangesFromSuccessfulTx` rebuilds `roTTLSet`, rescopes tx dirty entries, rereads old state with `getLiveEntryOpt`, and records either a dirty upsert/delete or an RO-TTL max bump.
- `src/transactions/ParallelApplyUtils.cpp:1294-1401` — `TxParallelApplyLedgerState` records tx-local upserts/deletes and moves the tx dirty map into `ParallelTxSuccessVal` only on success, preserving rollback isolation on failure.

### Why It Failed

The inefficiency exists but does not meet the optimize-soroswap Medium threshold. The proposed change can remove some duplicate old-state lookups and rescoping in `commitChangesFromSuccessfulTx`, but it cannot remove the host output decode, storage-change recording, metadata/invariant semantics, RO-TTL flush correctness, cluster ordering, or final thread/global/LedgerTxn commits. For soroswap, repeated conflicting swaps in a cluster quickly populate `mThreadEntryMap`, so most later old-state checks are thread-map probes rather than fresh `InMemorySorobanState`/snapshot loads. The reported `applySorobanStageClustersInParallel` and end-of-stage gaps are wrapper/wait timings and do not isolate enough eliminable dirty-map work to support a 3%+ top-line apply-time projection.

### Lesson Learned

For parallel Soroban worker optimizations, trace and measure the exact child work before projecting from `applySorobanStageClustersInParallel` gaps. Wrapper wall time and post-host tail gaps are dominated by worker scheduling, slowest-cluster completion, mandatory TTL flushing, and other per-tx semantics unless a dedicated span proves the specific eliminable map-merge work is large enough after NUM_CLUSTERS normalization.
