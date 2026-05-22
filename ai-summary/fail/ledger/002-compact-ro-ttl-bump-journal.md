# H002: Carry read-only TTL bumps as a compact max journal until materialization is required

**Date**: 2026-05-22
**Subsystem**: ledger / parallel Soroban apply
**Severity**: Medium
**Impact**: Reduce soroswap apply time by avoiding repeated full `LedgerEntry` materialization for commutative read-only TTL bumps on the parallel-apply critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Read-only TTL bumps should remain deterministic and semantically identical: bumps for the same TTL key commute by `max(liveUntilLedgerSeq)`, writes that conflict with a bumped entry must observe the bump before fee calculation, and the final ledger must contain the same TTL values and `lastModifiedLedgerSeq` as today.

## Mechanism

The current design buffers read-only TTL bumps in each `ThreadParallelApplyLedgerState::mRoTTLBumps`, but `flushRemainingRoTTLBumps` materializes each residual bump back into a full scoped `LedgerEntry` at the end of every worker. Those full entries are then merged into the global map, where `GlobalParallelApplyLedgerState::maybeMergeRoTTLBumps` often collapses duplicate TTL updates with another `std::max`. For soroswap, many transactions extend the same contract instance/code TTLs while leaving those entries otherwise read-only; carrying a compact `TTL key -> max liveUntilLedgerSeq` journal from tx to thread to global, and materializing only when a later RW footprint requires visibility or at final commit, should remove full-entry copies and old-value lookups from the stage tail.

## Trigger

Run the current soroswap apply-load benchmark with eight dependent clusters. The trigger is a stage containing many successful Soroban invokes that extend current contract instance/code TTLs without writing those TTL entries as part of the transaction's ordinary read-write state. Each worker accumulates read-only TTL bumps and then flushes them after host execution, delaying stage completion.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:29-103` — design comment describing commutative read-only TTL bumps and the current deferred-visibility semantics.
- `src/transactions/ParallelApplyUtils.cpp:1003-1039` — `flushRoTTLBumpsInTxWriteFootprint` materializes buffered bumps before a transaction writes the associated entry.
- `src/transactions/ParallelApplyUtils.cpp:1041-1064` — `flushRemainingRoTTLBumps` materializes every residual bump into full thread entries at worker shutdown.
- `src/transactions/ParallelApplyUtils.cpp:821-854` — `maybeMergeRoTTLBumps` merges already-materialized thread/global TTL entries by `std::max`.
- `src/transactions/ParallelApplyUtils.cpp:907-921` — `commitChangesFromThreads` computes the stage RW set, the natural point to decide which compact global TTL bumps must be materialized before the next stage.

## Evidence

The accepted soroswap trace shows `applySorobanStageClustersInParallel` as the dominant in-scope ledger zone at 3.427s total, while the final large stages contain long post-host tail gaps after the last `parallelApply` event (up to 450.2ms) before the stage returns. Host-level TTL extension is also hot in aggregate (`extend_current_contract_instance_and_code_ttl` appears 27,942 times, 634.0ms total inside apply windows), confirming that the workload repeatedly performs TTL bump work on the apply path. The ledger code already treats read-only TTL bumps as commutative max operations, but it materializes them as full `LedgerEntry` objects per worker before the global max merge.

A viable design would keep `mRoTTLBumps` compact across worker return, merge compact maps deterministically by key order / `max`, and only call `getLiveEntryOpt` plus `upsertEntry` for keys that are in the next stage's RW set or at final ledger commit. This does not exceed `NUM_CLUSTERS` parallelism and preserves observable order because the only delayed effects are the same commutative RO TTL bumps the current design already defers.

## Anti-Evidence

Previous narrow TTL-bump ideas were below threshold when they targeted host-side SAC TTL extension or empty-loop fast paths. This hypothesis depends on the stage-tail Tracy gaps being materially caused by C++ TTL-bump materialization rather than by dirty-map movement, allocator teardown, or scheduler noise. It also needs careful proof that delaying materialization across a stage boundary is safe only for TTL keys whose associated live entry is not in the next stage's RW footprint.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record covers this exact residual RO-TTL compact-global-journal mechanism
**Failed At**: reviewer

### Trace Summary

The residual RO-TTL mechanism exists: successful tx commits classify TTL changes from read-only Soroban footprint entries into `mRoTTLBumps`, flush conflicting bumps before a later write in the same cluster, and flush remaining bumps into full thread entries when the worker exits. However, the existing implementation is already compact per thread (`TTL key -> max liveUntilLedgerSeq`) and only materializes each residual key once per worker, not once per transaction. The later global merge already deduplicates into a single global entry per TTL key, so final `LedgerTxn` commit cardinality does not improve. The proposed cross-stage compact journal would remove only a small worker-tail/global-merge subset and cannot support the objective's required 3%+ apply-time reduction.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:29-103` — documents the correctness rule: RO TTL bumps commute by max, but must become visible before writes whose fee/result can observe TTL state.
- `src/transactions/ParallelApplyUtils.cpp:238-265` — `buildRoTTLSet` derives read-only TTL keys per tx, and `updateMaxOfRoTTLBump` already stores compact per-thread max TTL values.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — global setup preloads read-only Soroban entries and associated TTL entries once into `mGlobalEntryMap`; workers normally copy from this map rather than repeatedly loading old TTL values from the snapshot.
- `src/transactions/ParallelApplyUtils.cpp:970-1000` — each thread preloads the cluster footprint and TTL entries from the global map before execution, so residual TTL flushes generally update existing scoped thread entries.
- `src/ledger/LedgerManagerImpl.cpp:2490-2518` — `applyThread` flushes interfering RO-TTL bumps before each tx, applies the tx, commits successful tx changes, then flushes residual RO-TTL bumps once at worker shutdown.
- `src/transactions/ParallelApplyUtils.cpp:1003-1064` — `flushRoTTLBumpsInTxWriteFootprint` is mandatory for correctness before same-cluster writes; `flushRemainingRoTTLBumps` materializes only the leftover compact map entries.
- `src/transactions/ParallelApplyUtils.cpp:821-889` — global merge performs `std::max` for materialized TTL entries when the key is not in the stage RW set and marks the single global entry dirty.
- `src/ledger/LedgerManagerImpl.cpp:2635-2664` — `applySorobanStage` waits for worker futures, then serially commits thread changes; stage wrapper time includes slowest-worker waits and unrelated tail work.
- `src/ledger/LedgerManagerImpl.cpp:2701-2709` — all stages share one global state, and only the final dirty global entries are committed to the parent `LedgerTxn`.

### Why It Failed

The optimization target is real but below the optimize-soroswap Medium severity threshold. It does not eliminate host-side TTL extension work, per-tx RO-TTL classification, mandatory same-cluster flushes before writes, worker synchronization, thread-state destruction, or final dirty-entry commit. It only replaces per-worker residual TTL materialization and subsequent global `std::max` merges for keys that remain read-only across stage boundaries; those operations are bounded by unique residual TTL keys per cluster/stage and are parallel-worker tail work that must be normalized by the configured eight clusters. Prior ledger fail summaries already show adjacent TTL-bump and parallel-apply commit subsets are sub-threshold, and this hypothesis targets an even narrower subset of those costs. Because Low-severity optimizations are rejected for this objective, the finding is not viable.

### Lesson Learned

RO-TTL bump hypotheses must separate host-side TTL extension, per-tx classification, mandatory write-visibility flushes, residual worker flushes, and global commit work. The residual compact-journal idea is correctness-plausible, but performance projections must be based on unique TTL keys times clusters/stages, then divided by cluster parallelism, rather than inferred from aggregate host TTL zones or broad post-host stage gaps.
