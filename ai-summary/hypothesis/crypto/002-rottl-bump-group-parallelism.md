# H002: Parallelize Read-Only TTL-Bump Groups Inside Soroswap Clusters

**Date**: 2026-05-25
**Subsystem**: crypto / ledger / transactions / Soroban parallel apply
**Severity**: Medium
**Impact**: reduce soroswap apply time by parallelizing commutative read-only TTL-bump groups currently serialized within clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Read-only TTL bumps for the same Soroban ledger entry should continue to merge by `max(liveUntilLedgerSeq)` and preserve the same final TTL, fees, transaction results, events, metadata, and ledger-entry order as the current serial cluster execution. Writes to the same entry remain synchronization barriers: all read-only TTL bumps before a write must be flushed before that write, and all bumps after the write must observe the post-write state. Parallelism must be deterministic and capped by `NUM_CLUSTERS`.

## Mechanism

The parallel-apply code already treats read-only TTL bumps as commutative pseudo-writes and buffers them in `mRoTTLBumps`, but `LedgerManagerImpl::applyThread` still executes every transaction in the cluster one by one. The long comment in `ParallelApplyUtils.cpp` says future cores may schedule non-conflicting groups of `RoTTLBump(LE)` operations around individual writes; the current implementation defers visibility but does not exploit that parallelism. For soroswap, many transactions touch shared contract/pool/SAC instance TTLs read-only while only a subset write the associated entries, so contiguous read-only TTL-bump groups can run concurrently and merge their TTL bumps deterministically before the next write barrier.

## Trigger

Run the current accepted soroswap apply-load trace and timestamp-filter descendants of `applyLedger`. The current diagnostic trace shows `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` consuming 2.752707259 s over 43 stage executions, while individual `parallelApply` calls are executed in cluster-local serial loops. The concrete trigger is a cluster containing multiple transactions whose read-only footprints bump the same TTL keys and whose read-write footprints do not require those transactions to observe one another until a later writer to the same ledger entry.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:42-102` — design note describes read-only TTL bumps as commutative and explicitly mentions future scheduling of non-conflicting groups around write barriers.
- `src/transactions/ParallelApplyUtils.cpp:238-251` — `buildRoTTLSet` identifies read-only TTL keys for one transaction.
- `src/transactions/ParallelApplyUtils.cpp:1003-1038` — `flushRoTTLBumpsInTxWriteFootprint` flushes buffered read-only TTL bumps before a transaction writes the corresponding entry.
- `src/transactions/ParallelApplyUtils.cpp:1041-1064` — `flushRemainingRoTTLBumps` merges residual read-only TTL bumps at cluster end.
- `src/ledger/LedgerManagerImpl.cpp:2490-2518` — the current `applyThread` loop runs all transactions in a cluster serially despite the commutative TTL-bump design.

## Evidence

This path is an `applyLedger` descendant and is not one of the out-of-scope TX-set construction zones. The existing implementation already has the core deterministic merge operation (`max`) and explicitly avoids constraining future schedulers to a total order within read-only TTL-bump groups. A targeted scheduler that detects runs of transactions with only commutative RO TTL interactions can be much smaller than a full intra-cluster DAG scheduler: run the group in parallel, merge per-worker `mRoTTLBumps` by key using `max`, then flush before the next write barrier in the same order the current serial loop would have made the group visible.

## Anti-Evidence

The hypothesis depends on soroswap clusters having meaningful read-only TTL-bump group width. If most clustered transactions write the same pool/balance keys, or if fee semantics require each transaction to observe a previous bump rather than the deliberately deferred state, groups may collapse to width one. The PoC must add counters for group sizes, barrier frequency, and per-group wall time, and must verify fees and metadata against the existing serial path because the comment notes that deferred TTL visibility can intentionally charge slightly higher fees than a fully serial visibility model.
