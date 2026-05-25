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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/crypto/001-deterministic-intracluster-scheduler.md`
**Failed At**: reviewer

### Trace Summary

The traced apply path is the same serialization surface already reviewed in `001-deterministic-intracluster-scheduler`: `applySorobanStageClustersInParallel` launches one worker per final cluster, and each worker calls `applyThread`, which walks the cluster in a serial loop. The RO-TTL mechanism is also the same one covered by the prior record: `commitChangesFromSuccessfulTx` buffers read-only TTL bumps in `mRoTTLBumps`, `flushRoTTLBumpsInTxWriteFootprint` makes them visible before conflicting writes, and `flushRemainingRoTTLBumps` merges residual bumps at cluster end. The prior investigation explicitly examined the RO-TTL partial-order comment and attempted a bounded intra-cluster/stage scheduler; final review rejected it after benchmark runs showed consistent soroswap and max-sac regressions.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:42-102` — documents the exact RO-TTL partial-order scheduling opportunity cited here, including future scheduling of non-conflicting RO-TTL groups around write barriers.
- `src/transactions/ParallelApplyUtils.cpp:238-251` — `buildRoTTLSet` derives TTL keys from read-only Soroban footprint entries.
- `src/transactions/ParallelApplyUtils.cpp:1003-1064` — buffered RO-TTL bumps are flushed before a transaction writes the corresponding entry and at cluster end.
- `src/transactions/ParallelApplyUtils.cpp:1240-1251` — successful transaction changes are classified against the read-only TTL set and accumulated through `mRoTTLBumps`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies each `TxBundle` serially, flushing RO-TTL barriers and committing successful changes before the next transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` treats each final cluster as an indivisible async task.
- `src/herder/TxSetFrame.h:281-295` and `src/herder/ParallelTxSetBuilder.cpp:577-697` — cluster semantics and footprint conflict construction match the broader scheduler hypothesis previously reviewed.
- `ai-summary/fail/crypto/001-deterministic-intracluster-scheduler.md:43-86` — prior review marked the broader deterministic intra-cluster scheduler viable and explicitly included RO-TTL partial-order semantics in the analyzed code paths and PoC guidance.
- `ai-summary/fail/crypto/001-deterministic-intracluster-scheduler.md:244-271` — final review rejected the scheduler attempt because repeated non-Tracy benchmark runs showed no improvement and a 9.87% average soroswap regression.

### Why It Failed

This is a substantially equivalent subset of the already-investigated deterministic intra-cluster scheduler. The earlier hypothesis covered the same `applyThread` serial loop, the same final-cluster indivisibility in `applySorobanStageClustersInParallel`, the same footprint-conflict basis, and the same RO-TTL partial-order constraints; it even directed the PoC to preserve RO-TTL bump flush semantics. Narrowing the scheduler to contiguous RO-TTL groups does not make the review novel, and this file provides no new benchmark evidence showing that the narrower TTL-only version avoids the prior scheduler overhead or clears the objective's Medium threshold.

### Lesson Learned

Specialized RO-TTL group parallelism should be treated as a refinement of the existing intra-cluster scheduler investigation, not a new crypto hypothesis. Any future attempt must reference `001-deterministic-intracluster-scheduler.md` directly and bring new measurements proving that a narrower TTL-only scheduler has exploitable group width and avoids the already-observed benchmark regression.
