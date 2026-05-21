# H001: Replace Soroban Stage Barriers with a Deterministic Dependency DAG Scheduler

**Date**: 2026-05-21
**Subsystem**: transactions / ledger apply
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring the dominant parallel-apply wait phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply should preserve the transaction-set dependency semantics while keeping up to `ledgerMaxDependentTxClusters()` workers busy whenever a cluster's true read-write predecessors have completed. A cluster in a later XDR stage that is independent of some slow cluster in the previous stage should not have to wait for that unrelated slow cluster; it should be eligible to run as soon as every cluster it actually conflicts with has committed its thread-local state. Final ledger state, transaction results, metadata order, and fee/refund accounting should remain identical to the current stage-by-stage execution.

## Mechanism

`LedgerManagerImpl::applySorobanStages` currently applies every `ApplyStage` as a hard barrier: `applySorobanStageClustersInParallel` launches all clusters in one stage, waits for every future, then `commitChangesFromThreads` merges the whole stage before the next stage begins. The current soroswap trace shows `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with **3,455,290,270 ns self-time across 43 calls**, and timestamp unwrapping confirmed all 43 events are inside `applyLedger`; this "self-time" is the main thread waiting on worker completion and stage barriers. A deterministic dependency DAG built from cluster read-write footprints could pipeline independent later-stage clusters behind only their real predecessor clusters, reducing barrier idle while retaining the configured worker cap and deterministic merge order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on a ledger whose parallel Soroban phase has uneven cluster runtimes across multiple stages. The current executor waits for the slowest cluster in each stage before starting any cluster in the next stage, even if a next-stage cluster's footprint conflicts with only a completed predecessor. A PoC should replay the same `TxStageFrameList`, build a deterministic cluster conflict DAG from the existing `SorobanResources` footprints, and schedule ready clusters through at most `ledgerMaxDependentTxClusters()` workers.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one async task per cluster and waits for the whole stage.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` checks invariants and commits a whole stage only after all clusters complete.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` iterates stages sequentially, enforcing a global stage barrier.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` merges a completed stage; a DAG scheduler would need deterministic per-cluster or per-ready-set merge semantics.
- `src/herder/TxSetFrame.cpp:2328-2348` — validation already bounds clusters per stage and models stage cost by the slowest cluster, which is the same conservative barrier this hypothesis targets.

## Evidence

The current diagnostic trace's apply window totals `applyLedger` at **5,230,315,999 ns across 71 calls**. Within that apply subtree, `applySorobanStages` totals **3,835,000,197 ns**, and the main-thread wait zone `applySorobanStageClustersInParallel` has **3,455,290,270 ns self-time** with high variance (`max_ns=496,820,207`, `std_ns=185,811,366`). Source inspection shows the barrier is structural rather than required by `ApplyStage` storage: clusters expose complete transaction footprints, and final observable order can be preserved by buffering cluster results and committing in canonical XDR stage/cluster/transaction order after dependencies complete.

This is not the previously rejected worker-pool hypothesis: it does not target OS thread creation, `std::async`, or worker reuse. It changes the scheduling granularity from "all clusters in stage N must finish before any cluster in stage N+1 starts" to "a cluster starts when its actual predecessor conflicts are complete", which can recover idle time that a worker pool alone cannot address.

## Anti-Evidence

The current XDR transaction set only stores stages and clusters, not explicit dependency edges, so the PoC must reconstruct dependencies deterministically from footprints and prove the refined schedule is semantically equivalent to the conservative stage schedule. If soroswap stages are already perfectly balanced or every later-stage cluster conflicts with every previous-stage cluster, the DAG degenerates to the current barrier and the win disappears. The merge path must also avoid nondeterminism: worker completion order cannot affect ledger-entry updates, metadata ordering, result ordering, or restored-entry accounting.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The parallel Soroban apply path builds `ApplyStage` objects in transaction-set order, then `applySorobanStages` executes those stages strictly one after another. Each stage launches all clusters with `std::async`, waits for every future, checks invariants, and only then commits all thread states into `GlobalParallelApplyLedgerState`, so any idle worker caused by a slow cluster cannot take independent work from a later stage. Tx-set validation confirms only intra-stage cluster conflicts are forbidden; cross-stage clusters may be independent and can be identified from the same Soroban footprints used by the builder and validator. Correctness is feasible if the scheduler constructs thread state only after all true predecessors have committed and serializes global-state commits in deterministic XDR stage/cluster order rather than worker completion order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2967-3030` — `applyParallelPhase` converts `TxStageFrameList` into `ApplyStage`/`Cluster`/`TxBundle` storage, assigns stable `txNum`s, and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` per cluster, launches every cluster in the current stage, then blocks on every future before returning.
- `src/ledger/LedgerManagerImpl.cpp:2622-2705` — `applySorobanStage` commits only after all current-stage clusters finish, and `applySorobanStages` loops over stages sequentially, creating the structural barrier.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` preloads the cluster footprint from the current global state, so a DAG scheduler must construct a cluster's thread state after all conflicting predecessors have been merged.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` currently merges a whole stage using `getReadWriteKeysForStage`; a DAG scheduler needs equivalent deterministic per-cluster or canonical-ready-set merge semantics, including RO TTL bump handling.
- `src/herder/TxSetFrame.h:281-300` and `src/herder/TxSetFrame.cpp:2328-2440` — the XDR phase defines stages as conservative sequential groups, validates cluster-count/instruction limits per stage, and rejects only read/write conflicts between clusters within the same stage.
- `src/herder/ParallelTxSetBuilder.cpp:494-551` and `src/herder/ParallelTxSetBuilder.cpp:577-698` — the builder computes conflicts from footprints and packs independent dependency clusters into a bounded number of bins per stage; later stages can contain clusters that are independent of many earlier-stage clusters.
- `src/transactions/TransactionFrame.cpp:2352-2448` and `src/ledger/LedgerManagerImpl.cpp:3093-3140` — pre-parallel seq/signature effects are handled before the parallel operation phase, and post-tx-set refunds/meta are emitted later in stable `txNum` order, so worker execution order need not become observable.

### Findings

The inefficiency exists and is in the objective hot path: `applySorobanStages` is called during `closeLedger` and accounts for a dominant portion of the supplied soroswap apply trace. The barrier is not required by the in-memory executor for independent clusters; it is an implementation strategy that waits for the slowest cluster of each stage before starting any cluster from the next stage. The stage model is conservative because validation only proves clusters inside a single stage are mutually non-conflicting, while the builder's footprint conflict data makes it possible to compute a finer cross-stage dependency graph.

The proposed optimization is correctness-preserving only with strict constraints. A later cluster must not be given a `ThreadParallelApplyLedgerState` until all earlier clusters with RO/RW or RW/RW conflicts, including associated Soroban TTL keys, have committed to `GlobalParallelApplyLedgerState`. Commits must be serialized in a deterministic canonical order or otherwise proven commutative; worker completion order must not affect ledger entries, restored-entry accounting, invariant deltas, transaction results, metadata, fee refunds, or `mIsNew` preservation. RO TTL bumps already have max-merge semantics, but RW interactions must remain ordered exactly as the conservative stage schedule would require.

The impact is plausibly High for this objective because the targeted phase is a dominant `closeLedger` phase in the supplied trace and this is a scheduler redesign rather than a micro-optimization. The exact recoverable portion is not the whole `applySorobanStageClustersInParallel` self-time; it is the per-stage tail idle time that can be filled by ready later-stage clusters. The PoC must therefore measure cluster durations and compare stage-barrier critical-path time against DAG-scheduled critical-path time on the same soroswap workload.

### PoC Guidance

- **Target code**: Replace or augment `LedgerManagerImpl::applySorobanStages`, `applySorobanStage`, and `applySorobanStageClustersInParallel`; add helper logic near `ParallelApplyUtils` for cluster footprint conflict/dependency computation and deterministic merge support.
- **Change description**: Build a DAG over `(stageIndex, clusterIndex)` nodes using each cluster's unioned Soroban read-only/read-write footprints, treating RO/RW and RW/RW intersections as dependencies from earlier-stage clusters to later-stage clusters. Run at most `ledgerMaxDependentTxClusters()` worker tasks at a time. Construct each `ThreadParallelApplyLedgerState` only when the cluster becomes ready, apply it on a worker, then merge completed ready nodes on the apply thread in canonical order that preserves all conflicting predecessor relationships.
- **Correctness check**: Existing parallel tx-set validation tests in `src/herder/test/TxSetTests.cpp` cover stage/cluster conflict rules; ledger apply tests covering v23+ Soroban parallel apply, metadata, refunds, restores, and invariant checks should remain unchanged. Add focused scheduler tests only if the PoC introduces observable helper APIs or alternate scheduling branches.
- **Benchmark focus**: Use `scripts/run_apply_load_matrix.py` on soroswap `TX=2000, T=8` across repeated runs. Report top-line apply time, `applyParallelPhaseTotalMs`, `sorobanParallelApplyMs`, stage count, worker utilization, and the computed barrier critical path vs DAG critical path. The expected improvement should come from reduced per-stage tail idle and should clear the objective's 3% Medium floor, with High plausible if the measured reduction exceeds 10% or materially restructures the dominant `applySorobanStages` phase.
