# H001: Wavefront Soroban stage scheduler to remove global per-stage barriers

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / parallel Soroban apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by keeping independent cluster workers busy across stage boundaries without exceeding `NUM_CLUSTERS`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply should preserve the deterministic transaction order within each conflict cluster and should not allow a transaction to observe writes from an unrelated cluster that it did not conflict with. For soroswap-shaped ledgers with several independent pair clusters, once cluster `i` finishes its chunk for stage `k`, cluster `i`'s stage `k + 1` chunk should be able to continue on the same logical per-cluster state without waiting for every other independent cluster in stage `k` to finish, provided final result/meta placement still follows the stable stage-major transaction indices.

## Mechanism

`LedgerManagerImpl::applySorobanStages` currently applies every `ApplyStage` through a full barrier: `applySorobanStage` launches one async task per cluster, waits for every future, checks invariants, commits all thread states into the global state, destroys thread states, and only then advances to the next stage. This is stronger synchronization than the actual conflict constraint for soroswap pair clusters: transactions in the same apply-cluster must remain ordered, but independent pair clusters do not need to wait at every stage boundary if their state ownership is carried forward deterministically.

A wavefront scheduler can run at most `ledgerMaxDependentTxClusters()` per-cluster worker lanes, each lane processing that cluster's stage chunks sequentially while preserving its local order. The main thread would merge each lane's committed effects in deterministic `(stage, cluster, tx)` order or maintain per-tx `TxBundle::getTxNum()` placement for results/meta, so consensus-visible ledger output remains unchanged while barrier idle time and repeated thread-state setup/merge work are reduced.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect the diagnostic trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. The apply window contains 43 `applySorobanStageClustersInParallel` events totaling 3,520.949 ms inside `applyLedger`, meaning the main apply thread repeatedly waits at stage barriers while worker cluster work dominates the close-ledger critical path.

## Target Code

- `src/herder/TxSetFrame.h:281-300` — documents the current stage/cluster model and the global requirement that each stage executes after the previous one.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` per cluster, launches async workers, and waits for all futures before returning.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` enforces the per-stage barrier, invariant pass, global merge, and thread-state destruction.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` iterates stages serially and cannot start any next-stage cluster until the whole previous stage has committed.
- `src/ledger/LedgerManagerImpl.cpp:2966-3020` — `applyParallelPhase` materializes `ApplyStage` chunks while preserving stable `TxBundle::getTxNum()` transaction indices for deterministic result/meta placement.
- `src/transactions/test/ParallelApplyTest.cpp:1007-1030` — test helper builds final apply order by splitting each apply cluster into stage chunks, illustrating the per-cluster sequence that a wavefront lane could process without changing order.

## Evidence

- Tracy scope check: the cited `applySorobanStageClustersInParallel` events are contained inside `applyLedger` and under `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages`, not in transaction-set construction.
- Current in-apply Tracy aggregation for the current soroswap trace reports `applyParallelPhase` at 3,842.726 ms, `applySorobanStages` at 3,835.000 ms, `applySorobanStage` at 3,585.330 ms, and `applySorobanStageClustersInParallel` at 3,520.949 ms across 71 `applyLedger` windows. This is wall-clock wait time on the main apply thread, not aggregate worker self-time that must be divided by cluster count.
- The source enforces a global stage barrier even though the workload's headline parallelism comes from independent soroswap pair clusters. Any per-stage imbalance forces all faster clusters to idle before they can process their next chunk.
- The design stays within the objective's determinism constraints: one worker lane per cluster, no more than `ledgerMaxDependentTxClusters()` active lanes, per-cluster transaction order unchanged, and final merge/result publication ordered by existing stable transaction numbers.

## Anti-Evidence

- The XDR stage semantics are documented as a global ordering constraint. A PoC must prove that relaxing the implementation barrier for independent clusters is consensus-equivalent, or else protocol-gate the scheduler change and document that only non-conflicting cluster lanes may advance early.
- If soroswap's generated stages are already balanced, wavefront scheduling may recover little wall time despite the large enclosing wait zone. The PoC should add per-cluster stage timing counters before implementation or as a temporary measurement patch.
- `GlobalParallelApplyLedgerState::commitChangesFromThreads` currently assumes all thread states for a stage are committed together. Carrying per-cluster state across chunks or committing lane results incrementally will require careful ownership/scope auditing in `LedgerEntryScope` and `ParallelApplyUtils`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The code does implement a full stage barrier: `applySorobanStages` iterates stages, `applySorobanStage` waits for every cluster future, and only then merges thread states into the global parallel-apply state. However, the measured soroswap apply-load path explicitly asserts that each benchmark ledger has exactly one Soroban stage and the configured maximum cluster count, so there is no next-stage work that could be released by a wavefront scheduler in the objective workload. Separately, the proposed "same cluster index across stages" lane model is not a valid general execution dependency: XDR and validation only guarantee independence between clusters within a single stage, while cross-stage clusters may conflict arbitrarily and are assigned by stage-local bin packing.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2307-2333` — the measured model transaction close records apply time around `closeLedger` and then asserts `stagesMetric.count() == 1` and `maxClustersMetric.count() == APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`, ruling out per-stage barrier savings for soroswap.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generation round-robins independent pair footprints to maximize cluster parallelism; this benchmark is shaped to produce one stage with `T=8` clusters, not multiple sequential stage chunks per pair lane.
- `src/herder/TxSetFrame.h:281-300` — documents the protocol model: every stage must execute after every transaction in the previous stage; only clusters within the same stage are independent.
- `src/herder/TxSetFrame.cpp:2326-2440` — validation enforces cluster-count and same-stage no-conflict rules, but permits conflicts across stages because stages are semantically sequential.
- `src/herder/test/TxSetTests.cpp:1544-1567` — the valid test fixture includes a second-stage cluster that would conflict with every previous-stage cluster, demonstrating that a later cluster cannot be identified as a continuation of the same cluster lane by index.
- `src/herder/ParallelTxSetBuilder.cpp:88-107,400-435,522-551` — builder clusters are stage-local dependency groups packed into bins capped by `ledgerMaxDependentTxClusters`; the bin/cluster index is an artificial per-stage scheduling bucket, not a persistent conflict-component identity across stages.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` creates one thread state per current-stage cluster and waits for all worker futures before returning.
- `src/ledger/LedgerManagerImpl.cpp:2622-2705` — `applySorobanStage` commits all current-stage thread states to the global state before `applySorobanStages` advances to the next stage.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `GlobalParallelApplyLedgerState::commitChangesFromThreads` computes the read-write set for one whole stage and merges all thread states using that stage-wide context.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — each `ThreadParallelApplyLedgerState` is initialized from the committed global state for exactly one cluster; carrying it across stages would need a different dependency and ownership model.

### Why It Failed

The claimed hot-path inefficiency is not present in the target benchmark: soroswap's measured close ledger has one Soroban stage, so a scheduler that removes barriers between stages has no barrier to remove and cannot reach the objective's Medium threshold. The cited Tracy count of `applySorobanStageClustersInParallel` events is an aggregate across many `applyLedger` windows, including non-measured/setup closes, and does not establish repeated stage barriers inside the measured soroswap ledger. The proposed lane mechanism is also unsafe as stated because cluster indices are stage-local bins and later-stage clusters may depend on any earlier-stage cluster.

### Lesson Learned

Before targeting a synchronization zone, verify that the benchmark ledger actually has multiple synchronization rounds and that the alleged lane identity exists in the validated XDR semantics. `applySorobanStageClustersInParallel` wall time shows worker execution and the single-stage slowest-cluster wait; it is not by itself evidence of removable cross-stage barrier idle time.
