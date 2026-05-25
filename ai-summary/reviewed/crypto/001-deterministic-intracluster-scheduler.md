# H001: Deterministic Intra-Cluster Scheduler for Soroswap Parallel Apply

**Date**: 2026-05-25
**Subsystem**: crypto / ledger / transactions / Soroban parallel apply
**Severity**: High
**Impact**: reduce soroswap apply time by exploiting non-conflicting transactions currently serialized inside dependent clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban parallel stage should produce the same transaction results, ledger entries, TTL updates, metadata, events, and transaction-result ordering as the existing cluster-order execution. Transactions that have no read-write conflicts within the same cluster should be allowed to execute concurrently, while transactions connected by a conflict edge must preserve the same observable order. Worker count must remain capped by `ledgerMaxDependentTxClusters` / `NUM_CLUSTERS`.

## Mechanism

`LedgerManagerImpl::applyThread` currently applies every `TxBundle` in a `Cluster` serially, even though `TxSetFrame.h` explicitly says not all transactions in a cluster necessarily conflict. Soroswap clusters can become transitively dependent because of shared pool/SAC/TTL keys, but many transactions within such a transitive component may still be independent of each other. A deterministic intra-cluster conflict DAG scheduler can run ready non-conflicting transactions in parallel, commit their effects in original cluster order, and retain deterministic output while reducing the dominant `applySorobanStageClustersInParallel` wait time.

## Trigger

Run the current accepted soroswap trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`

The relevant top-level apply descendant is `applyLedger`. The current trace shows `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` with 4.437325974 s total over 71 ledgers, and `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with 2.752707259 s total over 43 stage executions. A PoC should instrument each `Cluster` with per-transaction footprint conflict edges and count ready-set width greater than one inside clusters before replacing the serial loop.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` serially loops over all transactions in one cluster.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one worker task per cluster and waits for each cluster as an indivisible unit.
- `src/herder/TxSetFrame.h:284-295` — comments define stage/cluster semantics and explicitly note that transactions inside a cluster are not necessarily all conflicting.
- `src/herder/ParallelTxSetBuilder.cpp:57-85` — clusters are transitive dependency components, merging conflict sets rather than preserving the full internal conflict graph for apply.
- `src/transactions/ParallelApplyStage.h:116-157` — `Cluster` is currently only a vector of `TxBundle`, with no retained internal dependency graph for deterministic ready-set scheduling.

## Evidence

The trace identifies `applySorobanStageClustersInParallel` as a dominant descendant of `applyLedger`, not a TX-set-construction zone. The source also documents the missed opportunity directly: clusters should generally be applied sequentially, but some or all transactions in a cluster can be parallel depending on footprints. This is a redesign hypothesis rather than a crypto primitive micro-optimization, so it is not bounded by the existing SHA256 or verifySig failure meta-patterns. Determinism can be preserved by using a stable transaction-index priority for ready transactions, capping workers at the configured cluster count, and applying/committing results in original cluster order after all conflict predecessors complete.

## Anti-Evidence

If current soroswap clusters are mostly single-transaction clusters or true cliques where every transaction conflicts with every other transaction, the ready-set width will be one and the scheduler will not help. The implementation is substantial: it needs the internal conflict graph or enough footprint data retained from TX-set building, and must preserve the existing read-only TTL-bump partial-order semantics, metadata order, and error handling. A PoC should first prove ready-set width and straggler reduction on the current trace before attempting a full scheduler.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The apply path is `applyParallelPhase` building `ApplyStage` objects from generalized transaction-set stages, then `applySorobanStages` applying each stage through `applySorobanStageClustersInParallel`. Today that function starts one future per final apply cluster, and each future calls `applyThread`, which walks the cluster's `TxBundle`s sequentially while mutating a single `ThreadParallelApplyLedgerState`. The final apply cluster is not guaranteed to be a true conflict clique: the tx-set builder first forms transitive dependency clusters, but then bin-packs potentially many independent clusters into at most `ledgerMaxDependentTxClusters` final XDR clusters. Because `applySorobanStageClustersInParallel` is a dominant `applyLedger` descendant in the cited trace, replacing fixed bin-local serial loops with a deterministic stage-level ready scheduler is a credible Medium/High optimization surface if ready width and straggler imbalance are present.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2871-3031` — `applyParallelPhase` converts every `TxClusterFrame` into a `Cluster` of `TxBundle`s, preserving transaction result references, transaction numbers, metadata builders, and fee events, then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the serial bottleneck inside each final cluster: it computes the deterministic per-tx PRNG sub-seed, flushes RO TTL bumps for the tx write footprint, runs `parallelApply`, and commits successful tx changes into the same thread state before advancing.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one async worker per final cluster and waits for clusters as indivisible units; the number of workers is bounded by the number of final stage clusters.
- `src/ledger/LedgerManagerImpl.cpp:2622-2710` — `applySorobanStage` runs parallel workers, checks invariants, then commits thread states to the global state; `applySorobanStages` applies stages sequentially and finally commits global changes to `LedgerTxn`.
- `src/herder/TxSetFrame.h:281-295` — protocol-facing comments explicitly state that transactions in different clusters are independent, but transactions inside a cluster are not necessarily all conflicting and may be partly or fully parallelizable depending on footprints.
- `src/herder/ParallelTxSetBuilder.cpp:57-85` — builder-local `Cluster` objects represent transitive dependency components and retain only tx ids plus a conflict bitset, not a reusable internal DAG.
- `src/herder/ParallelTxSetBuilder.cpp:400-426` — the final XDR cluster can be an artificial bin: independent dependency clusters may be packed into a smaller number of `DependentTxCluster`s to respect `ledgerMaxDependentTxClusters`.
- `src/herder/ParallelTxSetBuilder.cpp:522-544` — `visitAllTransactions` writes transactions into final stage clusters by bin id, which is where independent logical clusters become serialized inside one final apply cluster.
- `src/herder/ParallelTxSetBuilder.cpp:577-697` — transaction conflicts are derived deterministically from footprints: shared RW/RW and RO/RW keys create conflict edges, with hash collisions conservatively treated as conflicts.
- `src/transactions/ParallelApplyStage.h:71-116` — `TxBundle` keeps per-tx result, tx number, and effects; the apply `Cluster` is currently just `std::vector<TxBundle>`, so no dependency graph or subcluster identity survives into apply.
- `src/transactions/ParallelApplyUtils.cpp:90-102` — RO TTL bump handling intentionally preserves a partial order around writes, not a total order among read-only bumps, matching the kind of conflict-DAG scheduler this hypothesis proposes.
- `src/transactions/ParallelApplyUtils.cpp:1003-1055` and `src/transactions/ParallelApplyUtils.cpp:1165-1251` — per-tx flush/commit semantics require a scheduler to make predecessor writes visible before dependent successors, not merely run all txs and reorder outputs afterward.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — global commit currently folds completed thread states in deterministic vector order, so a replacement must preserve deterministic stage commit order while allowing worker-level load balancing.

### Findings

The inefficiency exists. `applyThread` serializes every transaction in a final apply cluster, while the tx-set builder documentation and implementation show final clusters can contain independent logical dependency clusters due to bin packing. This is not only a comment-level possibility: `ParallelTxSetBuilder::Stage` tracks true transitive dependency clusters internally, then maps them into a limited number of bins that become final `TxClusterFrame`s.

The path is hot and in scope. The cited `applySorobanStageClustersInParallel` time is inside `applyLedger`, and the objective explicitly focuses on `closeLedger` / apply work. Unlike crypto primitive hypotheses rejected in `ai-summary/fail/crypto/summary.md`, this is not bounded by the SHA256, verifySig, or host-syscall micro-optimization ceilings; it restructures the dominant parallel apply scheduler itself.

The proposed fix is correctness-plausible but must be refined as a stage-level scheduler, not nested unbounded per-cluster async work. Because the objective forbids exceeding `NUM_CLUSTERS` parallelism, the viable shape is a deterministic ready queue over the stage (or over a cluster using otherwise-idle stage workers) with total workers capped at `ledgerMaxDependentTxClusters`. It must reconstruct or retain conflict edges from footprints, use transaction number/order as a stable tie-breaker, and commit each tx's effects into its logical predecessor-visible state before releasing dependent successors.

The measurable impact depends on workload structure. If soroswap final clusters are true cliques or already balanced by bin packing, the win disappears. But the source proves the missed scheduling opportunity is real, and the target function dominates the cited apply trace enough that reducing straggler makespan in this phase can clear the optimize-soroswap Medium floor and potentially qualify as High because it materially restructures a dominant phase of `closeLedger`.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp:2483-2575`, `src/transactions/ParallelApplyStage.h:116-157`, and either `src/herder/ParallelTxSetBuilder.cpp:577-697` or an apply-side helper that deterministically rebuilds per-stage/per-cluster footprint conflict edges from `TxBundle::getTx()->sorobanResources().footprint`.
- **Change description**: First instrument each final apply cluster with exact counts for cluster size, conflict-edge count, ready-set width, critical-path length, and observed worker idle/straggler time. If those counters show exploitable width, replace the fixed one-future-per-cluster model with a deterministic stage-level work queue capped at `ledgerMaxDependentTxClusters`, scheduling ready txs by stable tx number while preserving dependency edges for RW/RW and RO/RW footprint conflicts. Do not add nested workers on top of the existing cluster futures.
- **Correctness check**: Preserve per-tx `subSha256(sorobanBasePrngSeed, txBundle.getTxNum())`, transaction-result ordering in `processPostTxSetApply`, metadata/event ordering by `txNum`, RO TTL bump flush semantics before dependent writes, and deterministic global commit ordering. Existing parallel Soroban apply tests and invariant-enabled runs should cover ledger/result equivalence; add targeted tests only for new scheduler branches if the implementation introduces them.
- **Benchmark focus**: Primary metric is `scripts/run_apply_load_matrix.py` soroswap apply time, with repeated runs. The PoC should report per-stage makespan before/after, ready-width histograms, number of final clusters with width >1, and whether wall-clock `applySorobanStageClustersInParallel` falls by at least 3% of end-to-end apply time without increasing total workers above `NUM_CLUSTERS`.
