# H001: Debin Artificial Parallel-Apply Clusters at Apply Time

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring the dominant Soroban parallel-apply phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban stage contains transactions that were placed in the same `TxClusterFrame` only because the transaction-set builder bin-packed independent dependency clusters into at most `ledgerMaxDependentTxClusters` bins, `applyLedger` should still be able to apply those independent components concurrently, capped by the configured worker count. The observable result order, transaction metadata order, fee/refund accounting, and final ledger state should remain identical to the current sequential-in-bin behavior.

## Mechanism

`ParallelTxSetBuilder` explicitly distinguishes logical dependency clusters from artificial bins: fine-grained clusters are merged only when they conflict, but then independent clusters may be packed into a smaller number of "artificial super-clusters" to fit `ledgerMaxDependentTxClusters` (`src/herder/ParallelTxSetBuilder.cpp:400-426`). The apply path loses this distinction and treats each resulting `Cluster` as a strictly sequential unit: `LedgerManagerImpl::applySorobanStageClustersInParallel` launches one worker per stage cluster, and `LedgerManagerImpl::applyThread` iterates every `TxBundle` in that cluster serially (`src/ledger/LedgerManagerImpl.cpp:2530-2575`, `src/ledger/LedgerManagerImpl.cpp:2500-2518`). Reconstructing independent components inside each binned cluster from transaction footprints at apply time would remove serialization that is not required for determinism.

## Trigger

Run the current soroswap apply-load benchmark with a generalized Soroban tx set whose stage contains more independent fine-grained dependency clusters than `ledgerMaxDependentTxClusters`, causing the builder to pack multiple independent components into the same final cluster. In the current code, all transactions in that final cluster execute serially on one apply worker; with apply-time debinning, disjoint components would execute on separate workers up to the configured cap.

## Target Code

- `src/herder/ParallelTxSetBuilder.cpp:400-426` — documents that final clusters can be artificial bins of independent logical clusters.
- `src/herder/ParallelTxSetBuilder.cpp:522-544` — materializes each bin as a single `TxClusterFrame`, erasing the fine-grained cluster boundaries.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — launches one async task per final stage cluster.
- `src/ledger/LedgerManagerImpl.cpp:2500-2518` — applies every transaction in a cluster sequentially.
- `src/herder/TxSetFrame.cpp:2328-2385` — validates the cap by treating stage cost as the maximum cluster instruction sum, so artificial bins become the unit of guaranteed parallelism.

## Evidence

The current soroswap Tracy trace is dominated by the apply subtree: `applyLedger` totals 5,230,315,999 ns across 71 calls, `applyTransactions` totals 4,609,935,546 ns, and `applyParallelPhase` totals 3,842,725,964 ns. Inside it, `applySorobanStageClustersInParallel` totals 3,520,949,405 ns with 3,455,290,270 ns self-time across 43 calls, consistent with the apply thread waiting on cluster futures. Worker execution is much larger in aggregate (`parallelApply` totals 12,671,220,592 ns and `InvokeHostFunctionOpFrame doParallelApply` totals 12,664,159,786 ns), so any independent work trapped inside a sequential bin has enough headroom to move the wall-clock slowest-cluster time.

This is not the previously rejected thread-launch or thread-state-setup family: the target is the semantic scheduling unit, not `std::async` overhead or construction of `ThreadParallelApplyLedgerState`. It also does not exceed `NUM_CLUSTERS`; it would schedule reconstructed subcomponents on the existing worker budget and merge effects in deterministic transaction order.

## Anti-Evidence

If soroswap's final clusters are mostly true logical cliques over the same liquidity-pool or token-balance write keys, debinning will reconstruct little or no independent work. The approach also has to preserve the existing read-only TTL bump semantics from `ParallelApplyUtils.cpp:71-102`, because blindly splitting a binned cluster must not make deferred TTL bumps observable in a different order.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to `fail/soroban/003-cluster-wall-time-imbalance.md`, but not a duplicate; that record rejected true-cluster imbalance/rebalancing, while this hypothesis targets artificial bin contents
**Failed At**: reviewer

### Trace Summary

The generic mechanism exists: the tx-set builder forms true dependency clusters, bin-packs those clusters into at most `ledgerMaxDependentTxClusters`, and the apply path then executes each resulting `TxClusterFrame` serially on one worker. The apply code and comments also acknowledge that not every transaction inside a cluster is necessarily conflicting, and the RO TTL bump design is intended to allow future partial-order schedulers. However, the current soroswap apply-load benchmark does not create more independent logical clusters than the configured cluster cap: setup creates exactly one token pair per configured cluster/bin, and every swap in a pair writes the same pair balances and pair contract instance. Reconstructing dependencies inside each final soroswap cluster would therefore produce one connected component per cluster, leaving the parallel apply wall time unchanged.

### Code Paths Examined

- `src/herder/ParallelTxSetBuilder.cpp:57-86` — true builder clusters merge transactions with RW/RO footprint dependencies and track their instruction sum.
- `src/herder/ParallelTxSetBuilder.cpp:120-217` — adding a transaction merges conflicting clusters and then bin-packs the resulting logical clusters against `mClustersPerStage`.
- `src/herder/ParallelTxSetBuilder.cpp:400-426` — comments explicitly describe final bins as artificial super-clusters of independent logical clusters when the logical cluster count exceeds `ledgerMaxDependentTxClusters`.
- `src/herder/ParallelTxSetBuilder.cpp:522-544` — materializes each bin as one `TxClusterFrame`, losing the original logical-cluster boundary.
- `src/herder/TxSetFrame.h:281-300` — stage/cluster comments state that transactions in a cluster should generally be sequential, but some or all may still be parallelizable depending on footprints.
- `src/herder/TxSetFrame.cpp:2328-2385` — validation caps only final cluster count and sequential instruction accounting, not intra-cluster logical-component count.
- `src/herder/TxSetFrame.cpp:2394-2440` — validation guarantees no RW conflicts between final clusters in a stage; it does not guarantee every pair inside a final cluster conflicts.
- `src/ledger/LedgerManagerImpl.cpp:2967-3032` — converts each tx-set cluster into one apply `Cluster` preserving transaction order and then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` applies all `TxBundle`s in one cluster sequentially and flushes deferred RO TTL bumps at write barriers and cluster end.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — launches one `std::async` worker per final stage cluster and joins all workers before committing thread states.
- `src/transactions/ParallelApplyUtils.cpp:29-102` — documents the conflict model and deferred RO TTL bump semantics, including the intended possibility of future intra-cluster parallel scheduling.
- `src/simulation/ApplyLoad.cpp:2323-2332` — the benchmark asserts one stage with exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` clusters.
- `src/simulation/ApplyLoad.cpp:2672-2678` — soroswap setup creates exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` token pairs, one per intended cluster/bin.
- `src/simulation/ApplyLoad.cpp:3389-3475` — swap generation round-robins transactions across those pairs; transactions for the same pair share RW pair balances and the RW pair contract instance, so each pair forms a true dependency component.
- `scripts/run_apply_load_matrix.py:417-424` and `docs/apply-load-limits-for-model-tx.cfg:36-42` — the current matrix sets soroswap `TX=2000, T=8`, feeding `APPLY_LOAD_MAX_SOROBAN_TX_COUNT=2000` and `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS=8`.

### Why It Failed

The optimization is not exercised by the objective workload. Current soroswap is deliberately shaped to achieve maximum existing parallelism: it creates eight pairs for eight configured clusters, then round-robins 2,000 swaps across those pairs. Within a pair cluster, every swap writes the same pair contract instance and pair-side SAC balances, so the conflict graph remains connected; across pairs, transactions are already separated into different final clusters and already run in parallel.

An apply-time debinner could be correct for a different generalized tx set with more independent logical clusters than configured bins, provided it preserves bounded worker count, deterministic tx/result ordering, true conflict-component order, and deferred RO TTL bump merging. But for `optimize-soroswap`, this would add dependency-graph reconstruction and scheduling complexity to the hot apply path while producing no Medium-or-High apply-time reduction on the current benchmark.

### Lesson Learned

Before promoting intra-cluster scheduling ideas, verify that the target benchmark actually contains artificial bins. The soroswap apply-load generator intentionally chooses `numPairs == ledgerMaxDependentTxClusters`, so binned-cluster debinning is a workload-shape mismatch rather than an apply-path bottleneck.
