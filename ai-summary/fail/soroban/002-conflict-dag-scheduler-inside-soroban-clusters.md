# H002: Conflict-DAG Scheduler Inside Soroban Parallel-Apply Clusters

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by parallelizing independent antichains within currently sequential clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Transactions in the same Soroban cluster should execute sequentially only where their footprints impose an actual read/write dependency or where read-only TTL bump ordering creates a required barrier. Transactions that are merely connected by transitive dependencies, but do not directly conflict with each other, should be executable concurrently while preserving deterministic commit, result, and metadata order.

## Mechanism

The current apply loop treats every `Cluster` as a total order even though the tx-set abstraction does not require that: `TxSetFrame.h` states that a cluster "should generally be applied sequentially" but that "not all the transactions in the cluster are necessarily conflicting" and some may be parallelizable (`src/herder/TxSetFrame.h:291-295`). `ParallelApplyUtils.cpp` also documents the intended future shape: within a cluster, read-only TTL bump groups and writes form a partial order, but the current implementation runs the cluster in a sequential incidental order and only preserves future flexibility through deferred TTL bumps (`src/transactions/ParallelApplyUtils.cpp:74-102`). Building a per-cluster conflict DAG and scheduling ready antichains across the existing worker cap would reduce slowest-cluster wall time without changing observable ledger output.

## Trigger

Use a soroswap ledger where a cluster contains a sparse dependency chain, for example transactions `A`, `B`, and `C` where `A` conflicts with `B`, `B` conflicts with `C`, but `A` and `C` touch disjoint write sets. The current `LedgerManagerImpl::applyThread` applies `A`, then `B`, then `C` serially; a DAG scheduler could run `A` and `C` concurrently when their relative order is not observable, then commit buffered effects in the deterministic topological/original transaction order required by the tx set.

## Target Code

- `src/herder/TxSetFrame.h:281-300` — defines stages, clusters, and explicitly notes that clusters may contain internally parallelizable transactions.
- `src/transactions/ParallelApplyUtils.cpp:71-102` — describes deferred read-only TTL bump groups and the partial-order constraints a future scheduler must preserve.
- `src/ledger/LedgerManagerImpl.cpp:2500-2518` — current per-cluster total-order execution loop in `applyThread`.
- `src/transactions/ParallelApplyUtils.cpp:898-960` — deterministic thread-state merge path that would need to consume buffered per-tx outputs in original order after DAG execution.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — current stage-level future join point where slowest sequential cluster determines stage wall time.

## Evidence

The current soroswap trace shows `applySorobanStageClustersInParallel` as an apply-path descendant with 3,520,949,405 ns total and 3,455,290,270 ns self-time across 43 stage executions; its self-time is primarily future waiting, not useful work. The worker-side descendants are large enough to matter: `InvokeHostFunctionOpFrame doParallelApply` totals 12,664,159,786 ns across 6,776 calls, and `Vm::invoke_function_raw` totals 12,842,366,133 ns across 20,313 calls. A scheduler that removes unnecessary total ordering inside large sparse clusters attacks the wall-clock critical path rather than a sub-1% per-call micro-cost.

This differs from the rejected "parallelize thread-state setup" and "persistent worker executor" hypotheses: those tried to reduce launch/setup overhead around the same wrapper zone. This hypothesis changes the amount of Soroban invocation work on the slowest cluster path while preserving the `ledgerMaxDependentTxClusters`/`NUM_CLUSTERS` cap.

## Anti-Evidence

The gain depends on sparse internal conflict graphs. If soroswap clusters are dominated by true hot write keys where every transaction conflicts with every other transaction in the cluster, the DAG collapses to the existing total order. The implementation also has to be careful with `ThreadParallelApplyLedgerState`: parallel antichains cannot share one mutable thread state directly, so each subtask likely needs isolated tx state plus deterministic ordered merge, otherwise the optimization would introduce nondeterministic state visibility.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — substantially duplicate of `ai-summary/fail/soroban/001-debin-artificial-parallel-apply-clusters.md`
**Failed At**: reviewer

### Trace Summary

The generic code mechanism is real: tx-set construction merges transactions into transitive dependency clusters, and `LedgerManagerImpl::applyThread` then applies each final `Cluster` in a sequential loop. The source comments in both `TxSetFrame.h` and `ParallelApplyUtils.cpp` explicitly preserve room for a future intra-cluster partial-order scheduler. However, this exact intra-cluster scheduling angle was already reviewed for the soroswap objective in `001-debin-artificial-parallel-apply-clusters.md`, which traced the same apply path and current workload shape. The current soroswap generator creates one pair per configured cluster, and every swap in a pair writes the same pair-side SAC balances and pair contract instance, so the per-pair conflict graph is effectively a clique rather than a sparse A-B-C chain.

### Code Paths Examined

- `src/herder/TxSetFrame.h:281-300` — defines stages/clusters and notes that cluster transactions are not necessarily all pairwise-conflicting.
- `src/herder/ParallelTxSetBuilder.cpp:57-86` — builder clusters are transitive dependency components formed from transactions sharing a footprint key where at least one access is read-write.
- `src/herder/ParallelTxSetBuilder.cpp:620-698` — conflict edges are generated for RW-RW and RO-RW footprint intersections.
- `src/herder/ParallelTxSetBuilder.cpp:400-426` and `522-544` — final clusters can also be artificial bins of logical clusters, but that prior review already found soroswap does not expose useful independent work inside its final clusters.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` sequentially flushes deferred RO TTL bumps, runs `parallelApply`, then commits each successful tx to the shared thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` and `2622-2657` — one worker is launched per final cluster, all workers join, then thread states are committed deterministically to global state.
- `src/transactions/ParallelApplyUtils.cpp:71-102` and `1003-1055` — deferred RO TTL bump semantics require ordered flush points around writes, which a DAG scheduler would need to preserve.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — per-tx results are merged into the thread state in the current total order.
- `src/simulation/ApplyLoad.cpp:2672-2678` — soroswap setup creates exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` pairs, one per intended cluster/bin.
- `src/simulation/ApplyLoad.cpp:3389-3475` — each generated swap round-robins across pairs and writes both pair-side SAC balance keys plus the pair contract instance, making same-pair swaps directly conflict with each other.
- `scripts/run_apply_load_matrix.py:417-424` and `docs/apply-load-limits-for-model-tx.cfg:36-42` — the benchmark maps scenario thread count to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` and currently uses 8 clusters for 2000 soroswap transactions.

### Why It Failed

This hypothesis is not novel for the objective: the prior `001-debin-artificial-parallel-apply-clusters.md` review already traced intra-cluster scheduling/debinning through the tx-set builder, apply stage construction, `applyThread`, and soroswap workload generation, and rejected it because current soroswap clusters contain no exploitable independent work. The new A-B-C conflict-DAG framing is a more general scheduler than simple debinning, but it depends on the same unproven workload condition: sparse internal conflict graphs inside soroswap clusters.

The actual soroswap benchmark deliberately creates one liquidity pair per configured cluster and round-robins swaps across those pairs. Within a pair, every swap writes the same pair contract instance and the same pair-side SAC balance entries, so each same-pair transaction directly conflicts with every other same-pair transaction. A per-cluster DAG would therefore collapse to the existing sequential order on the objective workload, producing no Medium-or-High apply-time reduction.

### Lesson Learned

Future intra-cluster scheduler hypotheses must first demonstrate, with the current soroswap benchmark inputs, that clusters contain measurable non-conflicting antichains on the apply critical path. The existence of comments preserving future scheduler flexibility is not sufficient; for optimize-soroswap, the workload must actually contain sparse intra-cluster conflict graphs rather than pairwise-conflicting hot-pair clusters.
