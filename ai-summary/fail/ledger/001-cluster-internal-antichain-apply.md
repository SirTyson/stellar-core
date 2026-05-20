# H001: Apply independent antichains inside oversized Soroban clusters

**Date**: 2026-05-20  
**Subsystem**: ledger / parallel Soroban apply  
**Severity**: High  
**Impact**: Dominant-phase redesign targeting the `soroban_parallel` median of 227.95 ms, with plausible >10% soroswap apply-time reduction if large clusters contain independent internal antichains  
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap ledgers should use up to `NUM_CLUSTERS` workers for all transaction work that is independent under Soroban footprints. Transactions whose read-write footprints do not conflict should not wait behind unrelated transactions merely because the tx-set cluster is a connected component rather than a fully ordered dependency chain. The observable ledger result, transaction result order, metadata order, PRNG sub-seeds, and fee/refund accounting should remain in consensus transaction order.

## Mechanism

`TxSetFrame.h` explicitly states that a `TxClusterFrame` "generally" runs sequentially but may contain transactions that can be applied in parallel with each other depending on their footprints. The current apply path gives each cluster to one worker and `applyThread` then applies every `TxBundle` in that cluster sequentially, so any independent antichains inside a large soroswap pool/router cluster serialize inside `applySorobanStageClustersInParallel`. A deterministic in-cluster scheduler could build dependency layers from the already-available footprints, run layer members in parallel while capping total workers at `NUM_CLUSTERS`, and merge per-tx effects back in the original `txNum` order.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the soroswap scenario (`TX=2000, T=8`) and inspect ledgers where one or more clusters contain many transactions connected transitively but not pairwise conflicting. The current path will show those transactions executing serially in a single `applyThread`; the proposed path should execute independent subgroups concurrently while producing byte-identical results.

## Target Code

- `src/herder/TxSetFrame.h:281-300` — documents that cluster contents are not necessarily all mutually conflicting and may contain additional parallelism.
- `src/ledger/LedgerManagerImpl.cpp:2480-2520` — `applyThread` loops over every transaction in a cluster sequentially.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one future per cluster and waits for cluster completion.
- `src/transactions/ParallelApplyStage.h:116-157` — `Cluster` is currently only a vector of `TxBundle`, with no representation of internal dependency layers.

## Evidence

The accepted soroswap trace confirms this target is entirely inside `applyLedger`: `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` accounts for 3,520,949,405 ns total across 43 calls, all overlapping `applyLedger`, and the benchmark log reports `soroban_parallel` as the dominant measured phase (median 218.12 ms, mean 227.95 ms, p99 498.74 ms). The workload setup log reports "Soroswap setup: 9 tokens, 8 pairs for 8 clusters", so the benchmark intentionally runs at the configured cluster count; any additional exploitable parallelism has to come from within clusters rather than by exceeding `NUM_CLUSTERS`.

## Anti-Evidence

Many soroswap transactions against the same pair may genuinely conflict on pool reserves, and splitting them would be impossible without changing semantics. The scheduler must also avoid the previously failed "parallelize cluster state setup" pattern: it should not add broad concurrent footprint walks that increase memory/cache pressure, and it must preserve deterministic merge order instead of letting worker completion order affect ledger output.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The apply-path serialization claim is real in the generic code path: `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` and one future per XDR cluster, and `applyThread` walks that cluster's `TxBundle`s sequentially. However, the soroswap benchmark generator constructs exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` token pairs and emits swaps round-robin across those pairs, so the transaction-set builder has one logical conflicting group per configured bin rather than oversized bins containing extra independent groups. Within each pair group, every swap writes the pair instance and both pair SAC balance keys, so same-pair transactions are pairwise conflicting and cannot be layered into independent antichains without changing observable pool-reserve semantics.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies all transactions in a `Cluster` sequentially and commits successful transaction changes into the same `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one async worker per stage cluster, capped by the number of XDR clusters in the stage.
- `src/herder/ParallelTxSetBuilder.cpp:57-86, 400-435, 522-544` — the builder first forms logical conflict clusters, then packs excess independent clusters into at most `ledgerMaxDependentTxClusters` bins; an XDR `DependentTxCluster` can be an artificial super-cluster, but only when independent logical clusters outnumber configured bins.
- `src/simulation/ApplyLoad.cpp:2672-2682` — soroswap setup creates exactly one token pair per configured cluster/bin.
- `src/simulation/ApplyLoad.cpp:3389-3403, 3447-3475` — swaps are distributed round-robin across pairs, and each swap writes unique user trustlines plus the selected pair's two SAC pool balances and pair contract instance; all swaps for the same pair therefore conflict pairwise.
- `scripts/run_apply_load_matrix.py:120-124, 417-424` — the active soroswap scenario uses `tx_count=2000`, `thread_count=8`, and passes that thread count through to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.

### Why It Failed

The proposed optimization depends on large soroswap clusters containing independent internal antichains. The target workload is deliberately shaped to avoid that condition: it creates eight pairs for eight configured clusters, and the per-pair swaps that fill each cluster are genuinely pairwise write-conflicting on pool state. A generic in-cluster scheduler might help some other overloaded or artificially binned transaction set, but it does not provide a Medium/High soroswap apply-time opportunity for this objective.

### Lesson Learned

For soroswap parallel-apply hypotheses, distinguish protocol-level cluster flexibility from the benchmark's generated footprint topology. `TxClusterFrame` can represent artificial bins in general, but the active soroswap matrix is constructed so each bin corresponds to one real pair-level conflict group; extra parallelism must come from changing the workload topology or optimizing per-swap execution, not from splitting same-pair clusters.
