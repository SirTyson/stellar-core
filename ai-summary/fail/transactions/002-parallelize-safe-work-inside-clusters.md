# H002: Parallelize Safe Work Inside Soroban Apply Clusters

**Date**: 2026-04-29
**Subsystem**: transactions, ledger
**Severity**: High
**Impact**: restructure the dominant `soroban_parallel` phase by exploiting deterministic sub-cluster parallelism
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban stage should produce the same transaction results, ledger entries, TTL bumps, events, metadata, refundable fees, and PRNG-derived behavior as the current implementation. Transactions whose effects are order-dependent must remain ordered exactly as today, read-only TTL bumps must still be flushed before any write that can observe them, and the implementation must never run more workers than the configured cluster/ledger-close worker cap. Results must be merged in deterministic transaction/cluster order, not completion order.

## Mechanism

`LedgerManagerImpl::applyThread` currently applies every transaction in a cluster sequentially, even though `ParallelApplyUtils.cpp` documents that a cluster may contain groups of read-only TTL bumps and writes where only a partial order is required. A per-cluster scheduler could build a small dependency graph from each transaction's read-write footprint and read-only TTL bump set, then run independent groups on idle workers while preserving barriers before conflicting writes and reducing returned `ParallelTxReturnVal`s in canonical tx order. This targets a different mechanism than the already-reviewed worker-pool hypothesis: it does not just reduce `std::async` lifecycle overhead, it reduces the amount of soroswap host invocation work forced onto a single slow cluster lane.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, `TX=2000`, `T=8`) and inspect the trace from `ai-summary/CURRENT_STATE.md`. The diagnostic trace shows `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with 4.179839638 s under `applyLedger`, while non-Tracy phase logs show `soroban_parallel` as the dominant per-ledger phase at roughly 236-252 ms median. The issue triggers when a stage has fewer effective long-running cluster lanes than available worker capacity, or when a large cluster contains independent read-only-TTL groups separated by a smaller number of write barriers.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:29-103` — documents the read-only TTL bump partial-order model and explicitly notes future schedulers can run non-conflicting work inside a cluster.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` currently loops over `TxBundle`s in a cluster sequentially and flushes read-only TTL bumps before each write footprint and at cluster end.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` schedules only whole clusters, leaving no way to use idle workers for independent intra-cluster work.
- `src/transactions/ParallelApplyUtils.cpp:1004-1063` — read-only TTL bump flushing is the key ordering constraint that a sub-cluster scheduler must preserve.
- `src/transactions/ParallelApplyStage.h:116-158` — `ApplyStage` and `Cluster` expose deterministic transaction order for stable result collection.

## Evidence

The current code already models the correctness constraints for this redesign: two transactions conflict when either read-write footprint intersects the other's read-only or read-write footprint, while read-only TTL bumps can commute and are merged with `std::max()` when safe. The hot path is clearly inside `applyLedger`: `applySorobanStages` totals 4.397943881 s in the current trace, `applySorobanStageClustersInParallel` totals 4.179839638 s, and worker `parallelApply` totals roughly 10.19 s aggregate across clusters. Because the accepted non-Tracy baseline has `soroban_parallel` consuming most of the soroswap close time, a scheduler that converts long sequential cluster tails into deterministic bounded parallel sub-stages can plausibly clear Medium and may qualify as a High-tier dominant-phase redesign.

## Anti-Evidence

If the soroswap cluster builder already emits clusters whose transactions all conflict through the same pair reserve writes, there may be little intra-cluster parallelism to exploit. The redesign is correctness-sensitive: RO TTL bump deferral affects fees, writes observe prior bumps, and metadata/result emission must remain canonical. A PoC should first log or trace per-cluster dependency graphs and idle-worker time to prove that enough safe sub-cluster work exists before implementing a full scheduler.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/transactions`, `ai-summary/success/transactions`, or the cross-subsystem fail/success records available in this tree
**Failed At**: reviewer

### Trace Summary

The architectural observation is real: `applyThread` executes every `TxBundle` in a final `Cluster` serially, and both `TxSetFrame.h` and `ParallelApplyUtils.cpp` explicitly leave room for some intra-cluster transactions to be independent. However, the target soroswap benchmark is deliberately constructed to avoid artificial binning: it creates exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` pairs for the same number of configured cluster lanes, round-robins swaps across those pairs, and sizes the ledger instruction limit so all available clusters are filled. Within a given pair lane, every swap writes the same pair contract instance and the same pair-owned SAC balance keys, so all swaps for that pair are direct RW/RW conflicts. A sub-cluster scheduler therefore has no meaningful independent host-invocation work to expose on the measured soroswap hot path.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:29-103` — documents the current conflict model and future partial-order scheduler possibility for RO TTL bump groups versus writes.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` loops over a cluster sequentially, flushes pending RO TTL bumps before each transaction's write footprint, calls `parallelApply`, then commits successful tx changes into the thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` and one async worker per final cluster, then waits on those futures in deterministic order.
- `src/herder/TxSetFrame.h:281-300` — final clusters generally apply sequentially, but the comments acknowledge that not every transaction inside a cluster is necessarily conflicting.
- `src/herder/ParallelTxSetBuilder.cpp:57-60,121-132,400-425,522-544` — builder clusters are transitive conflict groups, then independent logical clusters may be bin-packed into at most `ledgerMaxDependentTxClusters` final XDR clusters; such bins are "artificial super-clusters" only when independent logical clusters outnumber the cluster cap.
- `src/herder/ParallelTxSetBuilder.cpp:577-694` — conflicts are marked only for RW/RW and RO/RW shared footprint hashes; RO/RO sharing such as common router/code/SAC instance reads does not merge transactions.
- `scripts/run_apply_load_matrix.py:120-124,417-424` — the measured soroswap scenario is `TX=2000, T=8`, rendered as `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS = 8`.
- `src/simulation/ApplyLoad.cpp:489-493,769-791,1056-1067` — benchmark setup upgrades ledger limits from the requested tx count and cluster count specifically to generate a full ledger and fill all available clusters.
- `src/simulation/ApplyLoad.cpp:2672-2678` — soroswap setup creates exactly one token pair per configured dependent cluster lane.
- `src/simulation/ApplyLoad.cpp:3389-3400` — benchmark tx generation round-robins swaps across those pairs and uses a unique source account per transaction.
- `src/simulation/ApplyLoad.cpp:3447-3475` — each swap's read-only footprint contains router/SAC/code entries, but each swap's read-write footprint contains the user trustlines plus the pair-owned SAC balances and pair contract instance; all swaps for the same pair share the latter RW keys.

### Why It Failed

This fails the objective-specific Medium threshold because the measured soroswap workload does not contain the independent intra-cluster work the hypothesis depends on. The current final-cluster abstraction can contain independent logical clusters in general, and a future scheduler might help a workload with many more independent components than the configured `ledgerMaxDependentTxClusters` cap or with RO-TTL-only groups around sparse writes. But the soroswap benchmark already creates exactly one logical conflicting pair lane per configured lane, and each pair lane is a direct conflict clique through the pair instance and reserve balance writes. Running a dependency scheduler inside those lanes would add graph construction, task dispatch, merge, and synchronization overhead while finding no parallelizable host invocations, so it cannot plausibly produce the required 3-10% apply-time improvement for this objective.

### Lesson Learned

Do not infer intra-cluster parallelism from the final `DependentTxCluster` type alone. For soroswap, the benchmark generator intentionally shapes the workload to match the configured lane count, and the per-pair footprint makes each lane genuinely sequential; proposed cluster-internal schedulers must first prove artificial binning or sparse intra-cluster dependency structure in the actual benchmark trace.
