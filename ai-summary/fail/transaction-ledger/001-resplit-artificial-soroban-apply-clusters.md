# H001: Re-split artificial Soroban apply clusters for load-balanced worker scheduling

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / parallel Soroban apply
**Severity**: High
**Impact**: Soroswap apply-time reduction by removing long-tail worker imbalance inside `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban stage contains independent transactions or independent connected components that were packed into the same XDR `DependentTxCluster` only to respect the `ledgerMaxDependentTxClusters` cap, the apply path should still keep at most `NUM_CLUSTERS` workers busy by scheduling those independent components dynamically. The ledger effects, transaction results, PRNG sub-seeds, read-only TTL bump merges, and final commit order should remain deterministic and byte-for-byte equivalent to today's cluster-order application.

## Mechanism

`ParallelTxSetBuilder` explicitly treats final XDR clusters as artificial bins as well as true dependency components: comments in `src/herder/ParallelTxSetBuilder.cpp:400-426` explain that hundreds of independent logical clusters may be packed into `ledgerMaxDependentTxClusters` bins. `LedgerManagerImpl::applySorobanStageClustersInParallel` (`src/ledger/LedgerManagerImpl.cpp:2530-2574`) then creates exactly one `std::async` worker per final `ApplyStage` cluster and applies every `TxBundle` in that cluster serially. If one final cluster contains more independent work than the others, the whole stage duration becomes that one worker's runtime even though other workers are idle.

The current soroswap trace shows this exact long-tail shape in the longest `applyLedger` interval. Worker thread 4132 executes 309 `InvokeHostFunctionOpFrame doParallelApply` events totaling **907.564 ms**, while the other seven workers execute only 172-173 events totaling **528.522-535.211 ms** each. The same skew appears in `Vm::invoke_function_raw` (thread 4132: **928 calls / 916.814 ms**; other workers: ~517-520 calls / 530-541 ms). Recomputing fine-grained conflict components inside each stage, then feeding those components to a deterministic `NUM_CLUSTERS`-bounded work queue, would let idle workers pick up independent components from the overloaded bin. A perfect balance of the cited `doParallelApply` worker time would reduce the stage tail from ~908 ms toward ~578 ms, a >10% improvement on the 596 ms headline soroswap median if the imbalance is representative.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=4000, T=8`) with the Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. In the longest `applyLedger` window (`ledger/LedgerManagerImpl.cpp:1484`, 1,711.471 ms), group `InvokeHostFunctionOpFrame doParallelApply`, `Host::invoke_function`, and `Vm::invoke_function_raw` events by thread. The triggering condition is a stage where one final apply cluster has substantially more work than the other clusters even though the stage still has independent footprint components that could be scheduled separately.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` currently binds one worker future to one final `ApplyStage` cluster.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` waits for all cluster workers, checks invariants, and merges thread states after the stage.
- `src/transactions/ParallelApplyStage.h:116-157` — `Cluster` is just `std::vector<TxBundle>` and `ApplyStage` stores final clusters without retaining fine-grained dependency components.
- `src/herder/ParallelTxSetBuilder.cpp:400-426` — final clusters can be artificial super-clusters formed by bin-packing independent logical clusters down to the network parallelism cap.
- `src/herder/TxSetFrame.cpp:2394-2440` — validation requires no cross-cluster read/write conflicts within a stage; an apply-time re-split must preserve that property for subcomponents.
- `src/simulation/ApplyLoad.cpp:3389-3475` — soroswap swaps are generated round-robin over pair-specific footprints to create independent work for the configured cluster count.

## Evidence

- Tracy scope check: the imbalanced worker events are inside the longest `applyLedger` window and under `applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`, so they are in the measured close-ledger apply path, not TX set construction.
- `applySorobanStageClustersInParallel` launches one async task per final cluster and then waits for each future; there is no work-stealing once a worker finishes its assigned cluster.
- `ParallelTxSetBuilder` comments distinguish true dependency clusters from artificial bins used only to fit the cluster cap, implying that some serialized work inside a final cluster can be independent.
- The observed longest-window skew is large enough to matter: the heaviest worker's `doParallelApply` time is ~1.7x a normal worker. Even recovering half of the ~370 ms tail gap in that interval would exceed the objective's High threshold.
- Determinism can be preserved by using original transaction numbers for PRNG seeds and result ordering, applying only mutually non-conflicting subcomponents in parallel, and merging component/thread effects in a fixed stage/cluster/tx order after execution.

## Anti-Evidence

- The PoC must prove that the overloaded final cluster actually contains multiple independent footprint components. If it is a true dependency component, re-splitting will discover one component and provide no benefit.
- `ThreadParallelApplyLedgerState` ownership is currently built around one thread state per final cluster. A dynamic scheduler may need one state per fine-grained component or a worker-local state that can safely process multiple disjoint components and merge them deterministically.
- Recomputing connected components from footprints inside `applyLedger` adds measured overhead. It must be cheap enough, or cached from existing stage construction artifacts without targeting TX-set-construction runtime.
- Read-only TTL bumps and restored-entry tracking have merge rules that assume conflict-free cluster ownership. The re-split must keep the same max-TTL semantics and commit order for RO TTL bumps.
- The current trace captures one especially long apply window; repeated benchmark runs must confirm the imbalance is stable and not a Tracy-capture artifact.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no fail/success record investigated apply-time re-splitting of artificial Soroban bins; the closest prior failure only covered misattributing `applySorobanStageClustersInParallel` self-time to thread-state construction
**Failed At**: reviewer

### Trace Summary

The one-worker-per-final-cluster scheduler exists: `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` and one `std::async` future for each `ApplyStage` cluster, and `applyThread` then applies all transactions in that cluster serially before the main apply thread merges the completed thread states. `ParallelTxSetBuilder` can indeed pack more fine-grained dependency components into artificial bins when a stage has more logical components than `ledgerMaxDependentTxClusters`. However, the current soroswap benchmark shape does not create those artificial super-clusters: it configures `ledgerMaxDependentTxClusters` from `T`, creates exactly that many swap pairs, round-robins swaps across those pairs, and asserts the resulting apply has one stage with exactly that many final clusters. The overloaded worker shown in the trace therefore is not evidence of independent components hidden inside one final cluster; for this benchmark, each final cluster is a true pair-specific dependency component whose transactions share read-write pair state.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:417-424` — the `T=8` scenario sets `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` to the scenario thread count.
- `src/simulation/ApplyLoad.cpp:400-413` — apply-load upgrades Soroban network config so `ledgerMaxDependentTxClusters` equals `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.
- `src/simulation/ApplyLoad.cpp:768-790` — max-TPS mode sizes ledger instruction capacity by dividing total modeled instructions over the configured dependent cluster count, reinforcing the intended one-bin-per-cluster shape.
- `src/simulation/ApplyLoad.cpp:2261-2334` — the benchmark times `closeLedger`, then asserts one Soroban apply stage and `max-clusters == APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.
- `src/simulation/ApplyLoad.cpp:2672-2678` — soroswap setup creates exactly one token pair per configured dependent cluster/bin.
- `src/simulation/ApplyLoad.cpp:3389-3475` — swaps are round-robined across pairs; same-pair transactions share read-write SAC balance keys and the pair contract instance, while different pairs share only read-only router/code/SAC-instance keys and unique account trustlines.
- `src/herder/ParallelTxSetBuilder.cpp:57-85` and `567-699` — logical clusters are built from transitive read/write footprint conflicts; same-pair soroswap swaps merge into one true dependency cluster, while different pairs do not conflict.
- `src/herder/ParallelTxSetBuilder.cpp:88-107`, `276-303`, and `400-426` — a stage may pack many independent logical clusters into `ledgerMaxDependentTxClusters` bins, but that artificial-bin case requires more logical components than the configured cluster cap.
- `src/herder/ParallelTxSetBuilder.cpp:522-544` — the emitted XDR stage clusters are the final bins, so apply sees only one final cluster per bin.
- `src/herder/TxSetFrame.cpp:2328-2340` and `2394-2440` — validation enforces the per-stage cluster count cap and rejects cross-cluster read/write conflicts.
- `src/transactions/ParallelApplyStage.h:116-157` — `ApplyStage` retains final `Cluster` vectors only, with no record of the builder's pre-bin logical components.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520`, `2530-2574`, and `2622-2670` — each final cluster is executed by one async worker and then merged after all futures complete.

### Why It Failed

The hypothesis targets the wrong cause for the observed soroswap worker skew. Re-splitting a final cluster only helps when that cluster is an artificial bin containing multiple independent footprint components. In the reviewed `soroswap, TX=4000, T=8` path, the generator deliberately creates exactly eight true pair components for eight configured bins; the benchmark asserts one stage with eight clusters, and every transaction inside a pair component conflicts through the pair contract instance and pair SAC balance keys. Recomputing connected components inside any overloaded pair cluster would therefore return the same single component, leaving no extra work for idle workers to steal.

This does not disprove that artificial bins can occur in arbitrary Soroban tx sets, but the optimize-soroswap objective requires impact on the soroswap apply benchmark. The cited per-thread `doParallelApply` counts also do not line up with the benchmark's source-level invariants for a full `TX=4000, T=8` soroswap ledger, so the trace needs a different explanation such as a non-benchmark/setup ledger, a filtered Tracy window, per-transaction cost variation, or true dependency-component imbalance. Under the actual soroswap code path, an apply-time re-split would add footprint graph reconstruction and scheduler complexity without producing the claimed independent subcomponents or a Medium/High apply-time reduction.

### Lesson Learned

For parallel-apply load-balancing hypotheses, first prove that the hot final cluster is an artificial bin rather than a true dependency component. The soroswap apply-load benchmark is constructed to use exactly one true pair dependency component per configured cluster/bin, so observed worker-tail skew in this benchmark should be investigated as true component imbalance or trace/window selection before proposing bin re-splitting.
