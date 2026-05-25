# H001: Cross-Stage Ready-Queue Scheduler for Soroban Apply Clusters

**Date**: 2026-05-25
**Subsystem**: soroban / ledger parallel apply
**Severity**: High
**Impact**: reduce soroswap apply time by removing conservative full-stage barriers in the dominant parallel apply phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban parallel apply should execute any cluster whose read/write dependencies have been satisfied, up to `ledgerMaxDependentTxClusters` workers, while preserving the deterministic transaction result order and final ledger state. A cluster in a later `ApplyStage` that does not depend on the still-running clusters from earlier stages should be allowed to start as soon as a configured worker is free; it should not wait for an unrelated slow cluster just because both clusters are separated by the coarse `TxStageFrameList` stage boundary.

## Mechanism

`LedgerManagerImpl::applySorobanStages` currently applies stages with a strict barrier: for every stage it runs `applySorobanStage`, waits for every cluster future in `applySorobanStageClustersInParallel`, merges all thread states into global state, and only then starts the next stage. The generalized transaction set stages are a conservative scheduling artifact produced by `ParallelTxSetBuilder`; transactions can be in a later stage because of per-stage instruction capacity or a conflict with one lane, not necessarily because they depend on every cluster in the previous stage. Recomputing or retaining a deterministic cluster dependency graph at apply time would turn this into a ready queue: only true predecessor clusters block a successor, reducing idle time without exceeding `ledgerMaxDependentTxClusters` or changing observable order.

## Trigger

Run the current soroswap apply-load scenario from `ai-summary/CURRENT_STATE.md` (`TX=2000, T=8`). The current Tracy trace has 43 `applySorobanStageClustersInParallel` windows under `applyLedger`, with 2,752,707,259 ns total wall duration and high variance (`std_ns` 144,879,149). A stage-level barrier makes faster lanes idle until the slowest lane in the stage completes, then repeats this across 43 stages.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` serially iterates `for (auto const& stage : stages)`.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` enforces per-stage apply, invariant check, global merge, and thread-state destruction before the next stage.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one future per stage cluster and blocks on every `future.get()`.
- `src/herder/ParallelTxSetBuilder.cpp:457-565` — stages are produced by greedy capacity/conflict packing; later stages are not a minimal apply-time dependency DAG.
- `src/herder/ParallelTxSetBuilder.cpp:567-698` — footprint conflict information already exists during construction and can be recomputed deterministically from transaction footprints if not retained.

## Evidence

- Tracy confirms this is inside the measured apply path: `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` has 71 windows; all 43 `applySorobanStageClustersInParallel` windows overlap those apply windows.
- `applySorobanStageClustersInParallel` is the largest apply-path wall-clock envelope in the current soroswap trace: 2.752s total across 43 calls, with max stage window 390.6ms and very high variance. This is not TX-set construction and not lazy bucket work.
- Source structure shows a coarse barrier after every stage. The builder comments describe clusters and bins as scheduling constructs bounded by `ledgerMaxDependentTxClusters`; apply currently treats each emitted stage as an all-cluster barrier rather than checking whether individual later clusters are ready.
- The theory of improvement targets wall idle time, not a micro-optimization. Even recovering a modest fraction of the 2.75s stage-window envelope can exceed the 3% Medium floor; a substantial reduction in barrier idle time would be High-tier for soroswap.

## Anti-Evidence

- The existing fail record for intra-cluster debinning found that soroswap clusters themselves are genuinely conflicting, so this hypothesis must not rely on splitting a cluster internally. It targets dependencies between clusters across stage boundaries.
- Correctness requires deterministic scheduling and deterministic merge order. A viable implementation must compute predecessor counts from canonical footprint conflicts, cap active workers at `ledgerMaxDependentTxClusters`, and commit results in the original transaction-result order even if execution completes out of order.
- If every later-stage cluster depends on at least one still-running cluster from every previous-stage lane, the ready queue degenerates to the current barrier and the hypothesis fails.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The apply path constructs `ApplyStage` objects from the generalized Soroban phase, creates one `GlobalParallelApplyLedgerState`, and then serially calls `applySorobanStage` for each stage. Each stage launches all current-stage clusters, waits for every future, checks per-tx invariants, commits all thread states into the global state, and only then starts the next stage. The tx-set builder and validator only guarantee no read/write conflicts between clusters within the same stage; they do not prove that a later-stage cluster depends on every earlier-stage cluster, so a dependency-aware scheduler can preserve semantics while removing unrelated full-stage waits.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` builds `ApplyStage`/`TxBundle` objects in canonical tx order, assigns stable `txNum` indexes, and calls `applySorobanStages`; result/meta ordering is later driven by `txNum`, not by worker completion order.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster, launches each via `std::async`, and blocks on every future before returning.
- `src/ledger/LedgerManagerImpl.cpp:2622-2705` — `applySorobanStage` and `applySorobanStages` impose the hard stage barrier: worker completion, invariant checks, `commitChangesFromThreads`, and thread-state destruction all complete for stage N before any cluster in stage N+1 starts.
- `src/transactions/ParallelApplyUtils.cpp:29-102` — comments define the footprint conflict model and explicitly describe future schedulers using partial orders while preserving observable RoTTL bump/write ordering.
- `src/transactions/ParallelApplyUtils.cpp:907-922` — `commitChangesFromThreads` already merges a stage's completed thread states deterministically on the apply thread using the stage read/write set; a ready-queue design must retain deterministic commit for completed clusters whose predecessors are satisfied.
- `src/herder/ParallelTxSetBuilder.cpp:57-93, 109-217, 400-426` — builder clusters transactions by true footprint conflicts, then bin-packs independent logical clusters into at most `ledgerMaxDependentTxClusters` artificial bins; bins are scheduling artifacts, not necessarily true dependency units across all stages.
- `src/herder/ParallelTxSetBuilder.cpp:457-565` — transactions are greedily packed into one of several stages because of resource capacity and conflicts with that stage, so failure to fit an earlier stage does not imply dependency on every cluster in that earlier stage.
- `src/herder/TxSetFrame.cpp:2290-2440` — validation caps clusters per stage, computes sequential instruction budget as the sum of per-stage max-cluster instructions, and checks only intra-stage read/write conflicts; cross-stage conflicts are allowed and are therefore the dependency edges a scheduler would need to honor.
- `src/herder/TxSetUtils.cpp:200-223` and `src/herder/TxSetFrame.cpp:1950-2007` — stages, clusters, and transactions are normalized into hash order, giving a deterministic canonical order from which predecessor edges and result order can be derived.
- `ai-summary/fail/soroban/summary.md:107,114,169-170` — adjacent failures cover intra-cluster debinning, apply-side cluster-size rebalancing, thread-state setup, and post-join serial loops, but not cross-stage scheduling of already-formed clusters.

### Findings

The inefficiency exists and is in the hot path. The current benchmark's phase timings show `soroban_parallel` as the dominant apply subphase (median about 150 ms out of a roughly 208 ms soroswap median), and the traced code confirms a repeated full-stage barrier inside this phase. This is not tx-set construction, classic apply, lazy bucket work, or background merge work.

The proposed fix is structurally correct if it preserves the existing canonical order for dependency construction and commit. A later cluster may start only after all earlier canonical clusters with intersecting RW-vs-RO/RW footprints have committed their thread state into the global state; non-conflicting earlier clusters need not block it. Active workers must remain capped at `ledgerMaxDependentTxClusters`, and result/meta emission must continue to use `TxBundle::getTxNum()` order.

The impact is plausible at the objective's Medium floor but not proven High at review. The dominant target is wall idle time between stage lanes, and soroswap is intentionally shaped as eight independent pairs for eight configured clusters, so cross-stage lane pipelining can recover repeated slowest-lane waits without splitting genuinely conflicting intra-pair clusters. However the review did not measure the actual ready-queue critical path, so the severity is corrected from High to Medium pending PoC benchmark confirmation.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp::{applySorobanStages,applySorobanStage,applySorobanStageClustersInParallel}` and `src/transactions/ParallelApplyUtils.{h,cpp}` merge helpers; avoid changing tx-set construction unless retaining dependency metadata proves simpler and deterministic.
- **Change description**: Flatten `std::vector<ApplyStage>` into canonical cluster nodes, compute predecessor counts from read/write footprint conflicts against earlier canonical clusters, and run a deterministic ready queue capped at `sorobanConfig.ledgerMaxDependentTxClusters()`. When a cluster finishes, commit its thread state on the apply thread before releasing dependent successors. Preserve `TxBundle::getTxNum()` for PRNG seeds, post-apply, result, and metadata order.
- **Correctness check**: Existing parallel Soroban apply tests should cover conflict validation, deterministic result ordering, PRNG/result replay, RoTTL bump behavior, and post-tx-set refund/meta processing. Add focused tests only if needed to show a later-stage non-conflicting cluster can run before an earlier-stage unrelated cluster while a conflicting later-stage cluster still waits.
- **Benchmark focus**: Use `scripts/run_apply_load_matrix.py` on `soroswap, TX=2000, T=8`; the metric that must improve is median apply time across repeated non-Tracy runs. Also record stage/ready-queue critical-path stats: number of ready-queue nodes, dependency-edge count, maximum active workers, and current-barrier critical path vs scheduled critical path.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-25
**PoC by**: gpt-5.5, high

### Changes Made

- `src/ledger/LedgerManagerImpl.cpp:2580-2635` and `src/ledger/LedgerManagerImpl.h:385-393` — split invariant/refund-meta processing so it can run for a completed cluster while preserving the existing stage helper.
- `src/ledger/LedgerManagerImpl.cpp:2716-2928` — replaced the full-stage loop in `applySorobanStages` with a flattened canonical cluster graph, read/write-footprint predecessor counts, and a deterministic ready queue capped by `ledgerMaxDependentTxClusters`.
- `src/transactions/ParallelApplyUtils.cpp:104-144,938-948` and `src/transactions/ParallelApplyUtils.h:264-271` — factored read/write key collection to cluster granularity and added a single-cluster commit helper so completed ready-queue nodes can merge before releasing successors.

### Demonstration

The production apply path now starts any cluster whose earlier read/write conflicts have committed, instead of waiting for every cluster in the current `ApplyStage` to finish. Conflicting later clusters still wait on all canonical predecessors, while independent later clusters can occupy free workers immediately and retain existing `TxBundle::getTxNum()`-based PRNG/result/meta ordering.

### Test Results

`make -j30` completed successfully. `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check` completed successfully with exit code 0, covering the full lib, C++, and Soroban Rust test suites.
