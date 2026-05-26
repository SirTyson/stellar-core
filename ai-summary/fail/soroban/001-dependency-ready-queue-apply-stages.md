# H001: Dependency-ready Soroban apply scheduler to remove full-stage barriers

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap `closeLedger` parallel-apply wall time
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban parallel apply should keep at most `NUM_CLUSTERS` workers busy with any cluster whose footprint dependencies have been satisfied, while preserving deterministic transaction effects, metadata, result ordering, and ledger-entry merge order. A cluster in a later logical stage that has no unresolved dependency on currently running earlier-stage clusters should not wait behind unrelated slow clusters merely because `ApplyStage` is used as a full barrier.

## Mechanism

`LedgerManagerImpl::applySorobanStages` currently iterates stages serially and calls `applySorobanStage` for each stage. `applySorobanStage` then calls `applySorobanStageClustersInParallel`, waits for every cluster in the stage to complete, commits all thread changes for that stage, and only then advances to the next stage. In the current soroswap trace, the apply-contained unwrap export reports `applySorobanStages` at **3,012,151,266 ns total across 71 applyLedger windows** and `applySorobanStageClustersInParallel` at **2,718,087,904 ns total across 43 stage calls** (`ledger/LedgerManagerImpl.cpp:2537`), all inside `applyLedger`; this is the dominant measured apply phase after prior storage/metering wins. If the stage partition contains conservative barriers where only some clusters conflict across adjacent stages, a deterministic ready queue over the stage/cluster dependency DAG could start independent later clusters earlier and reduce the critical path without changing the final ordered commit.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` for `soroswap, TX=2000, T=8` on the current baseline. Inspect the soroswap trace from `ai-summary/CURRENT_STATE.md` and verify that many `applySorobanStageClustersInParallel` windows are separated by stage barriers under a single `applyLedger` window. A PoC should construct a ready queue from the same ordered `ApplyStage` list and run no more than `NUM_CLUSTERS` clusters concurrently, then benchmark three non-Tracy soroswap runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2570` — `applySorobanStageClustersInParallel` launches all clusters in one stage and joins every future before returning.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` imposes a per-stage apply/commit/destroy sequence.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` serializes all `ApplyStage`s.
- `src/transactions/ParallelApplyStage.h` — `ApplyStage`, `Cluster`, and `TxBundle` ordering constraints that the ready queue must preserve.
- `src/transactions/ParallelApplyUtils.cpp:898-940` — `commitChangesFromThread(s)` and global-state merge points that must remain deterministically ordered.

## Evidence

- Current soroswap diagnostic trace:
  `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`.
- `csvexport-release -u` containment check found `applySorobanStages` and `applySorobanStageClustersInParallel` events wholly inside `applyLedger`, not TX-set construction.
- Apply-contained aggregate totals from the trace:
  - `applySorobanStages,ledger/LedgerManagerImpl.cpp:2678`: 3,012,151,266 ns / 71 calls.
  - `applySorobanStageClustersInParallel,ledger/LedgerManagerImpl.cpp:2537`: 2,718,087,904 ns / 43 calls.
  - `parallelApply`/`InvokeHostFunctionOpFrame doParallelApply` worker totals exceed 11.5 s aggregate, so shortening the worker critical path by even part of a stage barrier can plausibly clear the 3% Medium threshold.
- The proposed scheduler does not exceed `NUM_CLUSTERS`; it changes when ready clusters start, not how many workers execute concurrently.

## Anti-Evidence

- If every later-stage cluster depends on the slowest earlier-stage cluster in soroswap, a ready queue degenerates to the existing full-barrier schedule and saves nothing.
- The commit path must preserve deterministic observable order. A viable PoC must buffer completed cluster results and commit in the same logical stage/cluster/transaction order, or prove an equivalent deterministic ordering over disjoint write sets.
- Worker overlap must not race `GlobalParallelApplyLedgerState` mutation: completed clusters may need per-cluster deltas held outside the global map until their deterministic commit point.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-cross-stage-ready-queue-scheduler.md + 002-carry-lane-state-across-stages.md`
**Failed At**: reviewer

### Trace Summary

The target code still matches the described scheduling surface: `applyParallelPhase` builds ordered `ApplyStage`/cluster bundles, `applySorobanStages` iterates stages serially, each `applySorobanStage` waits for all futures from `applySorobanStageClustersInParallel`, and only then commits the stage's thread states into `GlobalParallelApplyLedgerState`. The tx-set builder also confirms that final `DependentTxCluster` bins can be artificial super-clusters created to cap parallelism, which is the same surface a cross-stage ready queue would target. However, the Soroban fail summary already records this exact cross-stage ready-queue scheduler investigation, including the deterministic commit-order requirements and the note that the PoC passed but final review rejected it because no admissible benchmark could be produced after a test-infrastructure failure.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` converts tx-set stages to `ApplyStage` bundles, preserves `TxBundle::getTxNum()` ordering for PRNG/meta/result indexing, then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one future per cluster in the current stage and joins every future before returning thread states.
- `src/ledger/LedgerManagerImpl.cpp:2622-2724` — `applySorobanStage` performs apply, invariant checking, commit, and thread-state destruction per stage; `applySorobanStages` loops over stages serially and commits to `LedgerTxn` only after all stages complete.
- `src/transactions/ParallelApplyUtils.cpp:893-922` — `commitChangesFromThreads` merges stage thread states into the global state in deterministic stage/thread order using the stage read-write set.
- `src/herder/ParallelTxSetBuilder.cpp:400-426,474-551,703-800` — the builder forms dependency clusters and packs them into capped bins/stages; these bins may be artificial super-clusters and are selected before apply.

### Why It Failed

This is a duplicate, not a novel hypothesis. The prior fail-summary entry explicitly covers a "Cross-stage ready-queue scheduler for Soroban apply clusters" that replaces per-stage full barriers with a dependency-graph ready queue, with the same correctness constraints around canonical footprint conflicts, deterministic commit order, `ledgerMaxDependentTxClusters`, and `TxBundle::getTxNum()` ordering.

### Lesson Learned

Do not resubmit the cross-stage ready-queue scheduler as a new Soroban hypothesis unless there is materially new evidence or a clean rerun path that addresses the prior final-review rejection. The mechanism is real and already investigated; the pipeline needs novelty, not a second copy of the same scheduling surface.
