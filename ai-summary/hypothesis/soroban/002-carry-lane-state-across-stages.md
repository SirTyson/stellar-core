# H002: Carry Thread-Local Lane State Across Adjacent Soroban Stages

**Date**: 2026-05-25
**Subsystem**: soroban / ledger parallel apply
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding per-stage global merge barriers for lane-local dependent sequences
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a worker finishes a cluster and the next ready cluster depends only on state already owned by that same worker lane, the worker should continue with that next cluster using its current `ThreadParallelApplyLedgerState` rather than forcing a global merge and rebuilding a new thread state at the next stage boundary. The observable result should remain identical: all transaction results and metadata stay indexed by original tx number, and global ledger state is merged deterministically at dependency boundaries or at the end of the Soroban phase.

## Mechanism

`applySorobanStage` currently destroys all thread states after every stage: workers return `ThreadParallelApplyLedgerState`, the apply thread calls `globalParState.commitChangesFromThreads`, then `threadStates.clear()` before starting the next stage. For soroswap-shaped ledgers, each pool lane is a sequence of dependent swaps while other lanes are independent. The current stage barrier forces every lane to publish to global state after each stage, even when the next same-lane cluster could safely read the just-produced dirty entries directly from its thread state. A lane-carry design would keep a bounded set of worker-local states alive across adjacent ready clusters, only merging to global when a cross-lane successor needs the data or when the phase ends.

## Trigger

Run the current soroswap apply-load benchmark. In the current trace, `applySorobanStageClustersInParallel` has 43 calls under `applyLedger`; each call constructs fresh `ThreadParallelApplyLedgerState` objects in `LedgerManagerImpl::applySorobanStageClustersInParallel`, executes one cluster per future, merges all returned states in `applySorobanStage`, clears them, and repeats. The high `applySorobanStageClustersInParallel` wall variance indicates slowest-lane waits dominate the stage envelope.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2539-2554` — constructs a fresh `ThreadParallelApplyLedgerState` for every cluster in every stage.
- `src/ledger/LedgerManagerImpl.cpp:2556-2574` — waits for every stage future and returns all thread states at the barrier.
- `src/ledger/LedgerManagerImpl.cpp:2646-2664` — checks invariants, commits thread states to global, and clears thread state after every stage.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` constructor collects cluster footprint entries from global each time.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — thread-local `getLiveEntryOpt` already provides a coherent overlay that can serve later same-lane reads before global merge.

## Evidence

- Tracy shows the stage wrapper is the dominant measured apply envelope: `applySorobanStageClustersInParallel` totals 2,752,707,259 ns across 43 apply-contained calls in the current soroswap trace.
- Source inspection shows per-stage worker state is treated as disposable. Even though `commitChangesFromThread` self-time is small, the global-merge barrier is semantically tied to releasing the dirty state that a same-lane successor could otherwise consume directly.
- This targets a different slice than prior rejected thread-state setup work: the goal is not saving constructor self-time, but avoiding the all-lanes synchronization point by letting lane-local dependent sequences continue without publishing to global state between every adjacent stage.

## Anti-Evidence

- Prior thread-state-construction and persistent-executor proposals failed because setup and launch overhead were too small. This hypothesis is only viable if it removes slowest-lane barrier idle time; saving construction or merge self-time alone is sub-threshold.
- A worker-local state cannot be carried across arbitrary clusters. The scheduler must prove that the next cluster's predecessors are all either committed globally or present in that worker's carried state, and it must merge in a deterministic order before any cross-lane consumer observes the data.
- Invariant checks currently run after each stage. A viable implementation must either keep the same invariant-observable deltas at equivalent boundaries or explicitly preserve invariant checking by materializing deterministic per-cluster deltas without forcing a global merge.
