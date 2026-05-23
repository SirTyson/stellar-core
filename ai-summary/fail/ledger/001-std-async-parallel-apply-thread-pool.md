# H001: Replace per-stage std::async workers with a persistent apply thread pool

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Medium
**Impact**: Soroban parallel apply scheduling overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban stage should execute each cluster exactly once, collect worker results in deterministic cluster order, and merge writes exactly as today. Replacing per-stage `std::async` launches with a persistent executor would only be worthwhile if launch/join overhead were a material part of `applyLedger` time.

## Mechanism

The candidate mechanism was that `applySorobanStageClustersInParallel` creates futures for every stage and cluster, so a persistent pool capped at `NUM_CLUSTERS` might avoid repeated thread creation or scheduling overhead. The expected deviation would be excessive launcher overhead in the parent apply zone, causing wall time that could be reduced without changing deterministic result ordering.

## Trigger

Run the current soroswap apply-load benchmark with 8 clusters and inspect `applySorobanStageClustersInParallel` inside the `applyLedger` subtree. If most self/total time were in task launch or serial join overhead, a fixed worker pool would be a viable target.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` creates one `std::async` future per non-empty cluster and then calls `future.get()` in cluster order.
- `src/ledger/LedgerManagerImpl.cpp:2622-2705` — stage execution and merge remain deterministic after worker completion.

## Evidence

The broad Tracy zone `applySorobanStageClustersInParallel` is large in the current trace because it encloses worker execution and waits for workers. This initially made scheduler overhead appear attractive.

## Anti-Evidence

The zone is a parent/wait zone, not a measurement of `std::async` launch overhead. Descendant and unwrap-mode inspection showed the time is dominated by actual worker execution (`Host::invoke_function`, storage map work, VM work) and the parent waiting for the slowest cluster. A worker pool would still wait for the same deterministic cluster work and has no demonstrated removable Medium-sized subset.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in this session record

### Why It Failed

The apparent hotspot is mostly parallel worker execution aggregated under the parent zone; replacing `std::async` would not remove the work on the critical path and is unlikely to clear the 3% objective threshold.

### Lesson Learned

For parallel apply zones, parent totals must be decomposed before proposing scheduler changes. A large parent zone often represents useful worker work plus deterministic `future.get()` waiting, not launch overhead.
