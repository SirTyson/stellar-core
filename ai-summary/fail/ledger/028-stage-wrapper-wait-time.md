# H028: Optimize applySorobanStageClustersInParallel wrapper self-time

**Date**: 2026-05-24
**Subsystem**: ledger
**Severity**: Low
**Impact**: Apparent parallel-stage wrapper bottleneck
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If `applySorobanStageClustersInParallel` self-time were directly optimizable wrapper overhead, changing the wrapper should remove a measurable portion of soroswap apply time without touching transaction execution.

## Mechanism

The zone wraps `std::async` launches and then waits on futures in deterministic order. Its large self-time is primarily wall time spent waiting for worker clusters that execute Soroban host work, not CPU burned by the wrapper loop itself.

## Trigger

Inspect `applySorobanStageClustersInParallel` in the current soroswap trace and source. The zone appears as 44 calls with ~2.94 s self-time in aggregate Tracy output.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — launches one future per cluster, then joins futures and collects thread states deterministically.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — worker body that performs the actual per-transaction `parallelApply` and state commits.

## Evidence

`applySorobanStageClustersInParallel` is inside `applyLedger` and dominates aggregate self-time because Tracy attributes future wait time to the wrapper. This initially suggests worker-pool reuse or join-order changes.

## Anti-Evidence

Existing failures already show worker-pool reuse and cluster setup parallelization do not clear the Medium floor or regress due to cache/memory effects. The current source's wrapper does little besides launch and join; the removable OS future overhead is not the measured 2.94 s, which is mostly slowest-cluster execution and mandatory synchronization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: DUPLICATE-ADJACENT — current trace confirms the same stage-wrapper meta-pattern

### Why It Failed

The wrapper's large self-time is wait time for real worker execution, not an independent CPU hotspot. Optimizing the wrapper alone cannot recover Medium-tier apply time.

### Lesson Learned

Do not project savings from stage-wrapper self-time without dedicated zones proving a specific removable sub-operation; wrapper gaps are synchronization and slowest-worker effects.
