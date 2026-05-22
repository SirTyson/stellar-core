# H003: Parallel-Fold `commitChangesFromThreads` Across Cluster Outputs

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Medium (projected, but does not survive sizing)
**Impact**: serial-phase parallelism for parallel-Soroban commit phase
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `applySorobanStageClustersInParallel` returns and all `NUM_CLUSTERS`
per-thread `ThreadParallelApplyLedgerState` objects are populated, the work of
folding their entry maps back into `mGlobalEntryMap` should be O(N/T)
critical-path where N is total dirty entries and T is the cluster count, since
within a stage cluster read-write footprints are disjoint and the fold is
trivially partitionable by key.

## Mechanism

Today `GlobalParallelApplyLedgerState::commitChangesFromThreads`
(`src/transactions/ParallelApplyUtils.cpp:907`) iterates cluster outputs
sequentially on the main thread, calling `commitChangeFromThread` for every
entry. The benchmark phase log measures `commit_from_thrds` at 7.63 ms/ledger
on the current soroswap baseline (3.05% of apply time). Folding the cluster
outputs in parallel (e.g., partitioning by `key.ledgerKey()` hash range into
NUM_CLUSTERS folder tasks, each owning a disjoint shard of `mGlobalEntryMap`)
would in principle reduce the serial work to ~7.63/T ≈ 0.95 ms/ledger.

## Trigger

Soroswap apply on the current baseline. The phase is measured directly via
`mLastPhaseTimings.sorobanCommitFromThreadsMs`
(`src/ledger/LedgerManagerImpl.cpp:2659`).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:907` — `commitChangesFromThreads` serial loop
- `src/transactions/ParallelApplyUtils.cpp:857` — `commitChangeFromThread` per-entry work (find + rescope + maybeMergeRoTTLBumps)

## Evidence

- `commit_from_thrds = 7.63 ms/ledger` is the largest unexplored serial chunk
  after `soroban_setup_glbl` (24 ms) and `soroban_parallel` (194 ms).
- Stage-local disjointness of cluster read-write footprints is exactly the
  determinism guarantee that enables the parallel apply itself; the same
  guarantee applies in reverse to the fold.

## Anti-Evidence

- Sharded merge requires a per-shard `mGlobalEntryMap` instance + final
  concatenation, or a lock-free concurrent map. The concatenation cost itself
  is bounded by the same number of writes (~10k dirty entries/ledger).
- `maybeMergeRoTTLBumps` is bookkeeping over `RoTTLBumpSet` (per-stage)
  which is read but not written in commit_from_thrds; sharing is fine but
  doesn't help.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail 048 (pipelined mutex merge); this
proposes static hash-shard partition rather than mutexed incremental merge,
but the sizing conclusion is the same.

### Why It Failed

Critical-path savings bounded by `commit_from_thrds × (T-1)/T = 7.63 × 7/8
≈ 6.7 ms/ledger = 2.7%` of the soroswap baseline (~250 ms). The 2.7% upper
bound is below the **Medium 3%** floor required by this objective's severity
scale, and the realistic savings after worker-launch overhead, shard
concatenation, and the unavoidable single-thread tail of the slowest shard
will be smaller still. Meta-pattern #6 (aggregate worker time ≠
critical-path time) does not apply here because the phase IS serial today,
but the parallelization ceiling alone caps the win below threshold.

This is essentially the same structural ceiling that defeated fail 048
(pipelined-via-mutex), now re-measured against the larger 7.63 ms phase: the
math still does not clear 3%.

### Lesson Learned

For any serial phase X ms/ledger, the maximum recoverable savings via
T-way parallelization is X × (T-1)/T regardless of fan-out mechanism. For
NUM_CLUSTERS = 8 this caps at 87.5% of phase time. To reach Medium severity
(≥3% = 7.5 ms/ledger on the soroswap baseline), the target phase must be
≥8.6 ms/ledger after this cap. `commit_from_thrds` at 7.63 ms is just below
that floor. Future parallelization hypotheses should pre-size the post-cap
yield before promotion.
