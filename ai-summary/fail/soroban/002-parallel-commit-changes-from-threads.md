# H002: Parallelize `GlobalParallelApplyLedgerState::commitChangesFromThreads`

**Date**: 2026-05-02
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction (post-cluster commit phase)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `applySorobanStageClustersInParallel` completes a stage, the per-thread
modified-entry maps must be merged into the single shared
`GlobalParallelApplyLedgerState::mGlobalEntryMap` before the next stage starts
or before `commitChangesToLedgerTxn`. CAP-0063 requires that the observable
order of entry writes match a deterministic per-stage walk; the existing
`commitChangesFromThreads` implementation walks `threads` in cluster order
and, within each thread, walks `mThreadEntryMap` and calls
`commitChangeFromThread` per `(key, entry)` pair. The merge is allowed to be
performed in parallel as long as the per-key resolution between two clusters
that touch the same key is still order-deterministic (CAP-0063 commits the
"first write wins under cluster-order", with RO TTL bumps merged via
`maybeMergeRoTTLBumps`).

A correct optimization would shard the keyset across worker threads — e.g.,
hash-partition `mGlobalEntryMap` upserts into N independent sub-maps, run the
per-thread merges in parallel into their owned shards, then concatenate
shards into the global map. This would eliminate the serial commit phase
between stages.

## Mechanism

`commitChangesFromThreads` (`ParallelApplyUtils.cpp:908`) is currently
serial: a single `for (auto const& thread : threads)` loop on the apply
thread, executing `commitChangeFromThread` for every modified key in every
cluster. For the soroswap workload with NUM_CLUSTERS=8 and ~30 modified
keys/cluster, this is ~240 sequential `unordered_map::find` + `emplace`
operations per stage, plus per-key `maybeMergeRoTTLBumps` work and an
`mGlobalRestoredEntries.addRestoresFrom` per thread. Sharding this work
across the same NUM_CLUSTERS workers would, in principle, yield ~Nx
speedup on this phase.

## Trigger

Run the soroswap apply-load benchmark and observe `commitChangesFromThreads`
Tracy zone wall-time across the 70 ledgers.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:908-922` —
  `GlobalParallelApplyLedgerState::commitChangesFromThreads` serial loop.
- `src/transactions/ParallelApplyUtils.cpp:856-891` — `commitChangeFromThread`
  per-key upsert with `maybeMergeRoTTLBumps`.
- `src/ledger/LedgerManagerImpl.cpp:2656` — call site after each stage's
  `applySorobanStageClustersInParallel`.

## Evidence

Tracy zone `commitChangesFromThreads` (csvexport totals on
`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`):
total 51.9 ms across 42 calls (~1.2 ms/stage call, ~0.74 ms per ledger
amortized over 70 ledgers).

## Anti-Evidence

- Already serialized in cluster-index order to satisfy CAP-0063 first-write
  semantics; any sharding scheme must reproduce identical conflict
  resolution and identical RO-TTL-bump merge order.
- The merge does heap allocation in `mGlobalEntryMap` upserts, which
  contends on the global allocator across workers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (distinct from
"Parallel Thread State Setup Is Measured Noise" meta-pattern, which
targets the *pre*-stage `ThreadParallelApplyLedgerState` construction
phase, not the *post*-stage commit phase).

### Why It Failed

The total Tracy wall-time of `commitChangesFromThreads` is 51.9 ms across
the entire 70-ledger benchmark — approximately **1.0 % of the 5092 ms
`applyLedger` window**. Even with a perfect 8x parallel speedup of the
merge body (which is unattainable in practice because the merge competes
for a single global hashmap and a single global allocator), the absolute
ceiling on wall-time savings is ~45 ms = ~0.9 %. This sits below the
Low (1–3 %) threshold and far below the Medium (3–10 %) threshold required
for hypothesis promotion under the optimize-soroswap objective.

This also matches the established meta-pattern from
`021-addlivebatch-as-third-async-future.md`: when an existing serial
phase totals < 1 % of apply, no parallelization scheme can clear the
Medium floor.

### Lesson Learned

Before proposing parallelism for any post-stage commit/seal/merge phase
inside `applyLedger`, measure the absolute Tracy wall-time of the target
zone first. If the total is < 1 % of `applyLedger`, no
parallelization can recover Medium severity even under perfect-scaling
assumptions. The interesting parallelism opportunities for soroswap are
inside the cluster workers (already parallel) and inside individual host
invocations (constrained by determinism + metering), not the
between-stage glue code.
