# H004: Parallelize `commitChangesFromThreads` Across Worker Outputs

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / parallel-apply
**Severity**: Low
**Impact**: Apply-time critical path (post-stage commit)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all `applyThread` workers in a Soroban stage have completed,
`GlobalParallelApplyLedgerState::commitChangesFromThreads` should fold
each per-thread `mThreadEntryMap` into the global entry map. Because
`getReadWriteKeysForStage(stage)` already partitions keys so that
disjoint clusters write disjoint key sets (by construction — that is
the whole basis for parallel apply being safe), the per-thread fold
work is itself trivially independent across threads, and the runtime
could therefore process all `NUM_CLUSTERS` thread maps concurrently
rather than one after the other on the apply thread.

## Mechanism

`commitChangesFromThreads` (`src/transactions/ParallelApplyUtils.cpp:907-922`)
iterates the worker thread states sequentially: for each thread it
calls `commitChangeFromThread` for every entry in
`thread.getEntryMap()` and merges restored-entry sets. The work is
purely `apply`-thread-bound today, even though distinct threads' entry
maps are non-overlapping (the cluster scheduler in
`ParallelApplyStage` enforces disjoint read-write footprints). Moving
the per-thread fold body into the worker's tail (so each worker
publishes its post-rescope entries directly into a sharded slice of
the global map, then a short main-thread merge stitches the slices)
would replace ~1 ms of serial fold work per stage with a constant
small merge, on the order of microseconds.

## Trigger

Soroban-heavy ledgers with a large number of read-write entries per
stage (the soroswap shape) — every per-thread entry must be rescoped
and inserted into the global map at stage end, costing
~1.09 ms/stage on the current trace.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp::commitChangesFromThreads:907-922`
  — outer serial loop over per-thread states.
- `src/transactions/ParallelApplyUtils.cpp::commitChangeFromThread:830-890`
  — per-entry rescope + global upsert that would migrate to workers.
- `src/ledger/LedgerManagerImpl.cpp::applySorobanStageClustersInParallel:2530-2575`
  — the natural site for the per-stage rendezvous.

## Evidence

Tracy zones from the accepted soroswap trace
(`b196b6238`, `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`):

| Zone                          | Total (s) | Calls | Per call (ms) |
|-------------------------------|-----------|-------|----------------|
| `commitChangesFromThreads`    | 0.0448    | 41    | 1.09           |
| `commitChangesFromThread` (×N)| 0.0470    | 76    | 0.62           |

Per-ledger contribution ≈ `0.0448 / 70 ≈ 0.64 ms` on the apply
critical path. Disjoint read-write sets across clusters
(`ParallelApplyStage` invariant, used by
`getReadWriteKeysForStage`) make the fold trivially independent.

## Anti-Evidence

- `mGlobalEntryMap` and `mGlobalRestoredEntries` are written under
  the assumption of single-writer access; converting them to
  shard-and-merge requires either a sharded data structure or a
  short main-thread merge, both of which add code complexity.
- `LedgerEntryScope` rescoping (`std::move(entry).rescope(thread,
  *this)`) currently happens on the apply thread; doing the rescope
  on workers means workers must hold a reference to the global scope,
  which today is intentionally avoided by the
  `LedgerEntryScope` ownership design.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — fail #009 covered coalescing `getLiveEntryOpt`
calls inside `setEffectsDeltaFromSuccessfulTx`/`commitChangesFromSuccessfulTx`,
not parallelizing the outer `commitChangesFromThreads` loop. No prior
investigation in fail / hypothesis / reviewed / poc has targeted the
serial-over-threads structure of this commit step.

### Why It Failed

Total apply-critical-path cost is ~0.64 ms/ledger ≈ ~0.8% of apply
time, well below the Medium floor (3%) and inside benchmark noise.
The implementation requires invasive changes to
`LedgerEntryScope`'s scope-ownership model (workers would have to
rescope into the global scope rather than the thread scope) and to
`GlobalParallelApplyEntryMap` access discipline, with significant
review burden for a sub-1% gain.

### Lesson Learned

The post-stage `commitChangesFromThreads` step is structurally serial
but already small enough that parallelizing it is not worth the
complexity. The much larger lever for stage-end is reducing the
serial *setup* cost of `ThreadParallelApplyLedgerState` per cluster
before workers launch, which is on the apply critical path and is
already noted in fail #001-parallelize-thread-state — confirming
that serial-glue work around parallel apply consistently sits below
the Medium threshold once measured.
