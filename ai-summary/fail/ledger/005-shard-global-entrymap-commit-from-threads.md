# H005: Shard `mGlobalEntryMap` to parallelize `commitChangesFromThreads`

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban parallel apply commit
**Severity**: Medium (claimed); actually below threshold
**Impact**: Reduce serial post-worker merge of per-thread `EntryMap`s into the global entry map by partitioning `mGlobalEntryMap` into N shards (one per worker) so the merge can run in parallel
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After Soroban workers finish a stage, `GlobalParallelApplyLedgerState::commitChangesFromThreads`
walks each of the (up to `NUM_CLUSTERS` = 8) `ThreadParallelApplyLedgerState`
`mEntryMap`s and merges each dirty entry into `mGlobalEntryMap`. Because the
RW-footprints are partitioned across clusters by design, every RW entry is
touched by exactly one thread and the merge of those entries is conflict-free.
Read-only TTL bumps are the only overlap and could be reconciled per-shard with
`maybeMergeRoTTLBumps`. The merge should therefore be parallelizable across the
same `NUM_CLUSTERS` workers used to apply the stage, eliminating a serial
post-stage barrier.

## Mechanism

The current implementation
(`src/transactions/ParallelApplyUtils.cpp:908-922`) iterates `threads`
sequentially on the main thread, and for each thread walks the whole
`thread.getEntryMap()` calling `commitChangeFromThread` which performs an
`emplace`/`find` on the single global `UnorderedMap` `mGlobalEntryMap`. Per-ledger
wall-clock cost is ~7.44 ms (`commit_from_thrds` median in the soroswap apply-load
phase log), and the structure is dominated by hashtable lookups + `rescope`
moves on `ParallelApplyLedgerKey`. If we sharded `mGlobalEntryMap` into `K`
maps keyed by `hash(key) % K` and dispatched K workers each merging all 8
threads' contributions for its shard, we could in theory cut wall-clock by
~`K`× minus barrier/dispatch overhead.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8. Soroban worker stages
produce non-overlapping RW footprints; `commit_from_thrds` shows ~7.44 ms / ledger
in the median (3.5% of the 213.6 ms p50 close time).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:894-922` — `commitChangesFromThread`
  and `commitChangesFromThreads`, serial merge of per-thread entry maps into
  `mGlobalEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:856-892` — `commitChangeFromThread`,
  the per-entry merge with `maybeMergeRoTTLBumps` reconciliation of RO TTL
  bumps.
- `src/transactions/ParallelApplyUtils.h` — `mGlobalEntryMap` storage layout
  that would need to be sharded.

## Evidence

- soroswap apply-load p50 phase breakdown shows
  `commit_from_thrds = 7.44 ms` (3.5% of 213.6 ms close).
- RW footprints are partitioned across clusters by construction (this is the
  invariant that makes parallel apply correct); per-cluster contributions to
  the global map for RW entries are guaranteed disjoint.
- The merge logic is per-entry and stateless apart from the global map slot,
  so a hash-sharded implementation is straightforward.

## Anti-Evidence

- `ai-summary/fail/ledger/002-dirty-journal-parallel-apply-commit.md`
  (committed prior fail) already quantified
  `commit_from_thrds + commit_to_ltx` as ~4% upper bound combined, with
  `commitChangesFromThread` self-time at ~1.35% of `applyLedger`. The
  recoverable serial-merge cost is bounded **below 0.8%** of apply time even
  if the merge were free — most of the phase's wall-clock is `scopeDeactivate`
  per-thread + `rescope` moves + the unavoidable single-writer commit of the
  global map into `ltx` (`commit_to_ltx`).
- A sharded merge adds dispatch and synchronization overhead at the same
  per-cluster scale as the entries themselves; for ~150 entries × 8 threads
  per ledger, the per-shard task is so small that thread wake-up overhead
  consumes most of the parallelism budget. The fail-002 PoC quantification
  bounds this below the Medium threshold even in an optimistic implementation.
- `commitChangesToLedgerTxn` immediately following (`commit_to_ltx` 4.37 ms)
  cannot be parallelized at all (`AbstractLedgerTxn` single-writer / single-
  child constraint, also recorded in fail/ledger Meta-Pattern #5), so the
  combined optimization ceiling is constrained.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — sharded-map mechanism not previously named in
fail/hypothesis/reviewed/poc, but the *upper bound on commit_from_thrds savings*
was already established by `fail/ledger/002-dirty-journal-parallel-apply-commit.md`.

### Why It Failed

Even with a perfect sharded merge that fully parallelizes
`commitChangesFromThreads` across `NUM_CLUSTERS` workers, the wall-clock
savings are bounded by the existing fail-002 quantification:
`commitChangesFromThread` self-time is ~1.35% of `applyLedger`, and the
recoverable parallelizable subset is **below 0.8%** of apply time. The
serial-merge phase total (7.44 ms = 3.5%) is dominated by per-thread
`scopeDeactivate` + `rescope` moves that do not parallelize cleanly, and the
immediately-following `commit_to_ltx` (4.37 ms = 2%) remains fully serial
because `AbstractLedgerTxn` permits only a single writer. The full
post-worker commit pipeline therefore cannot reach the 3% Medium floor
even with an idealized sharded merge.

### Lesson Learned

Per-thread→global merge phases inside parallel apply have a hard ceiling set
by:
1. The fraction of phase time spent in operations that *do* parallelize
   (the per-entry merge call), versus the fraction that does not
   (scope deactivation, the subsequent `ltx`-bound serial commit).
2. The structural ceiling already documented in fail-002 (~0.8%
   recoverable). New mechanisms targeting `commit_from_thrds` need to
   first refute fail-002's bound — sharding the global map alone does
   not change that bound because it does not eliminate the dominant
   non-parallelizable sub-work.
