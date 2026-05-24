# H001: Bypass `mGlobalEntryMap` Intermediate Merge on Final Soroban Stage — Write Thread Maps Directly to `LedgerTxn`

**Date**: 2026-05-24
**Subsystem**: soroban (parallel-apply / ledger-txn boundary)
**Severity**: Medium
**Impact**: 3-5%+ apply-time reduction on soroswap (and sac); restructures the post-parallel commit phase of `applySorobanStages`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After workers finish the last stage of `applySorobanStages`, the parallel-apply
infrastructure should write the workers' dirty entries to the outer
`AbstractLedgerTxn` exactly once, performing only the work required for
ledger-state correctness (dirty entries emitted as create/update/erase calls;
RO TTL bump merge collisions resolved). No intermediate global map should be
populated for entries that will never be consumed by a subsequent stage.

## Mechanism

Today the post-worker pipeline runs two serial loops on the apply thread for
every stage, including the last:

1. `commitChangesFromThreads` (`ParallelApplyUtils.cpp:907-922`) iterates each
   thread's `mThreadEntryMap`, and for every dirty entry calls
   `commitChangeFromThread` (`:856-891`) which does
   `mGlobalEntryMap.find(key)` → `emplace` (or `maybeMergeRoTTLBumps` →
   in-place merge) into `GlobalParallelApplyLedgerState::mGlobalEntryMap`.
2. `commitChangesToLedgerTxn` (`:721-801`) then iterates the entire
   `mGlobalEntryMap`, opens a nested `LedgerTxn ltxInner(ltx)`, and for every
   dirty entry calls `createWithoutLoading` / `updateWithoutLoading` /
   `load`+`erase`, then `commit()`s `ltxInner` into the outer ltx.

For the **final** stage (the only stage in single-stage workloads, and the
last of N≥1 in multi-stage workloads), there is no downstream stage to read
`mGlobalEntryMap`, so populating it is pure overhead: every dirty entry is
hashed and stored once into the global map (loop 1) and then iterated and
written again into `ltxInner` (loop 2). The `BUILD_TESTS` diagnostic phase
timer measures these zones at `commit_from_thrds` 7.44 ms/ledger (3.4 %) and
`commit_to_ltx` 4.37 ms/ledger (2.0 %) on soroswap — a combined 11.81 ms =
**5.4 %** of the 218 ms baseline. Note that Tracy under-reports these zones
by ~8-14× (fail #039 cited 0.14 % and fail #047 cited 0.34 % from Tracy
totals), so prior rejections sized this work against the wrong baseline.

The deviation from expected behavior is that the apply thread is doing
quadratic-ish work — every dirty entry is moved through three maps
(thread → global → inner ltx → outer ltx) when only the inner→outer flow
is structurally required for the last stage. The proposed restructure
performs the merge directly into `ltxInner` from each thread's map (handling
RO TTL bumps by a per-key max during the same pass), eliminating one full
serial loop over ~2 000 entries and the entire `mGlobalEntryMap`
hash-insert / lookup cost on the last stage.

Concretely:
- Track a `bool isFinalStage` in the `GlobalParallelApplyLedgerState` API
  (the orchestrator knows whether more stages follow).
- For the final stage, call a new
  `commitChangesFromThreadsDirectToLtx(ltx, threads, stage)` that:
  - Opens `LedgerTxn ltxInner(ltx)` once.
  - Iterates per thread; for each dirty entry, either writes it directly,
    or — for RO TTL bumps where multiple threads bump the same key — uses
    a small local `UnorderedMap<ParallelApplyLedgerKey, uint32_t>` of
    pending TTL maxes, applied once at the end. This local map is sized
    by the count of RO TTL bumps (typically a handful per soroswap pool),
    not by every dirty entry.
  - Handles `mGlobalRestoredEntries` exactly as today (the restored set is
    small and already separate).
  - Commits `ltxInner`.
- For non-final stages, keep the existing two-loop path so that future
  stages can read prior-stage outputs through `mGlobalEntryMap`.

Determinism: writes to `ltxInner` are issued in the same per-thread,
per-stage order as the current path commits them through `mGlobalEntryMap`
into `ltxInner`. The only observable change is the elimination of one
intermediate map; the set of `createWithoutLoading` /
`updateWithoutLoading` / `erase` calls and their order remain identical
within each thread, and the final `ltxInner.commit()` to the outer ltx is
unchanged. RO TTL bump merging (the only cross-thread merge inside a
stage) is preserved by the local pending-TTL map.

Soroswap is benchmark-headlined and typically runs as 1–2 stages; even in
the 2-stage case the last-stage saving is roughly half of the combined
5.4 % (≈ 2.7 %, Low–Medium boundary), and in 1-stage cases (or for
`max-sac`) it is the full 5.4 %.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap and max-sac benchmarks
before and after the change. Expected: median apply-time drops by 3-5 %
on soroswap and a similar amount on max-sac, reproducible across at
least three runs. Verify Tracy: `commitChangesToLedgerTxn` and
`commitChangesFromThreads` aggregate self-time on the final-stage call
should drop substantially; new zone `commitChangesFromThreadsDirectToLtx`
should appear with a smaller total.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:907-922`
  (`GlobalParallelApplyLedgerState::commitChangesFromThreads`) — entry
  point for the per-thread merge into `mGlobalEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:856-891`
  (`commitChangeFromThread`) — the `find`/`emplace`/`maybeMergeRoTTLBumps`
  per-entry path being eliminated for the final stage.
- `src/transactions/ParallelApplyUtils.cpp:721-801`
  (`commitChangesToLedgerTxn`) — the second serial loop that becomes a no-op
  for entries written directly by the new final-stage path.
- `src/transactions/ParallelApplyUtils.cpp:821-854`
  (`maybeMergeRoTTLBumps`) — the merge semantics that the new direct-write
  path must preserve via a local pending-TTL map.
- `src/ledger/LedgerManagerImpl.cpp:2622-2710` (`applySorobanStage` /
  `applySorobanStages`) — call site that selects the final-stage path.
- `src/transactions/ParallelApplyUtils.h:183-260`
  (`GlobalParallelApplyLedgerState`) — API surface for the new
  `commitChangesFromThreadsDirectToLtx` method.

## Evidence

- **BUILD_TESTS diagnostic phase table** (per-ledger steady_clock timers in
  `LedgerManagerImpl::applySorobanStage[s]`): on the latest
  `CURRENT_STATE.md`-referenced soroswap run, `commit_from_thrds` = 7.44 ms
  median/ledger (3.4 % of 218 ms apply) and `commit_to_ltx` = 4.37 ms
  median/ledger (2.0 %). Combined 11.81 ms = 5.4 %.
- **Tracy under-reports these zones by 8-14×** (fail #039 cited 0.14 % for
  `commitChangesToLedgerTxn`; fail #047 cited 0.34 % for
  `commitChangesFromThreads`). The 8-14× discrepancy between Tracy and the
  diagnostic steady_clock timer is observable across multiple zones in this
  trace and means prior rejections were sized against an order-of-magnitude
  under-estimate.
- **Structural redundancy**: `commitChangeFromThread` does
  `mGlobalEntryMap.find(key)` → most entries miss (RW soroban data is
  cluster-local, only TTL bumps and RO Soroban preloads can collide);
  `emplace` then rehashes; `commitChangesToLedgerTxn` re-iterates the same
  ~2 000 entries.
- **Cluster RW-disjointness within a stage** (by ApplyStage construction):
  threads' RW footprints are disjoint, so the only cross-thread collisions
  are RO TTL bumps. This is exactly what `maybeMergeRoTTLBumps` resolves —
  a much smaller set than total dirty entries, easily handled by a local
  pending-TTL map.
- **No cross-stage consumer on the final stage**: by definition the last
  stage's `mGlobalEntryMap` content is only read by
  `commitChangesToLedgerTxn`. Skipping it is structurally safe.

## Anti-Evidence

- `mGlobalRestoredEntries` and the `markRestoredFromHotArchive` /
  `markRestoredFromLiveBucketList` calls in `commitChangesToLedgerTxn`
  (lines 774-799) still need to run and reference restored-entry tracking;
  the direct-write path must preserve these calls unchanged. (They iterate
  a small `restored` map, not `mGlobalEntryMap`, so this is straightforward.)
- For multi-stage workloads the saving is bounded by the share of dirty
  entries produced in the last stage. If soroswap actually runs in many
  small stages, the per-stage win shrinks. Empirically the
  `soroban_parallel` phase is 154 ms/ledger and a typical
  `applySorobanStageClustersInParallel` zone is on the order of 50-80 ms
  wall, suggesting 1-2 stages — making the final stage the dominant one.
- Invariant checks (`checkAllTxBundleInvariants`,
  `ArchivedStateConsistency`) consume per-bundle deltas, not the global
  entry map, so they are unaffected.
- Fail #039 (`avoid-inner-ledgertxn-in-commit-changes`) attacked only the
  `LedgerTxn ltxInner(ltx)` construction — a strict subset of the work
  being eliminated here. This hypothesis targets the *combined*
  global-map-population + ltxInner-population path, which is
  structurally distinct and sized at 5.4 % per the diagnostic timer
  (versus the 0.14 % Tracy slice cited in fail #039).
- Fail #047 (`cache-stage-rwkeyset`) attacked only the per-stage
  `readWriteSet` construction — a tiny slice. This hypothesis bypasses
  the per-entry global-map work entirely on the final stage, not just
  the per-stage set construction.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The hot path exists, but the proposed final-stage direct-write mechanism is incomplete for multi-stage parallel Soroban ledgers. `applySorobanStages` runs every stage, then performs one `commitChangesToLedgerTxn` after all stages; dirty entries from earlier stages live only in `GlobalParallelApplyLedgerState::mGlobalEntryMap` until that final commit. A final-stage thread state only copies global entries whose keys appear in that final cluster's footprint, so writing only the final stage's thread maps directly to `LedgerTxn` would drop earlier-stage dirty entries that are not touched again in the final stage.

The determinism explanation is also inaccurate: current final writes are not issued in per-thread/per-stage order, because `commitChangesToLedgerTxn` iterates `mGlobalEntryMap`, an unordered map, after `commitChangesFromThreads` has merged entries. A corrected design must reason about LedgerTxn's entry-map semantics and duplicate-key overwrite ordering, not claim the direct path preserves the existing write order.

### Alternative Angle

A refined version could still be worth investigating if it explicitly handles the already-merged global state. One safe shape would be a single final `LedgerTxn ltxInner(ltx)` that first writes pre-final dirty entries already present in `mGlobalEntryMap`, then writes final-stage dirty thread entries so final-stage changes overwrite prior-stage versions for overlapping keys, then applies restored-entry markers before committing. To keep the Medium projection, that refined design should also avoid iterating all clean preloaded global entries, likely by tracking dirty global keys separately; otherwise the remaining `mGlobalEntryMap` scan and prior-stage write work reduce the claimed 3-5% saving, especially in 2+ stage workloads.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` executes all stages before the single final `commitChangesToLedgerTxn`, so prior-stage dirty global entries remain pending until the end.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` is the only path that currently writes every dirty `mGlobalEntryMap` entry plus restored-entry markers into `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:856-922` — `commitChangesFromThreads` merges dirty thread entries into the global map after each non-final stage and preserves `mIsNew`/RO TTL merge semantics.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — final-stage thread states copy only footprint-relevant keys from `mGlobalEntryMap`; they do not contain all dirty entries produced by previous stages.
- `src/herder/ParallelTxSetBuilder.cpp:457-565` — stage construction spreads included transactions across stages and removes empty trailing stages; there is no invariant that the last stage's footprints cover all keys dirtied by earlier stages.
