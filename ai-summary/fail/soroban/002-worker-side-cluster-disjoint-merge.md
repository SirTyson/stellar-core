# H002: Worker-Side Cluster-Disjoint Merge of `commitChangesFromThreads`

**Date**: 2026-05-26
**Subsystem**: soroban (transactions/ParallelApplyUtils — post-stage serial merge)
**Severity**: Medium
**Impact**: Apply-time reduction via eliminating the serial post-parallel-stage barrier (Meta-Pattern 14 explicitly invites this structural change)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each parallel-apply cluster operates on a **mutually disjoint** read-write
footprint (this is the invariant that justifies running them in parallel
in the first place — see cluster construction in
`buildSurgePricedParallelSorobanPhase`). After all cluster workers finish,
their per-thread `ThreadParallelApplyLedgerState` results must be folded
into the `GlobalParallelApplyLedgerState`. Because RW footprints are
disjoint by construction, each worker's RW-key contributions can be
written directly into the global map **without inter-cluster contention**
on RW keys. Only the **read-only TTL bump merge** (`maybeMergeRoTTLBumps`)
requires cross-cluster coordination (max-reduction over RO TTL extensions).
Therefore the bulk of `commitChangesFromThread`'s work — copying RW
entries from thread-local to global — can be performed **inside each
worker thread** at the tail of its own apply, eliminating the serial
barrier `commitChangesFromThreads` currently imposes on the apply thread.

## Mechanism

In `GlobalParallelApplyLedgerState::commitChangesFromThreads`
(`src/transactions/ParallelApplyUtils.cpp:907–922`), the apply thread
**serially** iterates over every cluster's thread state and folds each
into the global map. This runs on the apply thread *after*
`applySorobanStageClustersInParallel` returns, blocking the apply path.
Because clusters are RW-disjoint, each cluster's RW entries could instead
be inserted directly into the global map by the cluster's own worker
thread, using either (a) a sharded global map keyed by `key_hash %
NUM_CLUSTERS` so that each worker owns one shard, or (b) a per-cluster
output slot that the apply thread concatenates with `O(1)` move-only
operations rather than `O(entries)` rescoping. The RO TTL bump merge
remains a true reduction and would be handled with a single concurrent
hash map (e.g. `tbb::concurrent_hash_map` or sharded mutex map) for
the small RO-bump subset only. The current code conflates these two
classes of writes into one serial pass; separating them unlocks the
RW path to run in parallel with apply.

## Trigger

Soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, 2000 tx, 8-thread config).
The `commitChangesFromThreads` Tracy zone consumes **~0.59% of total
trace ≈ 1.4% of `applyLedger` envelope** — at the borderline of the
Medium severity floor. However the full opportunity is larger than the
zone's self-time because:
1. The zone runs **on the apply thread on the critical path** between
   parallel-apply finishing and the next stage starting.
2. `getReadWriteKeysForStage(stage)` is also called inside this serial
   region (line 917) and itself does per-RW-entry `getTTLKey` (sha256)
   work — moving that into per-worker computation amortizes it across
   cluster threads.
3. `rescope` calls inside `commitChangeFromThread` (line 866) involve
   per-entry object-pointer rewiring; running these inside the originating
   worker thread (which already has thread-local scope context loaded)
   should reduce cache-miss cost.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:commitChangesFromThreads:907–922` —
  the serial loop to be eliminated.
- `src/transactions/ParallelApplyUtils.cpp:commitChangeFromThread:856–891` —
  per-key fold logic; the RW path (else-branch of `maybeMergeRoTTLBumps`)
  is the per-cluster-disjoint portion that can run in workers.
- `src/transactions/ParallelApplyUtils.cpp:maybeMergeRoTTLBumps:821–854` —
  the ONLY truly cross-cluster reduction; must stay synchronized but
  applies only to RO TTL bumps (small subset).
- `src/transactions/ParallelApplyUtils.cpp:getReadWriteKeysForStage:105–132` —
  currently called inside the serial commit; the RW set per cluster is
  already known at worker-launch time (it's the cluster's RW footprint).
- `src/ledger/LedgerManagerImpl.cpp:applySorobanStage:2622–2670` —
  where the serial commit is invoked; the synchronization point would
  shrink to a future-join on per-worker side-channel results plus the
  RO-TTL reduction sweep.
- `src/transactions/ParallelApplyStage.h` — `ThreadParallelApplyLedgerState`
  data structures; per-cluster output slots could be added here.

## Evidence

1. **Meta-Pattern 14 explicitly invites this**:
   `ai-summary/fail/soroban/summary.md` records "structural change
   (parallelizing merge with deterministic ordering or moving merge into
   worker)" as the explicit unexplored axis — the prior fail-sized
   alternatives were all single-thread micro-optimizations within the
   existing serial loop.
2. **Disjoint-cluster invariant is load-bearing**: parallel-apply
   correctness already depends on cluster RW disjointness; the merge can
   exploit the same invariant for parallel writeback.
3. **No prior hypothesis attempted worker-side merge**: a scan of
   `ai-summary/{fail,success,reviewed,poc}/soroban/` shows prior work on
   commit/merge focused on `commitChangesToLedgerTxn` (success/serial
   tail) and on right-sizing the global map's reserve
   (fail/002-right-size-global-entry-map-reserve.md), not on moving the
   write-back into workers.
4. **Trace-confirmed structure**: Tracy shows
   `applySorobanStageClustersInParallel` (parent-wait zone) followed by
   `commitChangesFromThreads` self-time on the apply thread, with no
   overlap. Worker threads are idle during the serial commit.

## Anti-Evidence

1. **RO TTL bump merge is not trivially parallelizable**: the
   `maybeMergeRoTTLBumps` path uses `readWriteSet.find(key)` to assert
   that the key is **not** in any cluster's RW set, then takes
   `max(oldTTL, newTTL)`. Doing this concurrently requires either a
   concurrent map or a final reduction pass; mis-ordering the max
   would not be a determinism violation (max is commutative) but the
   `lastModifiedLedgerSeq` propagation at line 847–848 must pick a
   deterministic winner (the latest stage's value). For a single-stage
   benchmark like soroswap this is a non-issue, but cross-stage RO TTL
   bumps need care.
2. **`mIsNew` preservation across stages** (line 878 — "preserve mIsNew
   from the first stage that touched this entry") is a per-key
   sequential dependency across **stages**, not across clusters within
   a single stage. Intra-stage, mIsNew preservation is trivially safe
   because each cluster touches disjoint keys. Inter-stage commit must
   still happen serially between stages — but commit *within* a stage
   (all clusters of one stage) is the proposed parallel scope.
3. **Sized at borderline Medium**: the zone is 1.4% of apply window;
   if the speedup is only the zone's self-time we miss the 3% floor.
   The hypothesis depends on the secondary effects (hoisting
   `getReadWriteKeysForStage`'s `getTTLKey` calls and avoiding the
   apply-thread cache-miss cost during rescope) bringing the total
   into Medium range. **This needs PoC measurement to confirm.**
4. **Implementation complexity**: introducing a concurrent map or
   sharded global map adds intricate code in a determinism-critical
   path. If PoC measurement shows only ~1.5% savings, the
   implementation cost may not justify the change.
5. **Meta-Pattern 14 also caps optimism**: the same pattern lists
   "sub-millisecond serial paths are exhausted" — this zone is
   sub-ms per ledger (~0.42ms/ledger × 71 ledgers / 0.21s baseline =
   well under 1%), so the structural change must produce
   second-order wins above the zone's nominal cost to clear Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` row `002-parallel-commit-changes-from-threads.md + 013-commit-changes-from-thread-serial-merge.md`
**Failed At**: reviewer

### Trace Summary

The apply path runs `applySorobanStageClustersInParallel`, waits for every worker future, then calls `GlobalParallelApplyLedgerState::commitChangesFromThreads` on the apply thread before thread-state destruction. The target loop is real and serial: it builds a stage-wide RW key set, deactivates each thread scope, rescopes dirty thread entries into `mGlobalEntryMap`, max-merges RO TTL bumps, and accumulates restored-entry bookkeeping. However this is the same serial thread-state-to-global-map merge surface already investigated and rejected in the soroban fail summary, including partition/shard variants; prior records bound the entire zone below the optimize-soroswap Medium floor. The hypothesis's secondary `getReadWriteKeysForStage`/TTL-key work is also already covered by existing fail/success records and is not enough to turn a sub-1%-to-1.4% tail into a reproducible 3-10% apply-time reduction.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:64` — prior retained finding rejects parallelizing `commitChangesFromThreads`, including a partition-shard scheme, because the zone total is below 1% of `applyLedger` and cannot reach Medium.
- `ai-summary/fail/soroban/summary.md:139,171` — prior records reject caching the stage RW key set as a sub-fraction of the commit zone and dirty-only commit walking as below Medium, while noting future structural ideas must still prove a larger absolute bound.
- `ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md:11-18,87-99` — the repeated footprint/TTL key hashing angle was separately optimized and confirmed only as Low severity, not Medium.
- `src/herder/ParallelTxSetBuilder.cpp:57-61,400-426,567-698` — cluster construction merges RW/RW and RO/RW conflicts, then packs independent logical clusters into bounded execution bins.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` constructs `ThreadParallelApplyLedgerState`s, launches `std::async` workers, waits on every future, and returns the completed thread states.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` invokes the parallel workers, checks invariants, then calls the serial `globalParState.commitChangesFromThreads(app, threadStates, stage)`.
- `src/transactions/ParallelApplyUtils.cpp:104-132` — `getReadWriteKeysForStage` builds the stage-wide RW/TTL set used to distinguish true writes from RO TTL max merges.
- `src/transactions/ParallelApplyUtils.cpp:371-384` — the design comment states per-thread objects retain no references to global maps because global maps and snapshots are not thread-safe, and are committed back only after worker use is complete.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — the target merge path skips clean entries, rescopes dirty thread entries into global scope, inserts or overwrites `mGlobalEntryMap`, handles `mIsNew`, max-merges RO TTL bumps, and merges restored entries.
- `src/transactions/ParallelApplyUtils.cpp:924-1252` — worker-side state preloads global entries, buffers RO TTL bumps, flushes them into the thread map, and emits one final per-thread entry map; it currently does not mutate global state from workers.
- `src/transactions/ParallelApplyUtils.cpp:721-800` — final `commitChangesToLedgerTxn` later scans `mGlobalEntryMap`, writes dirty entries to an inner `LedgerTxn`, and marks restored entries.
- `src/transactions/TransactionFrameBase.h:155-161` and `src/util/UnorderedMap.h:13` — `ParallelApplyEntryMap` is an ordinary `std::unordered_map` wrapper, so concurrent worker insertion would require the same new sharded/concurrent-map design space already captured by the prior duplicate.

### Why It Failed

This is substantially equivalent to the already-investigated `commitChangesFromThreads` parallelization/sharding hypothesis in the retained soroban fail summary. The present write-up changes the placement to "worker-side", but the optimization target and cost bound are the same thread-state-to-global-map merge tail; option (a) is explicitly the prior partition-shard family, and option (b) still has to materialize a usable global map for later stages and `commitChangesToLedgerTxn`, so it does not become an O(1) replacement for the O(entries) merge.

It also fails the optimize-soroswap objective severity threshold. The hypothesis's own sizing puts the target at ~0.59% of total trace / ~1.4% of the apply window, below the 3% Medium floor even under perfect removal. The proposed second-order effects are already bounded by prior records: stage RW-key caching is a sub-fraction of the commit zone, and repeated footprint/TTL-key hash recomputation was a separate confirmed Low-severity optimization. A concurrent or sharded global map would add synchronization and still need deterministic RO TTL/restored-entry handling, so the current evidence cannot support a Medium-or-better apply-time reduction.

### Lesson Learned

Do not re-promote `commitChangesFromThreads` parallelization solely by moving the same merge into worker tails. For this objective, future commit-tail hypotheses need a new measured envelope that exceeds the 3% floor after subtracting already-addressed RW-key hashing work, or they should target a larger combined path such as a correctly implemented one-stage direct-to-`LedgerTxn` design rather than the isolated thread-to-global-map merge.
