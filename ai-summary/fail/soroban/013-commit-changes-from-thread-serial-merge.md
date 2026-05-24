# H013: Parallelize `commitChangesFromThreads` Serial Hash-Map Merge Tail

**Date**: 2026-05-27
**Subsystem**: soroban / parallel-apply commit tail
**Severity**: Low (below objective severity threshold)
**Impact**: serial-tail apply-time reduction after parallel Soroban clusters join
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all `NUM_CLUSTERS` Soroban worker threads finish in
`applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2531-2575`), the per-thread
`ThreadParallelApplyLedgerState::mThreadEntryMap` deltas must be merged into
the single `GlobalParallelApplyEntryMap` before the next stage (or before
final `commitChangesToLedgerTxn`). The expected cost of this merge per
ledger should be a small fraction of apply time, because the merge is
serially executed on the apply thread between parallel stages and any
serial-tail cost is multiplied 1× into the critical path.

## Mechanism

`GlobalParallelApplyLedgerState::commitChangesFromThreads`
(`src/transactions/ParallelApplyUtils.cpp:907-922`) walks the
`threads` vector serially and, for each thread, calls
`commitChangesFromThread` which iterates every key in the thread's
`getEntryMap()` and `emplace`/`move`-assigns it into the global
hash map (`commitChangeFromThread`, lines 856-891). For soroswap with
~2000 txs/ledger × ~5 footprint keys × 2 (entry + TTL key) ≈ ~20 000
`ParallelApplyLedgerKey` entries to merge per ledger, executed serially
on the apply thread after the parallel join barrier.

The work could in principle be parallelized by sharding the global
`mGlobalEntryMap` into per-thread output partitions during the parallel
phase (with no cross-thread reads) and then concatenating partition
buckets in O(1) at join time, eliminating the serial hash-probe and
move-emplace cost.

## Trigger

Every soroswap apply window. `commitChangesFromThreads` is invoked
once per `applySorobanStage` call, immediately after `threadFutures` are
joined and before invariant checks (`LedgerManagerImpl.cpp:2646`,
`:2656`).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:907-922` —
  `GlobalParallelApplyLedgerState::commitChangesFromThreads` serial
  per-thread loop.
- `src/transactions/ParallelApplyUtils.cpp:856-891` —
  `commitChangeFromThread` per-key emplace + `maybeMergeRoTTLBumps`
  fallback.
- `src/ledger/LedgerManagerImpl.cpp:2656` — call site at the end of
  `applySorobanStage`.

## Evidence

- The merge is structurally serial on the apply thread (`ZoneScoped` in
  `commitChangesFromThread` and `commitChangesFromThreads`); any cost
  here is critical-path cost, not aggregate worker cost.
- For soroswap (~2000 txs × 5 RW keys × 2 (entry + TTL)) the per-ledger
  entry-map merge is ~20 000 emplace/move operations.

## Anti-Evidence

- A previously rejected hypothesis (`fail/transaction-ledger/039-avoid-inner-ledgertxn-in-commit-changes.md`)
  measured `commitChangesToLedgerTxn` at 27.3 ms aggregate / 71 ledgers
  = 384 µs/ledger = 0.14% of apply. The
  `commitChangesFromThreads` zone here merges into the in-memory
  `mGlobalEntryMap` rather than into LedgerTxn, but the per-entry cost is
  similar (hash-map emplace + small std::optional copy). Sizing the
  20 000 entry merge at ~0.3 µs/entry hash op ≈ 6 ms aggregate per
  ledger ≈ ~2.8% of the 211 ms soroswap baseline at the upper bound,
  but only the serial subset of that work appears on the critical
  path, and partition-shard parallelization can at best halve it.

## Sizing Against Objective Severity

- Even at the upper bound of ~6 ms/ledger serial merge cost
  (2.8% of 211 ms), parallel-partition redesign cannot eliminate all
  serial cost: hash-map emplace into the global map remains necessary
  even with per-thread output partitions (or requires migrating
  `mGlobalEntryMap` to a multi-shard structure, which has read-side
  cost in every later access point).
- Conservatively, the achievable saving is in the 1–2 ms/ledger range
  (~0.5–1% of apply), which is **below the objective's 3% Medium
  floor and at-or-below the 1% Low floor**.
- Per the objective's severity gate this falls in the
  "below objective severity threshold (Low not accepted at hypothesis
  stage)" bucket.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated under this specific zone
(prior commit-tail rejections targeted `commitChangesToLedgerTxn` outer
merge, not the inner thread-state merge)

### Why It Failed

The `commitChangesFromThreads` serial tail is real and on the critical
path, but its per-entry hash-map cost is bounded at the same order of
magnitude as the rejected `commitChangesToLedgerTxn` zone (0.14%
of apply). Even at the conservative upper bound of ~6 ms aggregate
per ledger, the achievable saving after accounting for the unavoidable
emplace cost is <1% of apply — below the objective's Low floor and far
below the Medium threshold. Per meta-pattern 14 (sub-millisecond serial
paths exhausted), this kind of serial-tail micro-optimization is no
longer in scope for this objective.

### Lesson Learned

For any serial-tail merge work after the cluster join barrier, size the
achievable saving as `(serial_zone_aggregate_ms - residual_serial_cost) /
apply_baseline_ms`. Partition-shard schemes still require an
emplace/concatenation step that itself runs serially; "free
parallelization" is not available for already-bottlenecked hash-map
merges.
