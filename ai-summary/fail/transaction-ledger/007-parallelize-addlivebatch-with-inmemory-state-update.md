# H007: Parallelize `addLiveBatch` with `updateInMemorySorobanState` in `finalizeLedgerTxnChanges`

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / bucket
**Severity**: Low–Medium (borderline)
**Impact**: critical-path overlap of two independent post-apply phases
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `getAllEntries` seals the ltx and produces `initEntries`, `liveEntries`,
`deadEntries`, the post-apply work consists of three logically independent
operations:

1. `addHotArchiveBatch` — modifies `mHotArchiveBucketList` (already async).
2. `updateInMemorySorobanState` — modifies `mInMemorySorobanState` (already async).
3. `addLiveBatch` — modifies `mLiveBucketList` (currently **synchronous** on the apply thread).

All three touch disjoint data structures and have no ordering dependency
on each other. The apply critical path inside `finalizeLedgerTxnChanges`
should therefore complete in `max(t_hotArchive, t_inMemory, t_addLive)`
time, not `t_addLive + max(t_hotArchive, t_inMemory)` time.

## Mechanism

`src/ledger/LedgerManagerImpl.cpp:3334-3367` launches `addHotArchiveBatch`
and `updateInMemorySorobanState` via `std::async(std::launch::async, ...)`
but runs `addLiveBatch` synchronously on the apply thread before joining
the futures. `addLiveBatch`'s synchronous portion (Tracy zones
`prepareFirstLevel` ≈ 2.5 ms / ledger + `mergeInMemory` ≈ 1.9 ms / ledger
plus the level-1+ `addBatchInternal` orchestration) is the single largest
serial block in this phase. By also launching `addLiveBatch` on a worker
thread and joining at the bottom alongside the other two, the apply thread
would only pay
`max(t_addLive, t_inMemorySoroban, t_hotArchive)` instead of the current
`t_addLive + 0`-overlap-with-others arrangement (the asyncs finish first
on soroswap because they're cheaper).

## Trigger

Run soroswap apply-load benchmark. On every ledger close,
`finalizeLedgerTxnChanges` runs `addLiveBatch` serially while two cheaper
async tasks have already completed.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3334-3367` — currently launches 2
  futures, runs `addLiveBatch` synchronously, joins.
- `src/bucket/LiveBucketList.cpp:15-…` and
  `src/bucket/BucketListBase.cpp:684-…,196-238` — `addBatch` /
  `addBatchInternal` / `prepareFirstLevel` are the synchronous portion.
- `src/ledger/LedgerManagerImpl.cpp:3354-3355` — `addAnyContractsToModuleCache`
  calls that precede `addLiveBatch` would need to move before the async
  launch (they touch the module cache and can run synchronously cheaply).

## Evidence

- Code comment at line 3334 explicitly states "All three can run in
  parallel" — the design contract already acknowledges independence.
- `addHotArchiveBatch` and `updateInMemorySorobanState` are already
  launched via `std::async(std::launch::async, ...)` with identical
  capture / join pattern — the third launch would be a mechanical
  copy-paste of the same scaffolding.
- Tracy shows `addLiveBatch` synchronous self-time of ~4–5 ms / ledger
  on soroswap; making it overlap with the in-memory update (~2–3 ms)
  would shave ~2–3 ms off the critical path.

## Anti-Evidence

- Projected savings (2–3 ms / ledger out of 207 ms baseline) = ~1–1.5%.
  This sits at the Low / sub-Low border — below the objective's
  Medium floor (3% / ~6.2 ms / ledger).
- Adds one more `std::async` launch (~µs of thread-pool overhead) plus
  data-lifetime management for `initEntries` / `liveEntries` / `deadEntries`
  shared between three workers; the vectors currently passed by reference
  must outlive all three futures. Easy with shared_ptr or capture-by-move
  but adds complexity.
- `addLiveBatch` triggers `BucketManager` background-merge scheduling
  (`FutureBucket` setup at levels 1..MAX) which itself spawns more
  threads; running addLiveBatch on a worker just shifts the same
  work to a different thread with no algorithmic improvement.
- Meta-Pattern #26: addLiveBatch → snapshotLedger chain is
  *mandatory synchronous* because subsequent `sealLedgerTxnAndStoreInBucketsAndDB`
  reads `mLiveBucketList`'s hash. Joining at the bottom of
  `finalizeLedgerTxnChanges` preserves this — but the available overlap
  is bounded by the cheaper concurrent task, capping the win at the
  duration of `updateInMemorySorobanState`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PARTIAL — prior fail
`004-async-defer-higher-level-addbatchinternal-orchestration.md`
addressed deferring level-1+ `FutureBucket` scheduling but did not
specifically propose running the entire `addLiveBatch` call concurrently
with the existing `inMemoryStateUpdateFuture`. The angle is narrowly
novel but the projected ceiling kills it.

### Why It Failed

Speedup ceiling is `min(t_addLive, t_inMemorySoroban + t_hotArchive_remaining)`,
which on soroswap is bounded by the ~2–3 ms cost of the cheaper concurrent
task. That's ~1.0–1.5% of the 207 ms baseline — clearly below the 3% Medium
floor mandated by the objective. Even pessimistically rounding up to 3 ms,
the gain barely clears Low and would not survive 3-run benchmark variance
(the meta-pattern repeatedly observed σ ≈ 1–2 ms across runs on this benchmark).

The architectural argument ("three independent data structures, max
parallelism") is correct, and the code is genuinely sequentially-suboptimal,
but the soroswap workload doesn't have enough post-apply serial work for
this overlap to break the Medium threshold on its own.

### Lesson Learned

Future viable wins in `finalizeLedgerTxnChanges` need to attack the
*synchronous portion of `addLiveBatch` itself* (the
`prepareFirstLevel`/`mergeInMemory` work), not just shift it to a worker
thread. Critical-path-overlap optimizations are bounded by the duration
of the cheapest concurrent task; for soroswap, the in-memory Soroban
state update is too cheap (~2–3 ms) to make this kind of overlap a Medium
win. A redesign that actually parallelizes `mergeInMemory` (e.g.,
sharded merge across NUM_CLUSTERS workers) or that elides the
synchronous level-0 in-memory merge entirely (already covered by prior
fail `002-skip-empty-curr-merge-walk-fast-path.md`) is the only path
above the threshold.
