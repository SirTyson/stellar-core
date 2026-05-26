# H004: Defer `inMemoryStateUpdateFuture.get()` past `unsealHeader` to extend async overlap window

**Date**: 2026-05-26
**Subsystem**: ledger / finalize + seal
**Severity**: Low
**Impact**: Apply-thread serial reduction in `sealLedgerTxnAndStoreInBucketsAndDB` by deferring the in-memory-soroban-state update join past the bucket snapshot + DB persistence work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3222`) launches two independent
async tasks during commit:

- `addHotArchiveBatch (async)` at line 3286 — writes the hot archive
  BucketList.
- `updateInMemorySorobanState (async)` at line 3345 — updates the
  `InMemorySorobanState` cache.

It then runs the synchronous `addLiveBatch` at line 3356, and finally
joins both futures at lines 3361 / 3365 before returning. The two
async targets touch state that is independent from the work that
follows `finalizeLedgerTxnChanges` inside
`sealLedgerTxnAndStoreInBucketsAndDB` — namely `ltx.unsealHeader(...)`
at line 3412, which calls `BucketManager::snapshotLedger`,
`storePersistentStateAndLedgerHeaderInDB`, and
`advanceApplySnapshotAndMakeLedgerState`. Of those:

- `snapshotLedger` only reads `mLiveBucketList` and
  `mHotArchiveBucketList` (already updated by addLiveBatch /
  addHotArchiveBatch — the hot archive future would still need to be
  joined before snapshotLedger or its result captured separately).
- `storePersistentStateAndLedgerHeaderInDB` is a SQL write that does
  not touch `InMemorySorobanState`.
- `advanceApplySnapshotAndMakeLedgerState` →
  `buildLedgerState` only reads bucket-list pointers + an optional
  Soroban config; it does not read `InMemorySorobanState`.

Expected correct behavior is that `mApplyState.getInMemorySorobanState()`
returns the post-apply state before the next ledger begins. The earliest
real consumer in the apply path is the next ledger's
`GlobalParallelApplyLedgerState` construction
(`ParallelApplyUtils.cpp:386`), which reads
`mApplyState.getInMemorySorobanState()`. If the join is moved to right
before the next apply (or to the end of `applyLedger` after publish), the
async window grows from ~addLiveBatch duration to ~addLiveBatch +
unsealHeader + advance + publish, allowing the in-memory state update to
overlap with all of that serial work for free.

## Mechanism

The current join inside `finalizeLedgerTxnChanges` artificially caps
the async overlap window at the synchronous `addLiveBatch` duration.
Any time `updateInMemorySorobanState` is slower than `addLiveBatch`,
the apply thread waits at line 3365 for the remainder. Deferring the
join past `unsealHeader` (and ideally past `maybeRebuildModuleCache`
at line 3425) would let the async task overlap with `snapshotLedger`,
DB header write, and snapshot publishing — all serial apply-thread
work that does not depend on `InMemorySorobanState`.

## Trigger

Run the soroswap apply-load matrix scenario. Soroswap is Soroban-heavy
and produces a large number of CONTRACT_DATA writes per ledger that
`updateInMemorySorobanState` must absorb; if its wall time exceeds
`addLiveBatch`, the join at line 3365 is on the critical path.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3340-3367` — async launch and
  same-function join of `inMemoryStateUpdateFuture`.
- `src/ledger/LedgerManagerImpl.cpp:3411-3419` —
  `unsealHeader`/`snapshotLedger`/`storePersistentStateAndLedgerHeaderInDB`/`advanceApplySnapshotAndMakeLedgerState`
  block that the join could be deferred past.
- `src/ledger/LedgerManagerImpl.cpp:3425` —
  `mApplyState.maybeRebuildModuleCache` (uses module cache, not
  in-memory Soroban state).
- `src/ledger/LedgerManagerImpl.cpp:2187-2214` — `buildLedgerState`:
  only reads bucket lists; does not read InMemorySorobanState.
- `src/transactions/ParallelApplyUtils.cpp:386` —
  `GlobalParallelApplyLedgerState` ctor: earliest in-memory-state
  reader on the next ledger apply path.

## Evidence

- The two async tasks are already explicitly designed to overlap with
  `addLiveBatch` (see the comment block at lines 3334-3339), proving
  the state-independence argument is already accepted by the codebase.
- `buildLedgerState` (line 2187) does not call any
  `InMemorySorobanState` method; the soroban config it propagates is
  loaded from the BucketList snapshot, not from in-memory state
  (line 2200-2203).
- Tracy zone `addLiveBatch` mean = 4.28 ms/ledger; the bracketing
  serial work (unsealHeader → buildLedgerState → publish) extends the
  apply-thread tail by several more ms — additional overlap budget
  available essentially for free.

## Anti-Evidence

- Tracy zone `updateInMemorySorobanState (async)` in the current
  soroswap trace
  (`9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`)
  has total 2.62 ms across 72 calls, **mean 36 µs/call**, max
  158 µs. The async task is already finishing far inside the
  `addLiveBatch` window (4.28 ms), so the join at line 3365 is
  essentially zero-wait today. Deferring the join saves nothing.
- The maximum recoverable amount per ledger is bounded by the **wait
  portion** of the join, not by the worker's total wall time. With a
  36 µs worker overlapping a 4.28 ms `addLiveBatch`, the wait portion
  is effectively zero.
- Hot-archive batch future would still need to be joined before
  `snapshotLedger` (which reads `mHotArchiveBucketList`); only the
  in-memory state future could be deferred. That further restricts
  the lever to a worker that is already sub-50-µs.
- The recoverable fraction (≪ 0.05% of apply time) is far below
  benchmark noise floor (1%) and the Medium severity threshold (3%).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — adjacent `addLiveBatch`/async-overlap failures
(`013-async-addlivebatch-overlap-in-finalize.md`,
`006-overlap-put-loop-with-async-finalize-tasks.md`) targeted the
opposite direction (overlapping addLiveBatch with async); deferring the
`updateInMemorySorobanState` join past `unsealHeader` was not previously
investigated.

### Why It Failed

Below this objective's Medium severity threshold (3-10% apply time
reduction). The `updateInMemorySorobanState (async)` worker takes a
mean of 36 µs per ledger — orders of magnitude less than the 4.28 ms
`addLiveBatch` it already overlaps with. The join at line 3365 is
essentially zero-wait today; deferring it cannot recover time that
isn't being lost. The recoverable fraction is far below the 1% noise
floor, let alone the 3% Medium threshold.

### Lesson Learned

When proposing to defer or extend an async-overlap window, first
measure the async task's **wall time on its worker thread** (Tracy
mean for the worker zone). If that wall time is already comfortably
inside the synchronous task it parallels, the join is not on the
critical path and no amount of window extension can recover apply
time. Use `csvexport-release -e` and compare the worker zone's mean
to the synchronous parallel task's mean before drafting the
hypothesis.
