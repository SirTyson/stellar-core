# H003: Defer `addHotArchiveBatch` Future Across Finalize Boundary

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / bucket
**Severity**: Low
**Impact**: Apply-time critical path (finalize phase)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Of the three async-style writers spawned at the end of
`finalizeLedgerTxnChanges` (`addHotArchiveBatch (async)`, `addLiveBatch` run
synchronously on the current thread, and `updateInMemorySorobanState
(async)`), the apply critical path should block only on the synchronous
work that the *next* ledger truly needs before it can begin applying
again. In particular, the hot-archive bucket list is consulted during
the next ledger's apply only via the read-only `BucketSnapshot` taken in
`advanceBucketListSnapshotAndMakeLedgerState`, so the merge work backing
`addHotArchiveBatch` could in principle complete after `finalize` returns,
as long as the next ledger's snapshot-advance step joins on it before
publishing a new snapshot.

## Mechanism

`finalizeLedgerTxnChanges` ends by joining `hotArchiveBatchFuture.get()`
and `inMemoryStateUpdateFuture.get()` (LedgerManagerImpl.cpp:3358-3366),
making the apply-critical path wait for the *slowest* of the three
writers. In the current soroswap trace `addLiveBatch` takes ~4.2 ms
(sync), `addHotArchiveBatch (async)` takes ~5.6 ms, and
`updateInMemorySorobanState (async)` takes ~0.34 ms, so the hot-archive
future is the limiter, costing ~1.4 ms/ledger of pure wait time on top
of the live-batch sync work. Deferring the hot-archive join to the start
of the next ledger's `advanceBucketListSnapshot` (or to whenever a fresh
hot-archive snapshot is first needed) would let that ~1.4 ms overlap
with the next ledger's tx-set construction, fee processing, and the
opening of `applyParallelPhase`.

## Trigger

Reproduce by running the standard soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py` with the soroswap shape) and
measuring `finalizeLedgerTxnChanges` self-time vs. the per-ledger max
of `addLiveBatch`, `addHotArchiveBatch (async)` and
`updateInMemorySorobanState (async)`. The current trace shows ~1.4 ms
of pure hot-archive wait per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp::finalizeLedgerTxnChanges:3220-3367`
  — join sites for `hotArchiveBatchFuture` and `inMemoryStateUpdateFuture`.
- `src/ledger/LedgerManagerImpl.cpp::advanceBucketListSnapshotAndMakeLedgerState`
  — natural deferred-join point for the hot-archive future.
- `src/bucket/BucketManager.cpp::addHotArchiveBatch` — the async work
  body (~5.6 ms/ledger in soroswap).

## Evidence

Tracy zones from the accepted soroswap trace
(`b196b6238`, `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`):

| Zone                                | Total (s) | Calls | Per ledger (ms) |
|-------------------------------------|-----------|-------|-----------------|
| `addHotArchiveBatch (async)`        | 0.385     | 69    | 5.58            |
| `addLiveBatch`                      | 0.295     | 70    | 4.21            |
| `updateInMemorySorobanState (async)`| 0.0234    | 70    | 0.34            |

Critical-path wait inside `finalizeLedgerTxnChanges` ≈
`max(5.58, 4.21, 0.34) − 4.21 = 1.37 ms` per ledger
(addLiveBatch is sync so it always pays its 4.21 ms regardless).

## Anti-Evidence

- `gIsProductionNetwork` and `Protocol23CorruptionDataVerifier` paths
  also touch the hot-archive future synchronously
  (LedgerManagerImpl.cpp:3274, 3296-3301), constraining when the join
  can actually be deferred.
- `BucketManager`'s public surface assumes hot-archive batches have
  landed before snapshot advance, so deferring the join requires
  threading the future through `advanceBucketListSnapshot…` and
  carefully reasoning about every reader of `mHotArchiveBucketList`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — fail #001 covered making `addLiveBatch` async; this
hypothesis is the symmetric case of deferring the hot-archive future
*past* the finalize boundary and is not duplicated in fail / hypothesis
/ reviewed / poc.

### Why It Failed

The measured critical-path wait that this hypothesis would remove is
~1.4 ms/ledger out of ~83.7 ms = ~1.7% of apply time, below the Medium
floor (3%) for this objective. The implementation cost is non-trivial:
the join would have to migrate from `finalizeLedgerTxnChanges` into
`advanceBucketListSnapshotAndMakeLedgerState` while keeping the P23
corruption-verifier path and `gIsProductionNetwork` upgrade path
synchronous, and every other reader of `mHotArchiveBucketList` would
need an audit. The risk/reward ratio is poor for a sub-2% gain.

### Lesson Learned

Three-way async fan-out at the end of `finalizeLedgerTxnChanges` is
already balanced enough that the slowest writer determines wall time:
in soroswap that is `addHotArchiveBatch`, but only by ~1.4 ms over the
sync `addLiveBatch`. To make a Medium-tier dent, an optimization must
either shorten `addHotArchiveBatch` itself or — more promisingly —
overlap *all three* writers with the next ledger's apply phase, not
just one of them.
