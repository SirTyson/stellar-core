# H006: Overlap Synchronous `addLiveBatch` Put-Loop with Async Finalize Tasks

**Date**: 2026-05-05
**Subsystem**: ledger
**Severity**: Low
**Impact**: apply time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3222`) runs three async tasks in
parallel with synchronous work:
`addHotArchiveBatch (async)`, `updateInMemorySorobanState (async)`, and
the synchronous `addLiveBatch` -> `prepareFirstLevel` -> `mergeInMemory`
chain. Maximally overlapping wall-clock would push `addLiveBatch`'s
synchronous put-loop work into a worker thread that runs in parallel
with the finalize-time async tasks, joining only at the boundary where
`snapshotLedger` requires the new bucket-list state.

## Mechanism

The synchronous put-loop inside `mergeInMemory`
(`src/bucket/LiveBucket.cpp:678`) is on the apply critical path for
`finalizeLedgerTxnChanges`. While `addHotArchiveBatch (async)` and
`updateInMemorySorobanState (async)` run in parallel, their wall-clock
contribution is too small to overlap meaningfully with the put-loop:
`addHotArchiveBatch (async)` total ≈ 38.9 ms / 71 ledgers ≈ 0.55 ms /
ledger, and `updateInMemorySorobanState (async)` total ≈ 2.6 ms / 72 ≈
36 µs / ledger. Both are vastly smaller than the put-loop wall time
(~1.9 ms/ledger), so a put-loop run on a worker thread would provide
no overlap savings — the join point is set by the longest async leg
(the put-loop itself).

This is distinct from `013-async-addlivebatch-overlap-in-finalize.md`
(which proposed overlapping `addLiveBatch` with `addAnyContractsToModuleCache`)
and `014-defer-bucket-file-write-mergeinmemory.md` (which proposed deferring
the write itself). Here the proposal is overlap with the existing async
tasks already running inside finalize.

## Trigger

Soroswap close ledger; finalize phase with three async tasks plus
synchronous bucket-batch work.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3222-3380` — `finalizeLedgerTxnChanges`
  (async task launches and joins)
- `src/bucket/LiveBucket.cpp:614-688` — `mergeInMemory` synchronous
  put-loop region

## Evidence

- `addLiveBatch` total ≈ 296 ms / 71 ledgers ≈ 4.17 ms/ledger ≈ 5.66%
  of `applyLedger`.
- The async siblings `addHotArchiveBatch (async)` and
  `updateInMemorySorobanState (async)` together ≈ 0.59 ms/ledger;
  smaller than the put-loop wall time, so they cannot mask any of it.
- Since both async siblings already run during the synchronous
  `addLiveBatch`, the only available "extra overlap" target would be
  the residual sync work after the put loop — but that work is
  `addAnyContractsToModuleCache` (already analysed at sub-1% in fail
  013).

## Anti-Evidence

- `snapshotLedger` (line 3414) consumes the bucket-list hash and HAS
  immediately after `finalizeLedgerTxnChanges` returns; the put-loop's
  output (the new `curr` hash) is required at that boundary.
- The async siblings are dominated by `addHotArchiveBatch` writing zero
  entries on soroswap (no archived entries this ledger), so even
  optimal scheduling cannot extract more than their total wall time as
  overlap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `013-async-addlivebatch-overlap-in-finalize.md`
(that one targets overlap with `addAnyContractsToModuleCache`; this one
targets overlap with the already-async `addHotArchiveBatch` /
`updateInMemorySorobanState` tasks).

### Why It Failed

The two async tasks already running during the synchronous put-loop
contribute only ~0.59 ms/ledger of wall time, vs ~1.9 ms/ledger of
synchronous put-loop wall. The overlap is upper-bounded by the smaller
leg, so even ideal scheduling saves at most 0.6 ms/ledger ≈ 0.8% of
applyLedger — well below the 3% Medium floor.

### Lesson Learned

For finalize-phase overlap hypotheses, quantify both legs of any
proposed overlap. Wall-time savings are bounded by the shorter leg, so
overlapping a long synchronous task (put-loop) with two short async
tasks (`addHotArchiveBatch`, `updateInMemorySorobanState`) yields at
most the sum of those short tasks' wall times. In soroswap that sum
is sub-1% of applyLedger.
