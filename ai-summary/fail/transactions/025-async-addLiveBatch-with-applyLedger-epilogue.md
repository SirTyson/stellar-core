# H025: Async addLiveBatch Overlapping applyLedger Epilogue (storePersistent + ltx.commit + history checkpoint)

**Date**: 2026-05-24
**Subsystem**: transactions (apply-path bucket-write pipelining)
**Severity**: Low
**Impact**: apply-time reduction (soroswap headline)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges` already launches `addHotArchiveBatch` and
`updateInMemorySorobanState` as `std::async` futures while running
`addLiveBatch` synchronously on the apply thread, then joins both at the
end. The hot-archive future (41 ms aggregate) and in-memory-state future
(2.7 ms) overlap fully with `addLiveBatch` (330 ms aggregate, the dominant
serial cost).

A correct apply path could also kick off `addLiveBatch` as a third async
future at the start of `finalizeLedgerTxnChanges`, returning control to the
apply thread immediately, and overlap the live-bucket work with the rest of
`sealLedgerTxnAndStoreInBucketsAndDB`'s epilogue:
`storePersistentStateAndLedgerHeaderInDB` (≈9.8 ms),
`advanceApplySnapshotAndMakeLedgerState`, `ltx.commit()` /
`commitChild` (≈34 ms), and `maybeQueueHistoryCheckpoint`. The
`BucketListHash` would still be needed for the LedgerHeader inside
`storePersistentStateAndLedgerHeaderInDB`, so the future must be joined
before that point.

## Mechanism

Async-dispatching `addLiveBatch` removes the 330 ms of CPU/IO work from the
apply thread, replacing it with a future-wait at the LedgerHeader-hash
point. The apply thread's overlapping work shrinks the critical path by the
amount of apply-thread work that runs concurrently with the now-async
`addLiveBatch`. In the current code structure, this overlapping window is
the apply-thread work between the start of `finalizeLedgerTxnChanges` and
the call to `mApp.getBucketManager().snapshotLedger(lh)` (which reads the
BucketList hash inside `sealLedgerTxnAndStoreInBucketsAndDB:3414`).

## Trigger

Run the soroswap apply-load benchmark on the current baseline; observe
`finalizeLedgerTxnChanges` at 362 ms = 7.55% of `applyLedger`, of which
`addLiveBatch` accounts for 330 ms = 6.87% (the rest is small:
`resolveBackgroundEvictionScan` 2 ms, `getAllEntries` 18.7 ms,
`addAnyContractsToModuleCache` 2.2 ms, plus eviction key iteration).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3368` — `finalizeLedgerTxnChanges`
  — wrap `addLiveBatch` in a third `std::async`, join before BucketListHash
  is read.
- `src/ledger/LedgerManagerImpl.cpp:3370-3429` —
  `sealLedgerTxnAndStoreInBucketsAndDB` — the apply-thread work that could
  run concurrently with the async `addLiveBatch`.
- `src/bucket/BucketListBase.cpp:684-797` —
  `BucketListBase::addBatchInternal` — confirm reentrancy / thread safety
  of the live BucketList update path against concurrent reads.

## Evidence

- The async pattern is already proven inside `finalizeLedgerTxnChanges`
  for `addHotArchiveBatch` (41 ms) and `updateInMemorySorobanState` (3 ms)
  — adding a third future for `addLiveBatch` matches the existing
  template.
- 330 ms of bucket-write CPU/IO work currently blocks the apply thread.
- `storePersistentStateAndLedgerHeaderInDB` is the consumer of the
  BucketList hash and is the natural join point.

## Anti-Evidence

- The apply-thread work that could overlap with the async `addLiveBatch`
  is small. Bounded above by:
  - `storePersistentStateAndLedgerHeaderInDB` self ≈ 9.8 ms
  - `ltx.commit` / `commitChild` ≈ 34 ms (runs AFTER
    `sealLedgerTxnAndStoreInBucketsAndDB` returns, i.e. AFTER the join)
  - `maybeQueueHistoryCheckpoint`, `advanceApplySnapshotAndMakeLedgerState`,
    misc bookkeeping: a few ms
- The `BucketListHash` (read by `snapshotLedger(lh)` inside the
  `ltx.unsealHeader` callback) is needed BEFORE
  `storePersistentStateAndLedgerHeaderInDB`. So the future MUST be joined
  before that point, leaving only the ≈18 ms `getAllEntries` and the
  small eviction-key iteration / `addAnyContractsToModuleCache` (~25 ms
  total) as overlappable apply-thread work.
- Real-world thread spawn / join overhead and contention on
  `BucketManager`'s synchronized state would consume part of the savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior bucket fails. The previously failed
hypotheses targeted: lazy level-0 physical file materialization
(`001-lazy-level0-live-bucket-file-materialization.md`), raw XDR sidecar
writers to skip re-serialization
(`002-raw-xdr-live-bucket-writes.md`), and pipelining the
`BucketOutputIterator::put` loop only
(`004-blocking-live-bucket-put-loop-below-threshold.md`). None targeted
async-dispatching the entire `addLiveBatch` as a third
`finalizeLedgerTxnChanges` future overlapping with the apply-thread
epilogue.

### Why It Failed

The `BucketListHash` is read inside the
`ltx.unsealHeader([&](LedgerHeader& lh) { mApp.getBucketManager()
.snapshotLedger(lh); ... })` callback at
`LedgerManagerImpl.cpp:3414`, which fires immediately after
`finalizeLedgerTxnChanges` returns and BEFORE
`storePersistentStateAndLedgerHeaderInDB`. So the async `addLiveBatch`
future must be joined at the end of `finalizeLedgerTxnChanges` (matching
the existing `hotArchiveBatchFuture.get()` / `inMemoryStateUpdateFuture.get()`
pattern), not later.

Inside `finalizeLedgerTxnChanges`, after `getAllEntries` returns (which
seals the LTX and is required before `addLiveBatch` can read entries), the
apply-thread work that could run while `addLiveBatch` is in flight is:

- `addAnyContractsToModuleCache(initEntries)` + `addAnyContractsToModuleCache
  (liveEntries)` ≈ 2.2 ms aggregate
- Waiting on `hotArchiveBatchFuture` (already async)
- Waiting on `inMemoryStateUpdateFuture` (already async)

Hot-archive and in-memory state futures complete in 41 ms and 3 ms
respectively, well before `addLiveBatch`'s 330 ms. The only NEW
apply-thread work to overlap is the 2.2 ms module-cache iteration, plus
sub-millisecond bookkeeping. Critical-path savings ≤ 2.2 ms ≈ 0.05% of
`applyLedger` — far below the 1% noise floor and the 3% Medium floor.

Pushing the join later (e.g., into `storePersistentStateAndLedgerHeaderInDB`)
would break the BucketListHash invariant: the LedgerHeader must contain
the BucketListHash including this ledger's level-0 update before being
hashed into the LCL, and consensus / catchup correctness depend on this
hash being present in the ledger N's LedgerHeader at the end of
`applyLedger N`.

### Lesson Learned

The `finalizeLedgerTxnChanges` async pattern (already used for
`addHotArchiveBatch` and `updateInMemorySorobanState`) cannot be extended
to `addLiveBatch` for meaningful savings: the join point is constrained
by the synchronous `BucketListHash` read in
`sealLedgerTxnAndStoreInBucketsAndDB`'s `unsealHeader` callback, and the
overlappable apply-thread work between `getAllEntries` and the join is
< 5 ms. Future bucket-pipelining hypotheses must either (a) move the
join later by deferring `BucketListHash` computation past the
LedgerHeader hash (which breaks consensus correctness) or (b) restructure
the level-0 hash so it can be computed without finishing the disk
write — neither is on the table for soroswap.
