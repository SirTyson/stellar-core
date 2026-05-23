# H011: Defer `addLiveBatch` Bucket Merge to a Post-Apply Async Future

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (bucket commit boundary)
**Severity**: Low
**Impact**: Apply-time reduction in `finalizeLedgerTxnChanges`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `applyParallelPhase` and `finalizeLedgerTxnChanges` build the
`initEntries`/`liveEntries`/`deadEntries` vectors, the bucket commit work
(`addLiveBatch` -> `prepareFirstLevel` -> `freshInMemoryOnly` +
`mergeInMemory`) should overlap with as much subsequent apply-thread work as
possible. Ideally any serial bucket commit work happens only when something
truly depends on the new BucketList state (the next ledger's prefetch /
snapshot consumers), not during the apply critical path that produces the
`CompleteConstLedgerState` for this ledger.

## Mechanism

In `LedgerManagerImpl::finalizeLedgerTxnChanges`
(src/ledger/LedgerManagerImpl.cpp:3354-3366) `addAnyContractsToModuleCache`
and `addLiveBatch` run synchronously on the apply thread after launching
`hotArchiveBatchFuture` and `inMemoryStateUpdateFuture`. `addLiveBatch` is
the dominant serial component (4.4 ms / ledger = 2.0% of the soroswap
median). Hoisting `addLiveBatch` into a third `std::async` task and only
joining it at the start of the next ledger's `applyLedger` (or just before
the next `snapshotLedger` call) would let the apply thread return its
`CompleteConstLedgerStatePtr` ~4 ms sooner, which propagates to the
benchmark's reported apply time.

## Trigger

Run the soroswap benchmark with the current accepted stack. Tracy shows
`addLiveBatch` 312 ms / 71 ledgers (4.4 ms/L) and `finalizeLedgerTxnChanges`
342 ms / 71 ledgers (4.8 ms/L), with `addLiveBatch` accounting for ~92% of
the latter's serial cost.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3366` — serial `addLiveBatch` call.
- `src/ledger/LedgerManagerImpl.cpp:3411-3419` — `unsealHeader` body that
  calls `mApp.getBucketManager().snapshotLedger(lh)` and computes
  `CompleteConstLedgerStatePtr`.
- `src/bucket/BucketManager.cpp:1026` — `addLiveBatch` entry.

## Evidence

- `addLiveBatch` is ~92% of `finalizeLedgerTxnChanges` serial cost.
- The other two async tasks (`hotArchive`, `inMemoryStateUpdate`) already
  prove the pattern; `addLiveBatch` is structurally similar (operates on
  the independent `mLiveBucketList`).
- Several follow-on operations (`storePersistentStateAndLedgerHeaderInDB`
  146 µs/L, `snapshotLedger` 10 µs/L) are tiny and rapidly free the apply
  thread.

## Anti-Evidence

- `snapshotLedger` (line 3414) snapshots the live BucketList header
  immediately after `addLiveBatch`. Its result feeds `LedgerHeader.bucketListHash`
  and is required for the published `CompleteConstLedgerState`. Deferring
  `addLiveBatch` past this point would corrupt the published ledger header.
- The whole `sealLedgerTxnAndStoreInBucketsAndDB` runs under
  `mLedgerStateMutex` (line 3379). Releasing the apply thread early does
  not let other ledger-close work proceed because the next `applyLedger`
  will re-acquire the same mutex.
- `mApplyState.maybeRebuildModuleCache` (line 3425) and downstream
  consumers expect a fully-committed BucketList.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior `addLiveBatch` async attempts
that targeted the level-0 merge writer specifically.

### Why It Failed

`addLiveBatch` is followed immediately by `snapshotLedger` which computes
the published `bucketListHash` for the new ledger. The `bucketListHash`
must be in the committed `LedgerHeader` returned by
`sealLedgerTxnAndStoreInBucketsAndDB`. Deferring `addLiveBatch` therefore
cannot defer the hash — the apply thread must block on the merge before
publishing the `CompleteConstLedgerState`. Moreover, the entire
`sealLedger…` body holds `mLedgerStateMutex`, so even a partial early
return would not free a concurrent ledger-close path. The realistically
achievable overlap is bounded by the few hundred microseconds of
`storePersistentStateAndLedgerHeaderInDB` / `maybeRebuildModuleCache`,
well below the 1% noise floor.

### Lesson Learned

`addLiveBatch` cannot be deferred past `snapshotLedger` without a
protocol-visible change to how `bucketListHash` is computed. Future
hypotheses in this region should instead target the *internal* cost of
`prepareFirstLevel` / `mergeInMemory put loop` directly (3.1 ms/L
combined), and only if a parallelization scheme can preserve the
sorted-merge invariant deterministically.
