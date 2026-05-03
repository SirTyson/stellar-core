# H013: Launch `addLiveBatch` asynchronously to overlap with `addAnyContractsToModuleCache` in `finalizeLedgerTxnChanges`

**Date**: 2026-05-03
**Subsystem**: ledger / bucket commit on apply path
**Severity**: Low
**Impact**: <1% apply-time reduction (below Medium threshold)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `ltx.getAllEntries(initEntries, liveEntries, deadEntries)` seals the
LedgerTxn at `src/ledger/LedgerManagerImpl.cpp:3332`, the only true
serial dependency for `BucketManager::addLiveBatch` is the entry vectors,
all of which are produced by that single seal call. The remaining work
inside `finalizeLedgerTxnChanges` —
`addAnyContractsToModuleCache(initEntries)` /
`addAnyContractsToModuleCache(liveEntries)` — only needs the same vectors
and modifies independent state (`SorobanModuleCache`), so it could run
concurrently with `addLiveBatch` rather than sequentially before it.

## Mechanism

Currently `addLiveBatch` (≈4.1 ms / ledger, the largest synchronous
post-seal cost) runs after the two `addAnyContractsToModuleCache` calls on
the primary apply thread. If `addLiveBatch` were dispatched via
`std::async(std::launch::async, ...)` immediately after `getAllEntries`,
the apply thread could perform `addAnyContractsToModuleCache(init)` and
`addAnyContractsToModuleCache(live)` while the bucket merge runs in
parallel. The future would then be joined just before `snapshotLedger`
inside `sealLedgerTxnAndStoreInBucketsAndDB`.

## Trigger

Run `apply-load --mode soroswap-tps`. Observe that `addLiveBatch` is on
the primary apply-thread critical path inside `finalizeLedgerTxnChanges`
and runs strictly serially with `addAnyContractsToModuleCache`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3340-3367` —
  `finalizeLedgerTxnChanges` async/sync ordering of
  `inMemoryStateUpdateFuture`, `addAnyContractsToModuleCache`,
  `addLiveBatch`, and the trailing `future.get()` waits.
- `src/ledger/LedgerManagerImpl.cpp:3408-3419` —
  `sealLedgerTxnAndStoreInBucketsAndDB` chain through
  `snapshotLedger` / `storePersistentStateAndLedgerHeaderInDB` /
  `advanceApplySnapshotAndMakeLedgerState`.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch`.

## Evidence

- Trace `9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`:
  `addLiveBatch` total 296 M ns / 72 = ~4.1 ms / ledger ≈ 2.88 % of
  trace, all on the apply thread inside `applyLedger`.
- `inMemoryStateUpdateFuture` (modifies `mInMemorySorobanState`) is
  already dispatched async and the existing comment at lines 3338-3339
  explicitly notes that `addLiveBatch`, `addHotArchiveBatch`, and
  `updateState` modify disjoint backing structures.
- `addAnyContractsToModuleCache` is a per-entry enum scan over
  init+live entries, on the same apply thread between
  `inMemoryStateUpdateFuture` launch and `addLiveBatch` (lines
  3354-3357).

## Anti-Evidence

- `addAnyContractsToModuleCache` is essentially free per fail-summary
  entry 009 (two enum scans over a few thousand entries, sub-1 % of
  `applyLedger`). The available overlap budget is therefore ≪1 ms,
  not the full 4.1 ms.
- `snapshotLedger` (called immediately after `finalizeLedgerTxnChanges`
  returns in `sealLedgerTxnAndStoreInBucketsAndDB`) reads
  `mLiveBucketList` state and so requires `addLiveBatch` to be
  complete; the join cannot be deferred past that point.
- The realistic savings are bounded by the duration of the only work
  that can overlap (≪1 ms), so the projected delta is well under 1 %
  of applyLedger — below benchmark noise and far below the Medium tier.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a finalize-reorder
  hypothesis (rejected entry 002-futurebucket-resolve-wait targeted a
  different blocking-wait pattern).

### Why It Failed

The only work available to overlap with `addLiveBatch` between
`getAllEntries` and the next hard barrier (`snapshotLedger` inside
`sealLedgerTxnAndStoreInBucketsAndDB`) is
`addAnyContractsToModuleCache`, which is sub-1 % per fail-summary
entry 009. Even a perfect overlap reclaims at most that ≪1 ms, which
falls below the objective's Medium severity floor (3–10 %) and likely
inside benchmark noise. To reach Medium, `addLiveBatch` would need to
overlap across a much larger barrier (e.g. into the next ledger's
classic phase), but the current pipeline structure makes
`mLiveBucketList` updates a hard prerequisite for `snapshotLedger` and
the fresh `CompleteConstLedgerState` consumed by the next ledger's
parallel apply preload.

### Lesson Learned

Out-of-order async launches around `addLiveBatch` only pay off when
there is genuine parallel work available before the next bucket-list
reader. Inside `finalizeLedgerTxnChanges`/`sealLedgerTxn...` the
bucket-list barrier (`snapshotLedger`,
`advanceApplySnapshotAndMakeLedgerState`) follows almost immediately,
so any async restructuring must extend the reordering across that
boundary (e.g. into `advanceLedgerStateAndPublish`) to unlock more
than ~1 ms of overlap. Localized async-launch reordering inside
`finalizeLedgerTxnChanges` cannot meet the Medium threshold.
