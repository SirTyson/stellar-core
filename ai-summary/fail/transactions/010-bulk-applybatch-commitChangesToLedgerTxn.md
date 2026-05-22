# H010: Bulk-Apply Dirty Entries in commitChangesToLedgerTxn via a Single Batch Move into the Parent LedgerTxn

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: Per-entry serial create/update calls into LedgerTxn during final commit
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all Soroban apply stages have completed,
`GlobalParallelApplyLedgerState::commitChangesToLedgerTxn`
(`transactions/ParallelApplyUtils.cpp:721-801`) is the final serial
apply-thread step that flushes the global parallel-apply state into
the main `AbstractLedgerTxn`. The minimum work behavior is to move
each dirty entry into the parent ledger txn exactly once, with no
per-entry virtual dispatch overhead beyond what the parent ltx's
internal map insert requires. Ideally, an inner `LedgerTxn ltxInner`
constructed around the parent could accept a bulk
`importEntries(map&&)` API that moves the entire entry map into the
parent's `EntryMap` in one pass, instead of iterating and calling
`createWithoutLoading` / `updateWithoutLoading` per entry.

## Mechanism

Actual behavior: `commitChangesToLedgerTxn` constructs a nested
`LedgerTxn ltxInner(ltx)`, then loops over `mGlobalEntryMap` and
calls either `ltxInner.createWithoutLoading(std::move(ile))` or
`ltxInner.updateWithoutLoading(std::move(ile))` per dirty entry.
Each call walks the `AbstractLedgerTxn` virtual dispatch, constructs
an `InternalLedgerEntry`, and inserts/updates the inner ltx's
`EntryMap`. After the loop, `ltxInner.commit()` merges the inner
entry map into the parent ltx via its standard parent-merge path,
which itself does another per-entry walk to combine maps.

Deviation: every dirty entry pays two passes through hash-map
infrastructure (insert into `ltxInner`, then merge into parent ltx)
even though both maps are owned by the same thread and the merge is
guaranteed to be a no-conflict bulk insert. A bulk
`importEntries(map&&)` that moves nodes directly into the parent's
underlying `UnorderedMap` would skip the per-entry virtual dispatch.

## Trigger

Run the soroswap apply-load benchmark; every closed ledger ends
with a call to `commitChangesToLedgerTxn`. For soroswap each
ledger has on the order of 200–400 dirty entries (per-tx SAC
balance updates, TTL bumps, pool state writes).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:721-801` —
  `commitChangesToLedgerTxn` per-entry loop.
- `src/ledger/LedgerTxn.cpp` — `createWithoutLoading`,
  `updateWithoutLoading`, and parent-merge `commit()` paths
  invoked from the loop.
- `src/ledger/LedgerTxn.h` — would need a new
  `importEntries(EntryMap&&)` (or equivalent) bulk API on
  `AbstractLedgerTxn`.

## Evidence

- Tracy `commitChangesToLedgerTxn` zone
  (`transactions/ParallelApplyUtils.cpp:724`): self-time
  27,300,311 ns aggregate across 71 ledgers, mean 384 µs/ledger.
- The zone is serial apply-thread work that runs after the last
  parallel cluster completes and before `finalizeLedgerTxnChanges`
  begins, so any saving translates directly to apply-time win.
- A per-ledger budget of 384 µs scaled to applyLedger
  (~64 ms/ledger) is 0.60% of apply-time.

## Anti-Evidence

- The 27.3 ms aggregate / 0.60% of apply-time figure is far below
  both the 3% Medium floor and the 1% benchmark-noise floor.
- A bulk `importEntries` API still has to scan dirty entries,
  preserve `mIsNew`/`mIsDirty` semantics, and respect the
  inner-ltx parent-merge contract (especially restored-key
  tracking via `markRestoredFromHotArchive` /
  `markRestoredFromLiveBucketList`, which require entry-by-entry
  observation). The "removable" portion is strictly less than
  0.60%.
- Prior cross-subsystem fail
  `002-bulk-import-global-state-to-ledgertxn.md` already attacked
  the same loop from a transaction-ledger angle and concluded
  reaching Medium would require >80% elimination of
  `commitChangesToLedgerTxn` together with the related
  child-commit chain, which the dirty-entry import alone cannot
  achieve.
- Restoring the `markRestoredFromHotArchive` /
  `markRestoredFromLiveBucketList` semantics inside a bulk
  import would itself add per-restored-entry work; soroswap
  restores are rare but the bulk-import path cannot skip them.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior fail
`002-bulk-import-global-state-to-ledgertxn.md` (which targeted the
broader child-commit chain in the cross-subsystem bucket); this
hypothesis is narrower (only the per-entry create/update loop), but
the bounding evidence converges on the same NOT_VIABLE verdict.

### Why It Failed

`commitChangesToLedgerTxn` is a real serial apply-thread bottleneck
but its absolute budget is 384 µs/ledger ≈ 0.60% of apply-time. Even
a zero-cost bulk-import primitive cannot clear the 1% noise floor on
soroswap, let alone the 3% Medium floor. The restored-key handling
required for hot-archive and live-BucketList invariants is itself
per-entry and cannot be batched without re-engineering the
`LedgerTxn` parent-merge contract.

### Lesson Learned

Serial apply-thread post-parallel-apply zones must be sized against
the Medium floor before proposing API refactors. For
`commitChangesToLedgerTxn` specifically, the per-ledger budget is
already sub-1%; future hypotheses in this zone need either a much
larger soroswap dirty-entry count per ledger or a structural redesign
that also eliminates `finalizeLedgerTxnChanges` work, not a
single-zone API change.
