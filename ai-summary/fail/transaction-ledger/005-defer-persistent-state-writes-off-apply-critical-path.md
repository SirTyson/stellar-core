# H005: Defer Persistent State / HAS Writes in `storePersistentStateAndLedgerHeaderInDB` Off the Apply Critical Path

**Date**: 2026-05-04
**Subsystem**: transaction-ledger (apply seal / DB persistence)
**Severity**: Low
**Impact**: Sequential close-window DB write
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`storePersistentStateAndLedgerHeaderInDB` (`src/ledger/LedgerManagerImpl.cpp:3166`)
is called synchronously from `sealLedgerTxnAndStoreInBucketsAndDB` inside
`unsealHeader` and runs three SQL `setMainState` calls (HAS string + last-closed-
ledger header + checkpoint append) on the apply critical path. The HAS object
also has to be JSON-serialized (`HistoryArchiveState::toString`) before the SQL
write. Since the HAS and ledger-header writes are crash-safety checkpoints
that the next ledger does not depend on for in-memory state, both could be
deferred to a background task launched after `unsealHeader` returns, joined
on the next `applyLedger` entry, removing them from the synchronous apply
window.

## Mechanism

Both writes are pure outputs: nothing read in subsequent in-memory apply
work depends on them being in the SQL DB at the time `applyLedger` returns.
A background `std::async` task could perform both `setMainState` calls and
the `appendLedgerHeader` while the next ledger's prefetch / fee-processing
runs. Apply-time would shed the sequential portion currently spent in
`storePersistentStateAndLedgerHeaderInDB` plus its `toString` child.

## Trigger

Any apply-load run that exercises `applyLedger`'s closing tail.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3166-3213` — `storePersistentStateAndLedgerHeaderInDB`
- `src/ledger/LedgerManagerImpl.cpp:3411-3419` — call site inside the
  `unsealHeader` lambda
- `src/main/PersistentState.cpp:172` — `setMainState`
- `src/history/HistoryArchive.cpp:139` — `HistoryArchiveState::toString`

## Evidence

- Tracy diagnostic trace shows
  `storePersistentStateAndLedgerHeaderInDB` total = 10.3 ms across 72 calls
  (0.143 ms / ledger) and `setMainState` total = 3.9 ms across 145 calls
  (~27 µs / call). `HistoryArchiveState::toString` total = 4.8 ms across
  72 calls (~67 µs / call).
- These are all on the synchronous `unsealHeader` path; deferring them
  would directly shrink the `applyLedger` envelope.

## Anti-Evidence

- Total recoverable critical-path time is **~0.14 ms / ledger ≈ 0.05%**
  of the soroswap median apply time. Two orders of magnitude below the
  Medium 3% threshold and below the 1% benchmark noise floor.
- Crash-recovery semantics: the HAS and `kLastClosedLedgerHeader` SQL
  writes are part of the persistent commit boundary. Deferring them past
  the SQL `commit` of the apply transaction risks the in-memory LCL
  diverging from what survives a crash; this would require explicit
  flush coordination with `LedgerTxnRoot::commit`'s SQL transaction or
  reordering the DB transaction boundary.
- The current call stack already shares one outer SQL transaction
  spanning apply; introducing a background DB write requires careful
  session/transaction handling against `LedgerTxnRoot::mTransaction`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; prior bucket-write
deferral work (fail H003 hot-archive future, H001 async addLiveBatch,
H017 poststamp encoded bytes) targeted bucket persistence rather than
SQL persistent state.

### Why It Failed

Below objective severity threshold by two orders of magnitude. Best-case
saving ~0.05% of apply time vs. a 3% Medium floor. The crash-safety
ordering complications around the ambient SQL transaction are
disproportionate to a sub-noise win.

### Lesson Learned

The synchronous DB writes in `storePersistentStateAndLedgerHeaderInDB`
are individually fast (sub-30 µs each) because they all hit the same
`SessionWrapper` already inside the apply SQL transaction. The whole
sealing tail (header store + HAS string + persistent state) is below the
1% noise floor on the soroswap shape. Future deferral hypotheses on the
seal tail should bundle the entire `unsealHeader` lambda's work plus
adjacent finalize work in one structural change, not target individual
sub-ms steps.
