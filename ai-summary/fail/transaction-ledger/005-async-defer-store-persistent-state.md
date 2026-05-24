# H005: Async-defer storePersistentStateAndLedgerHeaderInDB off the apply critical path

**Date**: 2026-05-24
**Subsystem**: transaction-ledger (ledger/main boundary)
**Severity**: Low
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`storePersistentStateAndLedgerHeaderInDB` (LedgerManagerImpl.cpp:3166)
persists the most recent `HistoryArchiveState` (HAS) and encoded ledger
header into the SQL persistent-state store at the end of each
`closeLedger`. This is a checkpoint write that allows the node to
re-attach to the live BucketList after a restart. While the write must
complete *eventually* (and must precede the next persistence commit), it
does not need to block the calling apply thread before that thread can
return its applied result — the runtime could move the writes to a
dedicated background queue and gate the next ledger's call on the queue
having drained.

## Mechanism

If the SQL write of HAS/header were a non-trivial slice of apply time,
hoisting it onto a background queue would shorten the synchronous tail
of `closeLedger` by exactly the moved DB-write time, minus a small
hand-off cost. The asymmetry between the synchronous wait and an
async-queue overhead is what would make it viable.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap scenario (TX=2000, T=8);
measure `storePersistentStateAndLedgerHeaderInDB` self-time per ledger
and compare to apply-time critical path.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3166-3213` — `storePersistentStateAndLedgerHeaderInDB`
- `src/ledger/LedgerManagerImpl.cpp:3411-3419` — call site in `advanceApplySnapshotAndMakeLedgerState`
- `src/main/PersistentState.cpp:172` — `setMainState` (SQL write)
- `src/history/HistoryArchive.cpp:139` — `HistoryArchiveState::toString` (HAS serialization)

## Evidence

The function performs a SQL `setMainState` write (twice per ledger), a
ledger-header encoding, and an HAS serialization — all synchronous on
the apply thread. Naively this looks like a candidate for async deferral.

## Anti-Evidence

Direct Tracy measurement on the accepted soroswap diagnostic trace
(`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`)
shows:

| Zone | Total | Per-ledger (72 ledgers) | % of 218 ms baseline |
|------|-------|-------------------------|----------------------|
| `storePersistentStateAndLedgerHeaderInDB` | 1.92 ms | 27 µs | 0.012% |
| `toString` (HAS serialization) | 4.96 ms | 69 µs | 0.032% |
| `setMainState` (×2/ledger) | 43 ms (145 calls) | ~594 µs | 0.273% |

The aggregate per-ledger synchronous cost (~700 µs ≈ 0.32%) is well
below the 3% Medium floor and even below the 1% Low floor. Async
deferral would add at minimum a `std::async`-equivalent launch+join
cost (~5–15 µs) plus next-ledger drain-wait, eating most of the saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (no fail/hypothesis/reviewed/poc
entry for `storePersistentStateAndLedgerHeaderInDB` deferral or for
`setMainState` apply-path optimization).

### Why It Failed

The synchronous SQL persistence at end-of-apply is structurally tiny
(~700 µs/ledger; 0.32% of soroswap apply time). Even if it were 100%
deferable with zero handoff cost, the saving would be sub-Low. With
realistic async overhead (10–20 µs/ledger) the net benefit shrinks
further. This is a real, novel observation — the LCL persistence call
has not been individually traced before — but the empirical zone size
puts it firmly below the objective's Medium severity threshold.

### Lesson Learned

End-of-apply persistence writes for HAS and ledger header are
sub-millisecond per ledger on the benchmark machine. Per-ledger SQL
`setMainState` is the dominant slice (~600 µs combined for HAS +
header), but even fully eliminated it cannot clear the 1% Low floor.
Future investigations of synchronous DB writes on the apply critical
path must pre-measure the zone before proposing async deferral; in this
codebase, only multi-ms synchronous SQL writes are candidates, and the
LCL persistence is not one of them.
