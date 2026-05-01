# H021: Run `addLiveBatch` as a third async future alongside `addHotArchiveBatch` and `updateInMemorySorobanState`

**Date**: 2026-05-01
**Subsystem**: soroban (finalizeLedgerTxnChanges / bucket)
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges` (LedgerManagerImpl.cpp:3217) already pipelines two
of the three independent post-apply writes — `addHotArchiveBatch` and
`updateInMemorySorobanState` — as `std::async` tasks joined at the end of the
function. The third independent write, `addLiveBatch` (line 3356), is still
performed synchronously on the apply thread before the futures are joined.
Since `addLiveBatch` only mutates `mLiveBucketList` (independent of
`mHotArchiveBucketList` and `mInMemorySorobanState`), the same async pattern
should apply, and finalize wall time should drop to roughly
`max(addLiveBatch, addHotArchiveBatch, updateInMemorySorobanState)` instead
of `addLiveBatch + max(addHotArchive, updateState)`.

## Mechanism

Promote `addLiveBatch` to a third `std::async` future scheduled before the
main thread's `getAllEntries` work; join all three futures at the end of
`finalizeLedgerTxnChanges`. All three targets are independent in-memory
structures, so deterministic ordering is preserved (sealLedger barriers
still block on completion).

## Trigger

Any soroswap apply ledger; measure wall time of `finalizeLedgerTxnChanges`
before/after.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges`,
  specifically the synchronous `addLiveBatch` call at line 3356.
- `src/bucket/BucketManager.cpp:1026-1100` — `BucketManager::addLiveBatch`
  body that would be executed on the async thread.

## Evidence

Trace data (soroswap, current baseline):
- `finalizeLedgerTxnChanges` total = 315ms (6.2% of `applyLedger`).
- `addBatchInternal` for the live bucket list = 208ms / 71 ledgers = 2.9ms
  per ledger.
- `addHotArchiveBatch (async)` = 38ms (already overlapped).
- `updateInMemorySorobanState (async)` = 2.5ms (already overlapped).

The async pattern is already proven to work for the other two writes.

## Anti-Evidence

The maximum wall-clock saving is `min(addLiveBatch, addHotArchiveBatch)`
≈ `min(208ms, 38ms)` = 38ms across 71 ledgers = 0.54ms/ledger. As a fraction
of `applyLedger`, this is `38ms / 5092ms` = **0.75%** — below the
benchmark-noise threshold (1%) and well below the objective's Medium
floor (3%). The `updateInMemorySorobanState` task is so cheap (2.5ms) that
even perfect overlap with it yields no measurable additional gain.

The remaining unaccounted ~106ms in finalize (315 − 208 − 16 − 8 − 2 − async
overheads) is not in `addLiveBatch` and would not be addressed by this
change. Three failed predecessor hypotheses already attempted overlap of
`addLiveBatch` with various downstream work
(011-async-add-live-batch.md + 002-async-level0-bucket-file-write.md +
003-async-addLiveBatch.md) and reported neutral results, confirming that
the BucketList write is not a bottleneck once it's removed from a
serialized critical path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS — the specific framing (addLiveBatch as a *peer* of the
existing two async futures, joined together inside finalize) was not
explicitly attempted; prior fails overlapped with post-finalize work or
with the level-0 file write only.

### Why It Failed

The maximum achievable saving is bounded by the wall-clock of the
already-async `addHotArchiveBatch` (38ms across 70 ledgers = 0.74% of
applyLedger). This is below the objective's 1% noise floor and far below
the 3% Medium severity threshold required for hypothesis promotion.
Restructuring finalize for a sub-1% gain is not warranted.

### Lesson Learned

When pipelining work across async futures, the achievable speedup is
bounded by the second-largest task. For `finalizeLedgerTxnChanges`, the
two existing async tasks are both small (38ms and 2.5ms total), so adding
a third parallel task can save at most ~38ms across the entire trace.
Future work in this area should target the synchronous parts of the
unaccounted ~106ms — likely lurking in `LedgerTxn`-EntryMap iteration,
`addAnyContractsToModuleCache`, or post-`addLiveBatch` bookkeeping — rather
than re-arranging the async fan-out.
