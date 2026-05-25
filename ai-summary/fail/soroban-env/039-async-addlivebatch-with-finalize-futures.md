# H039: Parallelize `addLiveBatch` with `addHotArchiveBatch` / `updateInMemorySorobanState` Futures

**Date**: 2026-05-25
**Subsystem**: ledger / bucket (apply-path finalize phase)
**Severity**: Low
**Impact**: Apply-time reduction (synchronous bucket batch insertion overlapped with already-async finalize work)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::finalizeLedgerTxnChanges` should overlap all three
independent batch-write operations:
- `addLiveBatch` (writes `mLiveBucketList`)
- `addHotArchiveBatch` (writes `mHotArchiveBucketList`)
- `inMemoryState.updateState` (writes `mInMemorySorobanState`)

The in-source comment at `LedgerManagerImpl.cpp:3334-3339` explicitly states
all three modify independent data structures and "can run in parallel".

## Mechanism

In the current code (`LedgerManagerImpl.cpp:3285-3357`), `addLiveBatch` is
called **synchronously** on the apply thread between the two async
`std::async` launches. Only `addHotArchiveBatch` and `updateState` run
in parallel; `addLiveBatch` blocks the apply path despite the comment
asserting it could be parallel. Moving `addLiveBatch` into its own
`std::async` future and joining all three at the end would overlap its
synchronous wall-clock cost with the others.

## Trigger

Soroswap apply-load benchmark: `finalizeLedgerTxnChanges` runs once per
ledger close; `addLiveBatch` is sync per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3367` (`finalizeLedgerTxnChanges`):
  `addLiveBatch` call at line 3356 is sync while the surrounding pattern
  uses `std::async` for parallel batch writes.
- `src/bucket/BucketManager.cpp:1031` (`addLiveBatch`): does
  `addBatch` → `addBatchInternal` → `freshInMemoryOnly` →
  `mergeInMemory` (sort + put loop + index build) per affected level.

## Evidence

Tracy soroswap trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`:
- `addLiveBatch` total = 303.8 ms / 72 calls = **4.22 ms/ledger wall**
- `addHotArchiveBatch (async)` total = 38.2 ms / 71 calls = 0.54 ms/ledger
- `updateInMemorySorobanState (async)` total = 2.6 ms / 72 calls = 0.04 ms/ledger
- `applyLedger` total = 4437.3 ms / 71 = 62.5 ms/ledger (sum of measured
  zones); soroswap apply-time baseline median is 207.6 ms/ledger.

## Anti-Evidence

The other two batch operations (0.54 + 0.04 ms/ledger combined) are
much smaller than `addLiveBatch` (4.22 ms/ledger). Moving `addLiveBatch`
to async only saves the overlap-able portion: `min(addLiveBatch_time,
max(other_async_times)) ≈ 0.54 ms/ledger`. Net wall-time saving is
bounded by the longer of the existing async branches.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (no fail/reviewed/poc/hypothesis
entry for parallelizing `addLiveBatch` against the existing finalize
futures).

### Why It Failed

The maximum theoretical wall-clock saving is bounded by the time of the
longest already-running async branch that could absorb part of
`addLiveBatch`. Since `addHotArchiveBatch` and `updateInMemorySorobanState`
together complete in ~0.58 ms/ledger but `addLiveBatch` takes ~4.22 ms,
parallelizing `addLiveBatch` can hide at most ~0.54 ms/ledger of its cost.

That is **0.54 ms / 207.6 ms ≈ 0.26%** of the soroswap apply-time
baseline — well below the 1% Low noise floor and three orders of
magnitude below the 3% Medium severity threshold this objective
requires.

Additionally, async dispatch of `addLiveBatch` would add synchronization
overhead (future creation, join) that further erodes the projected
saving, and would require careful auditing of any incidental state shared
between the bucket-list write and surrounding work (e.g., `mApplyState`
access patterns, lclSnapshot lifetime, BucketManager internal state).

### Lesson Learned

When an in-source comment claims three operations "can run in parallel"
but only two are currently async, quantify the wall-clock saving by
`min(serial_op_time, max(parallel_op_times))` — the cost of the
already-parallel branches is the ceiling on what the third can overlap.
For finalize-phase batch writes in soroswap, the live-bucket write
strictly dominates (≈7x larger than hot-archive + in-memory combined),
so making it async only hides a tiny fraction of its cost.
