# H001: Make `addLiveBatch` async to overlap bucket-list write with `sealLedgerTxn`'s post-finalize work

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / bucket
**Severity**: Low (sub-Medium)
**Impact**: Apply-time reduction via increased intra-`closeLedger` parallelism
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Inside `LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3217-3367`), three independent writes
happen during the seal phase: `addHotArchiveBatch` (async),
`updateInMemorySorobanState` (async), and `addLiveBatch` (sequential, ~7.9
ms per ledger in the soroswap trace). Since the post-finalize work in
`sealLedgerTxnAndStoreInBucketsAndDB` (`snapshotLedger`,
`storePersistentStateAndLedgerHeaderInDB`,
`advanceApplySnapshotAndMakeLedgerState`) does not depend on
`addLiveBatch`'s completion until the next ledger close, we would expect
`addLiveBatch` to also be launched as a `std::async` so the main thread
can run the post-finalize work in parallel and only join the future at
the end.

## Mechanism

`addLiveBatch` is the longest-pole sequential write in the seal phase
(~7.9 ms). The two existing async tasks (`addHotArchiveBatch`,
`updateInMemorySorobanState`) finish in <1 ms each, so the seal phase is
gated on `addLiveBatch`. After it completes, the main thread continues
into `sealLedgerTxnAndStoreInBucketsAndDB`'s post-finalize block which
does ~2–5 ms of additional work (DB writes for header, snapshot logic,
state advancement). Making `addLiveBatch` async would let those ~2–5 ms
overlap with the bucket-list write, shaving up to ~5 ms per ledger.

## Trigger

Run the soroswap apply-load benchmark and compare seal-phase Tracy
zones with and without the change.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3357` —
  `mApp.getBucketManager().addLiveBatch(...)` is the sequential call
  that would become `std::async`.
- `src/ledger/LedgerManagerImpl.cpp:3358-3366` — current `.get()` waits
  on the two existing futures; would add a third wait.
- `src/ledger/LedgerManagerImpl.cpp:3408-3429` —
  `sealLedgerTxnAndStoreInBucketsAndDB`'s post-`finalizeLedgerTxnChanges`
  block does the work that would overlap with the async `addLiveBatch`.

## Evidence

- Tracy: `addLiveBatch` runs ~7.9 ms / ledger sequentially, blocking the
  main thread; `addHotArchiveBatch` and `updateInMemorySorobanState`
  futures complete well before `addLiveBatch` does, so the join point
  is dominated by `addLiveBatch`.
- The post-finalize work (`snapshotLedger`,
  `storePersistentStateAndLedgerHeaderInDB`,
  `advanceApplySnapshotAndMakeLedgerState`) doesn't read from
  `mLiveBucketList` immediately, so an in-flight `addLiveBatch` is safe
  to overlap.
- The infrastructure (`std::async(std::launch::async, ...)`) is already
  in place for the other two seal-phase tasks; this is a tiny diff.

## Anti-Evidence

- The post-finalize work is bounded at ~2–5 ms; even if perfectly
  overlapped with `addLiveBatch`, the savings cap at ~5 ms / 620 ms
  ≈ **0.8 %** of soroswap apply time. That is below the objective's
  Medium threshold (3–10 %) and within or near the noise floor.
- `mLiveBucketList` mutation must complete before the *next* ledger
  begins reading it; the wait already happens at the end of
  `finalizeLedgerTxnChanges` so correctness is unchanged, but the
  upper bound on savings is tight.
- Adding a third async future is mechanically simple but increases
  surface area for ordering bugs (e.g. if a future post-finalize step
  is added that does need `mLiveBucketList`).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Best-case savings (~5 ms / ledger ≈ 0.8 %) sit well below the
objective's Medium severity threshold (3–10 %) and within benchmark
noise. The optimize-soroswap context explicitly excludes hypotheses
projected to deliver less than the Medium threshold; per-objective
guidance, only Medium and High hypotheses get promoted to review.

### Lesson Learned

When evaluating "make-it-async" hypotheses, the savings ceiling is
the duration of the work that can run in parallel — not the duration
of the task being made async. If the post-task work is small, the
ceiling is small even when the task itself is large. Always estimate
the *overlap window*, not just the task length.
