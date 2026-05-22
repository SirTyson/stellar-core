# H062: Async-Defer `applyStages` Destruction Off the Apply Thread

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (sub-threshold)
**Impact**: Apply-time critical-path reduction by moving the serial destruction
of ~2000 `TxBundle`/`TxEffects`/`TransactionMetaBuilder`/`OperationMetaBuilder`
objects off the apply thread.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `processPostTxSetApply` has moved out every transaction's finalized meta
XDR (via `processResultAndMeta → setTxProcessingMetaAndResultPair`), the only
remaining content in each `TxBundle` is empty / drained containers. Destruction
of the `std::vector<ApplyStage>` at
`src/ledger/LedgerManagerImpl.cpp:2956` (`applyStages.clear()`) should
contribute negligibly to `applyLedger` critical-path time. If destruction did
have material cost, it could be moved off-thread by `std::async`-shipping the
container to a background worker (the apply thread does not depend on
destruction completing before returning from `applyLedger`).

## Mechanism

`applyStages.clear()` runs serially on the apply thread after
`processPostTxSetApply`. Each `TxBundle` owns a `unique_ptr<TxEffects>`, and
each `TxEffects` contains:

- a `TransactionMetaBuilder` (which itself owns `xvector` of
  `OperationMetaBuilder`, `TxEventManager`, `DiagnosticEventManager`, and the
  finalized `TransactionMeta` XDR variant);
- a `LedgerTxnDelta` (`unordered_map<LedgerKey, EntryDelta>`);
- a `ParallelPreApplyInfo`.

For 2000 soroswap txs/ledger, this is 2000 `unique_ptr` `delete` invocations
plus the nested destructors. If each per-tx destruction cost ~3–5 µs (heap
free of multiple small vectors + map nodes), the serial total would be
6–10 ms/ledger (~2.6–4%), which is borderline Medium. Deferring to a
background thread would remove that critical-path slice.

## Trigger

Run the soroswap apply-load benchmark; the post-apply destruction loop runs
once per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2956` — `applyStages.clear()`
- `src/transactions/ParallelApplyStage.h:65-69` — `TxEffects` members
- `src/transactions/ParallelApplyStage.h:108-114` — `TxBundle::mEffects`
  unique_ptr
- `src/transactions/TransactionMeta.cpp:924-974` — `TransactionMetaBuilder`
  members and per-op `OperationMetaBuilder` allocation

## Evidence

- 2000 per-tx heap-allocated `TxEffects` objects need destruction at the end of
  every soroswap ledger.
- `TransactionMetaBuilder` retains its `mOperationMetaBuilders` vector and the
  `mTxEventManager`/`mDiagnosticEventManager` event buffers after meta has been
  moved out.

## Anti-Evidence

- For the soroswap benchmark, invariants are disabled, so
  `checkAllTxBundleInvariants` does NOT call `txBundle.getEffects().setDeltaEntry`
  via the invariant-only `setDeltaHeader` path; the parallel-apply commit code
  only populates `TxEffects::mDelta` inside the invariant-enabled branch
  (see `ParallelApplyUtils.cpp` `setEffectsDeltaFromSuccessfulTx`). Therefore
  `mDelta` is empty for the measured benchmark.
- `TransactionMetaBuilder::finalize` moves out the XDR meta; the residual
  state is small (vector of empty `OperationMetaBuilder` shells, event
  managers whose `mEvents` xvectors are typically empty when meta is
  disabled).
- H024 (`async-thread-state-destruction-between-stages`) measured per-stage
  thread-state destruction at sub-microsecond when the underlying maps were
  drained — the same lesson applies here.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — H024 covered the analogous deferral for
`ThreadParallelApplyLedgerState`, but no prior record investigated `applyStages`
destruction specifically.

### Why It Failed

In the actual soroswap benchmark configuration (invariants disabled, meta
disabled or already moved out), the residual state in each `TxBundle` is
sub-microsecond to destroy. The serial destruction loop is dominated by
freeing already-empty containers and the `unique_ptr<TxEffects>` heap free
itself (~50 ns/free × 2000 = 100 µs). Aggregated with the small per-op
meta-builder destructor, realistic total is well below 1 ms/ledger — far
below both the 3% Medium floor (~7 ms) and the 1% noise floor (~2.3 ms).
Deferral would not measurably shorten the apply critical path.

### Lesson Learned

Apply-path destruction phases consisting primarily of `unique_ptr`+nested
container teardown are bounded at sub-millisecond per ledger when the
upstream phases have already drained the heavy data. Before proposing
async deferral of any destruction, confirm that the destructors actually
free non-trivial allocations on the benchmark configuration (invariants,
meta enabled/disabled, etc.). The H024 precedent — "verify the actual
container fill level after the commit handshake before proposing async
destruction" — applies equally to `applyStages` cleanup.
