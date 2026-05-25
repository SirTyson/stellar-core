# H030: Parallelize collectModifiedClassicEntries and fetchSorobanReadOnlyEntries Pre-Apply Loops

**Date**: 2026-05-25
**Subsystem**: transactions (serial pre-apply phase inside GlobalParallelApplyLedgerState constructor)
**Severity**: Low
**Impact**: soroswap apply-time reduction (below objective floor)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`
(V_26+ path at `transactions/ParallelApplyUtils.cpp:432-468`) runs three
serial sub-phases on the apply thread:

1. `readOnlyPreParallelApply(app, txBundles)` — already parallelized
   across `LEDGER_CLOSE_WORKER_THREADS` workers (line 526-583).
2. `commitBufferedPreParallelApplyWrites(app, ltx, txBundles)` — serial
   per-tx `preParallelApplyWrite` calls (line 586-598).
3. `collectModifiedClassicEntries(ltx, stages)` (line 601-719) —
   walks every stage's every tx's footprint readWrite + readOnly to
   collect classic keys, then iterates the deduplicated classic keys
   doing per-key `ltx.getNewestVersionBelowRoot(lk)` and
   `scopeAdoptEntryOpt`, followed by the
   `"fetchSorobanReadOnlyEntries from footprints"` zone which iterates
   every footprint readOnly key, does per-key
   `InMemorySorobanState::get(lk)` (SHA-256 inside) or
   `mLCLSnapshot.loadLiveEntry(lk)`, plus the same for the TTL key.

Expected behavior: per-key entry fetches across disjoint keys could in
principle be parallelized across the same `LEDGER_CLOSE_WORKER_THREADS`
worker pool that `readOnlyPreParallelApply` already uses.

## Mechanism

Both inner loops are read-only against `InMemorySorobanState`,
`mLCLSnapshot`, and the LedgerTxn root's `EntryCache`; results are
written into `mGlobalEntryMap` (single producer if work is chunked by
key with results merged at the end). A parallel variant would compute
the deduplicated key set serially, partition the keys across workers,
have each worker produce a local `(LedgerKey,
GlobalParallelApplyEntry)` vector, then merge into `mGlobalEntryMap`
on the apply thread. Reducing the serial fetch time would shrink the
apply-path window between `applySorobanStages` start and
`applySorobanStageClustersInParallel` start.

## Trigger

Run the soroswap apply-load benchmark on the current baseline.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:601-719` —
  `collectModifiedClassicEntries` and its embedded
  `"fetchSorobanReadOnlyEntries from footprints"` zone.
- `src/transactions/ParallelApplyUtils.cpp:432-468` — the V_26+
  pre-apply orchestration loop.

## Evidence

- `collectModifiedClassicEntries` Tracy zone total =
  21.25 ms (0.21% of `applyLedger`).
- `fetchSorobanReadOnlyEntries from footprints` Tracy zone total =
  8.39 ms (0.08% of `applyLedger`).
- Both run serially on the apply thread and access shared read-only
  state.

## Anti-Evidence

- The combined zone total is 29.64 ms = 0.30% of `applyLedger`. Even
  perfect parallelization at T=8 with zero overhead would save at
  most 25.9 ms ≈ 0.26% of `applyLedger`.
- The LedgerTxn root's `EntryCache` is not thread-safe; per the
  meta-pattern (fail `021-overlap-prefetchTransactionData-with-processFeesSeqNums`),
  `LedgerTxnRoot::mEntryCache` is a concurrency blocker for any
  apply-time parallel fetch against the root LedgerTxn (the call
  `ltx.getNewestVersionBelowRoot(lk)` traverses up to the root and
  can touch `mEntryCache`).
- The merge step to combine per-worker maps into `mGlobalEntryMap`
  must run serially and would consume part of the saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (prior parallel-apply
pre-phase fails (`002-parallel-process-fees-disjoint-sources`,
`003-precompute-modified-classic-keys-hashset`,
`015-move-preparallel-readonly-into-cluster-workers`,
`021-overlap-prefetchTransactionData-with-processFeesSeqNums`)
targeted fee parallelism, hashset precomputation, RO-phase relocation,
and prefetch overlap — none targeted parallelizing the in-constructor
serial classic+Soroban-RO entry fetch loops directly).

### Why It Failed

The total addressable zone surface is 29.64 ms / 4,437 ms = 0.67% of
`applyLedger` (combining `collectModifiedClassicEntries` at 0.48%,
already including the embedded fetchSorobanReadOnlyEntries sub-zone
at 0.19%). This is below the objective's 1% noise floor and well
below the 3% Medium severity threshold. Even fully eliminating both
phases — which is impossible because the per-worker merge into
`mGlobalEntryMap` is serial — could not produce a measurable
improvement against the soroswap baseline. Additionally,
`ltx.getNewestVersionBelowRoot` walks up to the LedgerTxn root and
touches the non-thread-safe `mEntryCache`, which is a documented
correctness blocker for parallelizing apply-time entry fetches
against the root.

### Lesson Learned

The serial setup phase inside `GlobalParallelApplyLedgerState`'s
constructor (collectModifiedClassicEntries + fetchSorobanReadOnlyEntries)
is currently 0.67% of `applyLedger` for soroswap. Combined with the
already-confirmed Meta-Pattern 9 (`preParallelApply` phase is thin),
the entire pre-parallel-apply setup phase is bounded well below the
Medium floor. Any future hypothesis touching the in-constructor entry
fetch loops must either include a new measurement showing
substantially higher overlap (e.g., a different workload with much
larger Soroban footprints), or pair with a broader refactor that
removes other Meta-Pattern 9 / Meta-Pattern 15 sub-Medium phases
simultaneously. The non-thread-safe `LedgerTxnRoot::mEntryCache`
remains a correctness blocker for any direct apply-time parallel
fetch against the root LedgerTxn.
