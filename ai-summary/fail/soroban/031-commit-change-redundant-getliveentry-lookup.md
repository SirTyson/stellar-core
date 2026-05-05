# H031: Eliminate Redundant `getLiveEntryOpt` in `commitChangeFromSuccessfulTx`

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-tx parallel-apply commit phase microcost
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When committing the modified-entry map of a successful tx into the
thread-local parallel apply state, the commit loop should look up each
key in the thread state at most once. The `getLiveEntryOpt(key)` call
inside `commitChangeFromSuccessfulTx` (which retrieves the prior value
purely to compute the `isNew` flag and to gate the RO-TTL accumulation
branch) duplicates a lookup that the just-finished tx already performed
when it issued its writes through `TxParallelApplyLedgerState::upsertEntry`.
The expected design caches the prior `LedgerEntry` (or just the
`hadOldValue`/`isNewKey` flag) inside `ParallelTxSuccessVal::ModifiedEntryMap`
so that the commit step does not re-walk the lookup chain.

## Mechanism

In `src/transactions/ParallelApplyUtils.cpp:1164-1196`,
`commitChangeFromSuccessfulTx` calls
`ThreadParallelApplyLedgerState::getLiveEntryOpt(key)` for every modified
entry of every successful tx. That lookup walks the thread's
`mModifiedEntryMap`, then escalates to `GlobalParallelApplyLedgerState`,
then to `InMemorySorobanState` for Soroban keys. For most soroswap
keys this hits `mModifiedEntryMap` (warm) or `InMemorySorobanState`
(constant-time hash lookup).

The lookup is used only for:
1. The `roTTLSet.find(key) != roTTLSet.end()` branch (RO-TTL accumulation
   into `mRoTTLBumps`) — but this is gated on `newEntryOpt && oldEntryOpt`
   so the entry must already exist in some parent map.
2. The `isNew = !oldEntryOpt.has_value()` flag passed to `upsertEntry`/
   `eraseEntry`, used purely for thread-state bookkeeping (initial
   entry tracking).

Both could be derived from cheaper signals captured during apply.

## Trigger

Any successful Soroban tx with non-trivial modified-entry map.
Soroswap apply produces ~5 modifications per tx × 6776 txs / 70
ledgers = ~485 modified-entry commits per ledger.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1164-1196` —
  `commitChangeFromSuccessfulTx`: redundant `getLiveEntryOpt` and
  double `readInScope` per modification.
- `src/transactions/ParallelApplyUtils.cpp:1240-1252` —
  `commitChangesFromSuccessfulTx`: per-tx loop wrapper.
- `src/transactions/ParallelApplyUtils.cpp:1316-1332` —
  `TxParallelApplyLedgerState::upsertEntry`: where the prior lookup
  was already implicitly available during tx apply.

## Evidence

- `commitChangesFromThreads` was reported in summary line for fail
  hypothesis #002-parallel-commit-changes-from-threads as "<1% of
  applyLedger" — the related per-tx commit loop is structurally even
  smaller. No fail entry covers the per-modification `getLiveEntryOpt`
  redundancy specifically.
- The lookup walks at most 3 map layers (warm hash hits ~50–100 ns each).

## Anti-Evidence

- 485 commits/ledger × 100 ns lookup × 1.5 average map walks ≈ 73 µs per
  ledger of removable work, on a single thread.
- Aggregated across the 8 cluster threads it is still ≪ 1 ms / ledger.
- Against the 272.9 ms soroswap median: ~0.027% — orders of magnitude
  below the 1% Low floor, far below benchmark noise.
- Removing the lookup altogether requires plumbing a `prevEntry` cache
  through `ParallelTxSuccessVal::ModifiedEntryMap`, increasing per-entry
  memory footprint and adding complexity.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — `commitChangeFromSuccessfulTx` per-modification
`getLiveEntryOpt` redundancy is not in any prior fail entry; previously
explored commit-phase angles (`002-parallel-commit-changes-from-threads`,
`002-precompute-cluster-modulecache-snapshot`) targeted the wrapper
zone or the cluster-init phase, not the per-modification lookup.

### Why It Failed

The per-tx commit phase is structurally too small to clear the Low
(1%) threshold even in aggregate across the 8 cluster threads. With
~485 commits per ledger and ~100 ns of removable lookup work per
commit, the absolute saving is well under 0.1 ms per ledger — far
below the 1% (~2.7 ms) Low floor and entirely within benchmark
noise. This matches the lesson from fail
`002-parallel-commit-changes-from-threads`: "if total is <1% of
applyLedger, no concurrency model can reach the Medium floor",
extended here to "no per-entry micro-optimization can either".

### Lesson Learned

For per-modified-entry commit-phase optimizations in the parallel
apply pipeline, first compute `(N_modifications_per_ledger × removable_cost_ns)`
and compare to the Medium floor (≈ 8 ms / ledger) BEFORE proposing.
The commit phase processes ~500 entries per ledger, which means each
entry would need to save ~16 µs of work to clear Medium — an unrealistic
number for what is essentially a hash lookup + flag derivation.
Future commit-phase hypotheses should target either (a) eliminating
work that is currently O(N²) per ledger, or (b) zones whose absolute
self-time exceeds 8 ms.
