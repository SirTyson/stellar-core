# H079: Parallelize `collectModifiedClassicEntries` across stages/clusters

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Low
**Impact**: apply-thread serial classic-key collection in `GlobalParallelApplyLedgerState` construction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState::collectModifiedClassicEntries`
(`src/transactions/ParallelApplyUtils.cpp:600-644`) iterates every stage ×
cluster × tx footprint key (both `readWrite` and `readOnly`) on the apply
thread, filters non-Soroban keys, and for each calls
`ltx.getNewestVersionBelowRoot(lk)` then inserts an entry into
`mGlobalEntryMap`. With Soroban-only ledgers the only classic footprint
keys are typically the fee-source `ACCOUNT` and `TRUSTLINE` keys per tx
(soroswap has 2 RW trustlines plus the implicit source account). For 28
txs/ledger the inner loop performs roughly 80–90 classic key lookups
serially on the apply thread per ledger. The expected correct behavior is
to pre-populate `mGlobalEntryMap` with the same set of `(key,
GlobalParallelApplyEntry{entry, false})` pairs for every classic key
referenced by any Soroban tx footprint, with the same canonical entry
identity as the sequential implementation produces.

## Mechanism

The actual sequential implementation produces a unique set of classic
keys, then for each key performs a single LedgerTxn lookup. The hypothesis
is that this can be sharded across `NUM_CLUSTERS` worker threads via the
same `std::async` pattern used in `readOnlyPreParallelApply`
(`src/transactions/ParallelApplyUtils.cpp:525-583`), with each shard
producing a partial `(key, entry)` map that is merged into
`mGlobalEntryMap` in canonical order on the apply thread. Sharded
execution would reduce the serial apply-thread cost to roughly
1/`NUM_CLUSTERS` of the current cost.

## Trigger

Every Soroban ledger that runs `applySorobanStages` triggers
`collectModifiedClassicEntries` exactly once during
`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`.
The soroswap apply-load benchmark exercises this on every ledger that
contains a parallel Soroban phase.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:600-644` — the serial
  `collectModifiedClassicEntries` body.
- `src/transactions/ParallelApplyUtils.cpp:525-583` — the existing
  `readOnlyPreParallelApply` std::async sharding pattern that would be
  copied.

## Evidence

- The function is on the apply-thread critical path between cluster
  pre-apply and the actual parallel cluster worker dispatch — any
  serial work here delays the parallel phase from starting.
- `getNewestVersionBelowRoot` on a `LedgerTxn` chain can touch the
  parent LedgerTxnRoot's entry cache; with 80–90 lookups per ledger the
  aggregate cost is non-trivial even if each call is cheap.
- The sharding pattern is already proven safe in this file
  (`readOnlyPreParallelApply`) so the engineering cost is low.

## Anti-Evidence

- Tracy zone measurement on the soroswap baseline:
  `collectModifiedClassicEntries` total self-time = 21.27 ms across 71
  ledgers (`0.207%` of full applyLedger time), i.e. ~0.30 ms/ledger.
- Idealized 8-way parallelism caps savings at
  `0.30 ms × (T-1)/T = 0.30 × 7/8 ≈ 0.26 ms/ledger`, i.e. roughly
  **0.13%** of the soroswap apply-time baseline (207 ms median).
- Realistic `std::async` launch overhead per `applySorobanStageClustersInParallel`
  cluster shard is on the order of tens of microseconds; for a phase of
  size ~0.30 ms the launch+join overhead is comparable to or larger than
  the saved serial work.
- Sharded inserts into `mGlobalEntryMap` require a final serial merge in
  canonical key order to preserve deterministic entry identity across
  nodes (see Meta-Pattern 23 about `commitChangesFromThreads` ordering).
  The merge step recovers most of the per-stage saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not duplicate of any existing fail/hypothesis/reviewed/poc
file in `ai-summary/{fail,hypothesis,reviewed,poc}/transaction-ledger/`.
Prior failures (`003-bulk-preload-ro-classic-footprint-at-thread-setup`,
`H009-cross-phase-source-account-load-cache`) targeted different code paths
(thread-state setup and cross-phase caching respectively); none targets the
sharding of `collectModifiedClassicEntries` specifically.

### Why It Failed

Below objective severity threshold. Even with idealized 8-way sharding,
the maximum recoverable critical-path saving is ~0.26 ms/ledger
(~0.13% of the 207 ms soroswap median), far below the 1% Low noise
floor and the 3% Medium acceptance floor. Realistic savings are
materially smaller after accounting for `std::async` fan-out overhead
and the mandatory serial merge required to keep `mGlobalEntryMap`
entry identity canonical across nodes.

### Lesson Learned

`collectModifiedClassicEntries` is in the same sub-millisecond bucket
as the other already-rejected per-tx serial setup phases
(`processFeesSeqNums`, `preParallelApplyWrite`,
`commitBufferedPreParallelApplyWrites`,
`fetchSorobanReadOnlyEntries from footprints`). Each of these phases
sits at ~0.1–0.5 ms/ledger and individually cannot reach Medium even
under idealized sharding. Future serial-phase parallelization
hypotheses must measure the absolute zone size against the 3% Medium
floor *before* designing a sharding scheme.
