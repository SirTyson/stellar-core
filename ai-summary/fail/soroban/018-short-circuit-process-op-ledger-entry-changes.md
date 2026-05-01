# H018: Short-Circuit `processOpLedgerEntryChanges` When Both Restore Maps Are Empty

**Date**: 2026-04-30
**Subsystem**: transactions / meta build
**Severity**: Low
**Impact**: Per-op `LedgerEntryChanges` deep copy + 4 set/unordered_set
allocations during meta build in worker threads
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When neither auto-restore was triggered nor the operation is a
`RESTORE_FOOTPRINT`, the meta-build path
(`processOpLedgerEntryChanges`,
`src/transactions/TransactionMeta.cpp:40`) should return the input
`LedgerEntryChanges` unchanged, with no per-op deep copy of the
xvector and no allocation of the 1 `std::set<LedgerKey>` +
2 `std::unordered_set<LedgerKey>` it builds for restore-tracking. For
the soroswap workload (no auto-restore and no `RESTORE_FOOTPRINT`),
this should be a thin wrapper that hands the xvector through by
const-ref or moved rvalue.

## Mechanism

`processOpLedgerEntryChanges` unconditionally executes
`auto changes = initialChanges;` (line 48) — a deep copy of the entire
`LedgerEntryChanges` xvector — on the first line. For
`INVOKE_HOST_FUNCTION` ops on protocol ≥ 23 (current),
`needToProcess == true`, so the function falls through to allocate
3 sets and run 3 loops over `changes`. For soroswap, `hotArchiveRestores`
and `liveRestores` are empty (no autorestore activity), so all 3 loops
are no-ops, but the deep copy and 3 set allocations still happen on
every successful soroban op. The caller (`setLedgerChangesFromSuccessfulOp`,
`:444`) then assigns the returned vector into
`meta.get().changes`, which triggers a move (good) but the
already-paid copy at line 48 is wasted.

## Trigger

Run the soroswap benchmark (no autorestore in the workload). Per ledger
~70 successful soroban ops × 1 redundant `LedgerEntryChanges` deep copy
+ 3 set allocs.

## Target Code

- `src/transactions/TransactionMeta.cpp:40-58` —
  `processOpLedgerEntryChanges` entry point and unconditional copy
- `src/transactions/TransactionMeta.cpp:65-75` — set declarations
- `src/transactions/TransactionMeta.cpp:444-451` — caller in
  `setLedgerChangesFromSuccessfulOp`

## Evidence

- Soroswap workload has no `RESTORE_FOOTPRINT` ops and the host does
  not autorestore (verified: no `hotArchive` or `liveBucketList`
  restores observed in apply-load traces for this workload).
- The `auto changes = initialChanges;` copy walks every
  `LedgerEntryChange` in the xvector and deep-copies the embedded
  `LedgerEntry` (which contains a multi-kB `ContractDataEntry` for
  CONTRACT_DATA modifications).
- Caller could move the locally-built `changes` vector into the
  function (it has no other use) and the function could return early
  by `std::move(initialChanges)` when both restore maps are empty.

## Anti-Evidence

Quantification:

- Per soroswap tx: ~5–10 modified entries → `LedgerEntryChanges`
  vector of ~5–10 entries × ~few-hundred-byte `LedgerEntry` deep copy.
- Per-op deep copy cost ≈ 5 µs.
- 5093 ops/run × 5 µs ≈ 25 ms total worker CPU/run ÷ 8 workers
  ≈ 3 ms wall/run ÷ 70 ledgers ≈ 0.04 ms/ledger ≈ **0.015 %** per
  ledger of apply time.
- Adding the 3 set allocations (~100 ns each) is negligible.
- Total wall-time impact is two orders of magnitude below the 3 %
  Medium threshold and well below benchmark noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — meta-build deep-copy path was not previously
investigated; restore-handling fast path is a real cleanup but with
sub-noise impact.

### Why It Failed

`LedgerEntryChanges` xvectors are small (~5–10 entries per op) and the
embedded `LedgerEntry` deep copy is bounded; the per-op cost is in the
single-µs range. Across the 70-ledger benchmark with 8-way parallelism,
the wall-clock saving is well under 0.1 % — three orders of magnitude
below the Medium severity floor. The diff is clean but the win is
sub-noise.

### Lesson Learned

Per-op micro-allocations and small xvector copies in the meta-build
path are not Medium-tier targets at the current soroswap baseline
(~278 ms/ledger): even removing all per-op micro-overhead in a single
zone would not exceed ~1 % savings unless that zone's total worker CPU
contribution exceeds ~80 ms/run (≈ 8 × 10 ms wall ÷ 8 workers). Future
hypotheses should screen candidates by total worker CPU contribution
before writing.
