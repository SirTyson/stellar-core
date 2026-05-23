# H017: applyTransaction / `apply` Zone Counts Dominated by Setup-Phase Ledgers (Sequential-Path Tracy Trap)

**Date**: 2026-05-23
**Subsystem**: transactions
**Severity**: Medium (initially projected)
**Impact**: classic-phase sequential apply per-tx overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a soroswap benchmark trace shows `applyTransaction`
(`ledger/LedgerManagerImpl.cpp:3046`) and `apply`
(`transactions/TransactionFrame.cpp:2703`) zones with hundreds of millions of
nanoseconds of total time inside `applyLedger`, those zones should reflect
in-benchmark work that an optimization could reduce. Specifically, if
`apply` totals 435 ms (~9.7% of `applyLedger`) and `applyTransaction` totals
616 ms (~13.8% of `applyLedger`) in the current soroswap trace
(`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`), a meaningful
per-tx fast path on the classic sequential apply loop should produce a
Medium-tier (3–10%) reduction in measured close time.

## Mechanism

`applySequentialPhase` (`src/ledger/LedgerManagerImpl.cpp:2949–3041`) wraps
each tx in `applyTransaction` and calls `tx->apply()`. Each call has fixed
overhead: `TransactionMetaBuilder` construction, `ltx.loadHeader()` per-tx,
`newFeeEvent` emission, `subSha256` (for Soroban), and `commonPreApply` plus
`applyOperations` machinery. At 23 µs mean per `apply` call and 32 µs mean
per `applyTransaction` call across 18 909 occurrences, a per-tx-overhead
optimization (pool-allocated `TransactionMetaBuilder`, hoist `loadHeader`,
cache subSeed, skip empty `newFeeEvent` paths) looks like it could clear
the Medium floor. The mechanism would specialize the sequential loop for
the common case of single-op classic payments (the soroswap workload's
`generateClassicPayments`).

## Trigger

Soroswap apply-load benchmark (`run_apply_load_matrix.py` with
`model_tx="soroswap"`, `TX=2000`, `T=8`) producing the diagnostic Tracy
trace identified in `ai-summary/CURRENT_STATE.md`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2949–3088` — `applySequentialPhase` loop
- `src/transactions/TransactionFrame.cpp:2696–2810` — `apply` entry
- `src/transactions/TransactionFrame.cpp` — `commonPreApply`, `applyOperations`

## Evidence

Trace zone totals (from `csvexport-release` on the current accepted-state
soroswap diagnostic Tracy trace):

| zone | total_ns | total_perc | counts | mean_ns |
|------|----------|-----------|--------|---------|
| `applyLedger` (`LedgerManagerImpl.cpp:1484`) | 4 475 605 676 | 43.51% | 71 | 63 036 699 |
| `applyTransaction` (`LedgerManagerImpl.cpp:3046`) | 616 473 936 | 5.99% | 18 909 | 32 602 |
| `apply` (`TransactionFrame.cpp:2703`) | 435 462 878 | 4.23% | 18 909 | 23 029 |

Within `applyLedger` (4 475 ms), `applyTransaction` aggregates to 616 ms
(13.8%) and `apply` to 435 ms (9.7%) — superficially well above the 3 %
Medium floor.

## Anti-Evidence

The apply-load config used for these runs (`docs/apply-load-benchmark-sac.cfg`
with `APPLY_LOAD_CLASSIC_TXS_PER_LEDGER` not overridden by
`scripts/run_apply_load_matrix.py`) leaves
`APPLY_LOAD_CLASSIC_TXS_PER_LEDGER = 0` (the default in `src/main/Config.h`).
With zero classic txs per ledger in the *benchmark* phase, the
`applySequentialPhase` loop body cannot run 266 times per ledger
(18 909 / 71) during the measured window.

The 18 909 calls come from the **setup phase** of the soroswap workload
(`ApplyLoad::setup()` → `setupSoroswapContracts()`, account creation,
trustline setup, classic payment seeding). Setup happens in many ledgers
before the benchmark begins timing the `closeLedger` window, but Tracy
captures the entire process. `applyLedger` count of 71 already reflects
only the timed window (out of 200 configured `APPLY_LOAD_NUM_LEDGERS`),
but `applyTransaction` and `apply` zones are aggregated across the whole
trace — including setup ledgers where `applyTransaction` runs heavily.

This is structurally identical to Meta-Pattern 7 (Validation Zone Tracy
Trap) but for the sequential apply path rather than validation: a large
total-time zone outside the benchmark window misleads the per-percentage
calculation against `applyLedger`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — sequential-apply variant of the Tracy-Trap pattern not
previously documented; existing Meta-Pattern 7 covers only validation zones.

### Why It Failed

The 13.8% / 9.7% apply-zone share is computed against `applyLedger` count
of 71 (benchmark-window only) but aggregates apply-zone events from setup
ledgers outside the measured window. `APPLY_LOAD_CLASSIC_TXS_PER_LEDGER`
defaults to 0 and is not overridden in `scripts/run_apply_load_matrix.py`,
so the soroswap timed window has no classic phase content for the
sequential apply loop to optimize. The within-window contribution is
near-zero and cannot move the benchmark.

### Lesson Learned

For zones in `applySequentialPhase` / `applyTransaction` / classic
`TransactionFrame::apply`, future agents must timestamp-filter against
`applyLedger` windows before projecting impact. Tracy's `counts` column
will reveal mismatches: when `applyTransaction.counts / applyLedger.counts`
is much larger than `APPLY_LOAD_CLASSIC_TXS_PER_LEDGER` configured for
the benchmark, the bulk of the events are from setup-phase ledgers and
should be excluded. This extends Meta-Pattern 7 (currently scoped to
validation zones) to the entire pre-soroban sequential apply path.
