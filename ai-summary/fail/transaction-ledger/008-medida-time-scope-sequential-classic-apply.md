# H008: Gate sequential classic per-tx mTransactionApply.TimeScope() on DISABLE_SOROBAN_METRICS_FOR_TESTING

**Date**: 2026-04-28
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Per-tx medida histogram update overhead on classic apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `DISABLE_SOROBAN_METRICS_FOR_TESTING=true` is set (the soroswap
benchmark config), the per-tx medida histogram `mTransactionApply` should
NOT be updated for sequential classic transactions, mirroring the gate
that already exists for the parallel Soroban path
(LedgerManagerImpl.cpp:2493-2498). Each medida histogram `Update` acquires
an internal mutex and walks a sample reservoir; with ~568 classic
applyTransaction calls per ledger, this overhead recurs every benchmark
ledger.

## Mechanism

`LedgerManagerImpl.cpp:3049` opens
`mApplyState.getMetrics().mTransactionApply.TimeScope()` unconditionally
before each sequential classic tx. The parallel Soroban analog at
LedgerManagerImpl.cpp:2493-2498 wraps the equivalent call in
`if (!mApp.getConfig().DISABLE_SOROBAN_METRICS_FOR_TESTING)`. The
asymmetry is bug-like — both call sites measure tx-apply wall time using
the same metric — but one is gated and one isn't. Closing the gap would
remove one medida histogram update per classic tx per ledger.

## Trigger

Run soroswap apply-load with the benchmark config. Before/after the gate
should differ by ~6.6 ms/ledger (568 calls × ~11.7 µs medida histogram
update cost).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3049` — ungated `TimeScope()` on
  classic apply path.
- `src/ledger/LedgerManagerImpl.cpp:2493-2498` — analogous gated
  TimeScope() for Soroban parallel apply (the pattern to mirror).
- `src/main/Config.h` (search `DISABLE_SOROBAN_METRICS_FOR_TESTING`) —
  config flag definition.

## Evidence

- Per-ledger overhead estimate: 568 classic txs × ~11.7 µs medida histogram
  update ≈ 6.6 ms/ledger. Against 596 ms apply baseline this is ~1.1%.
- Trivially clean diff: wrap line 3049 in the same `if
  (!mApp.getConfig().DISABLE_SOROBAN_METRICS_FOR_TESTING)` guard.

## Anti-Evidence

- Below the 3% Medium threshold defined in the objective.
- Already covered by `fail/transaction-ledger/003-redundant-xdrsize-in-inmemoryindex-constructor.md`'s
  prior finding family (`disable-residual-medida-histograms`, rejected at
  ~1.2% / ~7.5 ms — within noise of this estimate). The fail summary
  records a meta-pattern that residual medida-histogram disables fall
  below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: FAIL — duplicates prior `disable-residual-medida-histograms`
investigation (recorded in fail summary as ~1.2% / 7.5 ms / sub-3%).

### Why It Failed

Estimated savings (~6.6 ms/ledger ≈ 1.1% of 596 ms p50 apply) fall below
the objective's Medium severity threshold (3–10%). The objective context
explicitly excludes Low (1–3%) findings at the hypothesis stage:
"Minimum severity: Medium … Low not accepted at hypothesis stage." Prior
investigation recorded in
`ai-summary/fail/transaction-ledger/summary.md` already concluded the
broader "disable residual medida histograms" angle is below threshold.

### Lesson Learned

When estimating apply-time wins, always compute against the headline
baseline (soroswap p50 ≈ 596 ms in `CURRENT_STATE.md`) not against the
mean Tracy `applyLedger` zone (66 ms) — the trace mixes warmup/setup
ledgers with the timed sample ledger. A finding that looks ~10% of mean
applyLedger may be ~1% of the actual benchmark denominator. Also: when
adding a new metric or histogram, always add the corresponding
`DISABLE_*_METRICS_FOR_TESTING` gate at every call site to prevent
benchmark-only overhead from compounding over time.
