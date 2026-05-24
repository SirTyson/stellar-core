# H004: Optimize Classic `applyTransaction` / `ChangeTrustOp` Hotspots Seen in Soroswap Trace

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Classic setup-ledger work visible in process-wide soroswap Tracy trace
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Performance hypotheses for the optimize-soroswap objective should reduce the steady-state soroswap swap apply path: Soroban host invocation, parallel Soroban apply, footprint loading, and blocking ledger close writes. Classic-only setup transactions such as `ChangeTrustOp` should not be treated as headline soroswap bottlenecks unless they materially affect the accepted soroswap apply-time median.

## Mechanism

The process-wide Tracy trace contains `applyLedger` windows for ledgers that run classic setup work, and those windows include `applySequentialPhase` / `applyTransaction` and `ChangeTrustOpFrame::doApply`. Optimizing those classic operation paths could reduce those setup windows, but it would not reduce the normal soroswap swap ledgers that dominate the objective's accepted median and are intentionally Soroban-heavy.

## Trigger

Inspect the current diagnostic soroswap trace and intersect candidate zones with `applyLedger`. Classic setup ledgers show `applyTransaction` and `ChangeTrustOp apply` descendants even though the target workload's steady-state swap transactions run through the parallel Soroban phase.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3035-3065` — `LedgerManagerImpl::applySequentialPhase` emits the `applyTransaction` Tracy zone and applies classic transactions sequentially.
- `src/transactions/ChangeTrustOpFrame.cpp:145-180` — `ChangeTrustOpFrame::doApply` emits `ChangeTrustOp apply` and runs classic trustline setup logic.
- `src/ledger/LedgerManagerImpl.cpp:2785-3030` — `applyTransactions` dispatches between sequential classic phases and parallel Soroban phases.

## Evidence

An apply-window Tracy intersection for the current soroswap trace shows `applyTransaction` at 603.978 ms over 18,909 events and `ChangeTrustOp apply` at 94.987 ms over 18,000 events under `applyLedger`. These are real apply descendants, not TX-set construction zones.

## Anti-Evidence

The zones are classic setup work rather than Soroban swap execution. The retained soroban fail summary already warns that classic-tx-only paths are not the soroswap hot path, and the objective explicitly excludes classic-tx-only application paths that are not exercised by the soroswap benchmark's headline workload. Even full removal of `ChangeTrustOp apply` would normalize to about 0.165 ms/ledger across the 72-window diagnostic trace, well below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — this exact apply-window classic setup-zone observation was not separately recorded in `ai-summary/fail/soroban/summary.md`

### Why It Failed

The candidate optimizes classic setup/application work, not the steady-state Soroban swap path. It is therefore outside the objective focus, and the isolated `ChangeTrustOp` component is also far below the 3% Medium threshold.

### Lesson Learned

Being a descendant of `applyLedger` is necessary but not sufficient. For apply-load traces, distinguish steady-state soroswap ledgers from setup ledgers before promoting classic operation zones as soroswap optimization targets.
