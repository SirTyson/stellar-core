# H003: Skip Empty Soroban Transaction-Data Prefetch

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Low
**Impact**: small apply-time reduction from avoiding no-op prefetch work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The apply path should avoid calling the root prefetch machinery when a Soroban-only transaction set has no classic operation keys to prefetch for transaction application. Source-account prefetch before fee processing should remain intact, but the later transaction-data prefetch should become a cheap no-op if no operation contributes keys.

## Mechanism

`LedgerManagerImpl::applyTransactions` always calls `prefetchTransactionData`, which walks every phase and transaction, calls `TransactionFrame::insertKeysForTxApply`, and then calls `LedgerTxnRoot::prefetch` even when the resulting set is empty. For `InvokeHostFunctionOpFrame`, `insertLedgerKeysToPrefetch` is intentionally empty, so a pure soroswap ledger can spend time walking transactions and exercising empty prefetch plumbing. Skipping the root call when `keysToPreFetch.empty()` would be safe and deterministic.

## Trigger

Run the current soroswap apply-load benchmark, whose transactions are Soroban invoke-host-function operations. Inspect `prefetchTransactionData` and `LedgerTxnRoot::prefetch` in the baseline Tracy trace.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2463-2480` — builds `keysToPreFetch` and unconditionally calls `ltx.prefetch(keysToPreFetch)`.
- `src/ledger/LedgerManagerImpl.cpp:2784-2824` — `applyTransactions` unconditionally invokes `prefetchTransactionData`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` — Soroban invoke operations do not add classic prefetch keys.
- `src/ledger/LedgerTxn.cpp:3100-3155` — root prefetch still constructs search sets and calls `loadLiveKeys`.

## Evidence

The trace shows `prefetchTransactionData` at `ledger/LedgerManagerImpl.cpp:2468` with 33.408 ms self-time and 66 calls, while `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` contributes no keys. The code has a straightforward empty-set guard opportunity.

## Anti-Evidence

The measured `prefetchTransactionData` self-time is only 33.408 ms across the full trace, below 1% of aggregate `applyLedger` time. Even if the empty prefetch root call also saves some child time, this is unlikely to reach the objective's Medium threshold on its own.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded in ledger fail/hypothesis dirs

### Why It Failed

The optimization is plausible and low risk, but the measured impact is below the objective severity threshold; Low hypotheses are not accepted at this stage.

### Lesson Learned

Empty-set fast paths can be worthwhile cleanup, but this objective requires a measurable multi-percent soroswap apply-time win, so prefetch walking overhead alone is not a strong target.
