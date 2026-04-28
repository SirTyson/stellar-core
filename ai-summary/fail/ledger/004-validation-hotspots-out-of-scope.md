# H004: Apply-path signature validation aggregate hotspots

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Low
**Impact**: rejected performance hypothesis; aggregate hotspot is mostly outside the objective scope
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If signature or transaction validation is a viable soroswap apply optimization, the expensive validation zones should be descendants of `applyLedger` and consume enough measured close-ledger time to meet the objective's Medium threshold. The correct optimization target would be repeated validation during close, not transaction-set construction or herder-side admission work outside the measured benchmark window.

## Mechanism

The aggregate Tracy profile shows very large totals for `checkValidWithOptionallyChargedFee`, `commonValidPreSeqNum`, `checkAllTransactionSignatures`, and Ed25519 verification. This initially suggested that close-ledger might be redundantly validating soroswap transactions, but the aggregate profile includes TX-set construction and herder validation work that is outside the benchmark's apply-time measurement.

## Trigger

Inspect the reference soroswap Tracy trace with aggregate and self-time exports, then compare validation zones to `applyLedger` windows. `checkValidWithOptionallyChargedFee` totals 16,493,884,757 ns across the full trace, and `commonValidPreSeqNum` self-time totals 3,419,816,816 ns, but the in-apply fee/sequence path does not carry comparable time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1581-1688` — `applyLedger` prepares the tx set, prefetches source accounts, processes fees/sequence numbers, and applies transactions.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` is the in-apply fee/sequence path.
- `src/transactions/TransactionFrame.cpp:1318-1562` — `commonValidPreSeqNum` performs much of the apparent aggregate validation work.
- `src/transactions/TransactionFrame.cpp:1907-1969` — `checkValidWithOptionallyChargedFee` wraps common validation and operation validation.
- `src/herder/TxSetFrame.cpp:1382-1435` and `src/herder/TxSetFrame.cpp:2565-2605` — tx-set preparation/validation paths appear in the trace but are not necessarily measured apply work.

## Evidence

Aggregate Tracy self-time shows `verifySig`, `commonValidPreSeqNum`, and signature validation among the largest zones in the full process trace. However, filtering to events inside `applyLedger` shows `processFeesSeqNums` at only 272,268,613 ns total over 65 ledgers, with `processFeeSeqNum` at 103,148,029 ns over 44,945 calls. That is far smaller than the aggregate validation totals and does not support a Medium-threshold soroswap apply optimization.

## Anti-Evidence

The objective explicitly excludes TX set creation, and the Tracy skill warns that `tryAdd`, `buildSurgePricedParallelSorobanPhase`, surge pricing, and related validation can dominate the process trace while remaining outside the measured apply window. The top aggregate validation zones are therefore not sufficient evidence for an apply-path hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in `ai-summary/fail/ledger`, `hypothesis/ledger`, `reviewed/ledger`, or `poc/ledger`

### Why It Failed

The validation hotspots are mostly aggregate process hotspots rather than measured `applyLedger` descendants, and the in-apply fee/sequence processing path is below the objective's Medium severity threshold.

### Lesson Learned

For apply-load performance hypotheses, aggregate Tracy totals must be filtered against `applyLedger` intervals before promoting a zone; otherwise TX-set construction and herder validation produce misleading hotspots.
