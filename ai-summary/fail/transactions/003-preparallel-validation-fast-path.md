# H003: Reuse Earlier Soroban Validation During Pre-Parallel Apply

**Date**: 2026-04-28
**Subsystem**: transactions
**Severity**: Low
**Impact**: reduce redundant transaction validation work before Soroban parallel apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `closeLedger`, Soroban transactions should still validate against the current last-closed ledger state, update sequence numbers, remove one-time signers when required, initialize refundable fee tracking, set non-refundable fee metadata, validate operation signatures, and fail with the same transaction result codes. If an earlier tx-set validation result can be reused safely, apply should avoid repeating deterministic checks that cannot change between tx-set construction and ledger close.

## Mechanism

The global Tracy self-time table makes `commonValidPreSeqNum` look extremely hot: 3.390 s self-time at `transactions/TransactionFrame.cpp:1327` across 187,782 calls. This suggested carrying validated Soroban resource/footprint/signature state into `preParallelApplyReadOnly` or adding an apply-mode fast path that skips checks already performed while building the tx set. However, timestamp correlation with the current soroswap `applyLedger` windows shows the apply-path portion is small: `preParallelApplyReadOnly` overlaps apply by 34.408 ms total, `processSignaturesReadOnly` by 5.599 ms, `computePreApplySorobanResourceFee` by 5.519 ms, and `commonValidPreSeqNum` by 42.926 ms across the apply windows.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) and inspect the headline trace from `ai-summary/CURRENT_STATE.md`. The investigated path triggers during `GlobalParallelApplyLedgerState::readOnlyPreParallelApply`, where each Soroban tx calls `TransactionFrame::preParallelApplyReadOnly` before worker-side `parallelApply`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:525-583` — `GlobalParallelApplyLedgerState::readOnlyPreParallelApply` parallelizes read-only pre-apply validation over tx bundles.
- `src/transactions/TransactionFrame.cpp:2145-2198` — `commonParallelPreApplyReadOnly` builds a `SignatureChecker`, recomputes Soroban resource fee, calls `commonValid`, and records pre-apply info.
- `src/transactions/TransactionFrame.cpp:2270-2312` — `preParallelApplyReadOnly` calls the common read-only validation path and then operation `checkValid`.
- `src/transactions/TransactionFrame.cpp:1318-1490` — `commonValidPreSeqNum` performs the Soroban consistency, resource, fee, and footprint duplicate checks that looked hot in aggregate.

## Evidence

The code does repeat validation work during ledger close, and `commonValidPreSeqNum`, `checkValid`, and signature-checking zones are among the largest global self-time entries in the trace. The apply path also has a read-only/write split (`preParallelApplyReadOnly` followed by `preParallelApplyWrite`) that makes it tempting to carry reusable validation state into the write stage.

## Anti-Evidence

The global hotspot is dominated by tx-set construction and validation outside the measured benchmark window. Direct overlap analysis against `applyLedger` shows only 34.408 ms of `preParallelApplyReadOnly` total time and 42.926 ms of `commonValidPreSeqNum` total time inside apply windows, and that work is already spread over read-only worker chunks. Normalized to the 8 configured clusters, the removable wall-clock portion is well below the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated for the transactions queue

### Why It Failed

The apparent validation hotspot is mostly a Tracy trap: tx-set validation dominates the global `commonValidPreSeqNum` and `checkValid` totals, while the measured `applyLedger` overlap is too small to meet the optimize-soroswap Medium severity floor.

### Lesson Learned

For transaction validation zones, always correlate event timestamps with `applyLedger` before proposing a reuse or fast-path optimization; global self-time alone overstates apply impact because the benchmark trace includes tx-set construction.
