# H015: Skip Repeated Signature Validation During Soroswap Apply

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Apply-time reduction by avoiding signature verification
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The apply-load optimization target should only count work that occurs inside the `applyLedger` measurement window. If transaction signature validation is already performed outside the measured apply path, optimizing it should not be proposed as a soroswap apply-time hypothesis even if the trace shows large total or self time for signature zones.

## Mechanism

The raw soroswap Tracy self-time table shows very large signature-related zones: `verifySig`, `checkSignature`, `checkAllTransactionSignatures`, and `commonValidPreSeqNum`. This initially suggests caching or reusing validation results could materially reduce apply time. Event-window overlap analysis against `applyLedger` showed those zones do not overlap the measured apply windows in the diagnostic trace; the large signature totals come from transaction validation / TX-set construction outside the benchmark's apply-time target.

## Trigger

Run `csvexport-release -u` on the current soroswap trace from `ai-summary/CURRENT_STATE.md`, extract `applyLedger` events, and compute temporal overlap for `commonValidPreSeqNum`, `checkAllTransactionSignatures`, `verifySig`, and `checkSignature`. The overlap with `applyLedger` is **0.000 ms** for all four zones in the current diagnostic trace, while `processFeeSeqNum` and `preParallelApply` do overlap as expected.

## Target Code

- `src/transactions/SignatureChecker.cpp:33-144` — `SignatureChecker::checkSignature` performs signer iteration and signature verification.
- `src/transactions/TransactionFrame.cpp:499-597` — transaction-level source-account signature checks call into `SignatureChecker`.
- `src/transactions/TransactionFrame.cpp:1318-1385` and `src/transactions/TransactionFrame.cpp:1665-1715` — `commonValidPreSeqNum` / `commonValid` appear hot in the full trace but outside the apply window.
- `src/transactions/TransactionFrame.cpp:2251-2371` — `preParallelApply` is the apply-overlapping Soroban pre-apply path, but the large signature-validation zones were not observed inside it for this trace.

## Evidence

The current full-trace self-time table shows `verifySig` at **4074.874 ms** self, `commonValidPreSeqNum` at **4238.940 ms** self, and `checkSignature` at large total time, which is enough to look like a dominant bottleneck. A direct unwrap-mode overlap check against `applyLedger` windows reported:

- `commonValidPreSeqNum`: total **5153.617 ms**, overlap with `applyLedger` **0.000 ms**
- `checkAllTransactionSignatures`: total **4230.370 ms**, overlap **0.000 ms**
- `verifySig`: total **5911.965 ms**, overlap **0.000 ms**
- `checkSignature`: total **9034.028 ms**, overlap **0.000 ms**

## Anti-Evidence

`processFeeSeqNum` and `preParallelApply` do overlap `applyLedger`, so the overlap method is capable of detecting apply-contained transaction processing. The absence of signature-zone overlap means these signature costs are part of trace-wide setup/validation rather than the measured close-ledger apply path for this objective.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded in the soroban fail summary as a signature-validation-specific trap

### Why It Failed

The optimization target is out of scope. The expensive signature-validation zones are visible in the process-wide Tracy trace but are not descendants of the `applyLedger` measurement window used for the soroswap apply-time benchmark.

### Lesson Learned

Always verify trace candidates against `applyLedger` windows before proposing them. Full-trace hotspots from validation, TX-set construction, or admission can dwarf apply-path work but do not reduce the objective metric.
