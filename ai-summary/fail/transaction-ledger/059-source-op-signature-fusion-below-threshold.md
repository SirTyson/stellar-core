# H059: Fuse source-account and operation signature checks for single-op Soroban transactions

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-time validation micro-optimization below the optimize-soroswap threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a single-operation Soroban transaction whose operation source account is the transaction source account, the apply path should only need to prove the maximum required threshold once. A successful medium-threshold operation-source signature check should imply the low-threshold transaction-source signature check, while still enforcing extra signers and `checkAllSignaturesUsed()`.

## Mechanism

`commonValid` checks the transaction source signature at low threshold, then `processSignaturesReadOnly` calls `checkOperationSignatures`, and `OperationFrame::checkSignature` checks the same source account again at the operation threshold. For source-account-only soroswap transactions, this repeats `SignatureChecker::checkSignature` work in the serial pre-parallel-apply phase even though the operation source is not distinct.

## Trigger

Run the current soroswap apply-load benchmark. The generated transactions are single-operation `INVOKE_HOST_FUNCTION` transactions with no operation source account override, so pre-parallel apply checks the transaction source and operation source against the same account.

## Target Code

- `src/transactions/TransactionFrame.cpp:1665-1745` — `commonValid` calls `checkAllTransactionSignatures` for the source account.
- `src/transactions/TransactionFrame.cpp:2146-2197` — `commonParallelPreApplyReadOnly` invokes `commonValid` and then `processSignaturesReadOnly`.
- `src/transactions/TransactionFrame.cpp:2200-2248` — `processSignaturesReadOnly` calls `checkOperationSignatures` and then `checkAllSignaturesUsed`.
- `src/transactions/OperationFrame.cpp:217-260` — `OperationFrame::checkSignature` reloads the operation source and calls `TransactionFrame::checkSignature`.
- `src/transactions/SignatureChecker.cpp:33-144` — `SignatureChecker::checkSignature` iterates signatures/signers and marks used signatures.

## Evidence

The current trace, filtered to `applyLedger` windows, shows `preParallelApplyReadOnly` **118.066 ms**, `checkOperationSignatures` **61.631 ms**, `checkSignature` **122.938 ms**, and `verifySig` **43.153 ms** in apply. The duplicate-source shape is real in `ApplyLoad::generateSoroswapSwaps`, where the operation has no source override.

## Anti-Evidence

Prior validation-cache investigations already found that most global signature/validation time is outside `applyLedger`, and the apply-window slice is small. The current direct measurement confirms the full serial pre-parallel-read-only envelope is only about 118 ms across the whole trace; the removable duplicate operation-signature subset is smaller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — this exact same-source threshold-fusion variant was not separately recorded, though it is adjacent to prior signature-cache failures

### Why It Failed

Even deleting the whole measured `checkOperationSignatures` slice would save only about 61.6 ms across the diagnostic trace, and the safe implementation would preserve extra-signer handling, operation-source overrides, `mUsedSignatures`, and `checkAllSignaturesUsed`. The realistic critical-path saving is below the 3% Medium floor and likely below the 1% noise floor on the current non-Tracy baseline.

### Lesson Learned

Source/operation signature fusion is a valid local simplification opportunity, but soroswap's apply-time bottleneck is now dominated by Soroban host execution rather than C++ pre-parallel validation. Do not promote additional signature-validation micro-optimizations without a new trace showing a much larger in-apply serial validation share.

