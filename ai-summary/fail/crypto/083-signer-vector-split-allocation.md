# H083: Signer Vector Copy and Split Allocation Are Below Threshold

**Date**: 2026-05-26
**Subsystem**: crypto / transactions
**Severity**: Low
**Impact**: apply-path signer-list allocation and grouping below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When applying soroswap transactions, Core should validate source-account and operation signatures without spending Medium-tier time constructing temporary signer containers. A viable optimization would preserve signer-weight semantics, one-time signer handling, `checkAllSignaturesUsed`, and all protocol-version branches while avoiding repeated `std::vector<Signer>` construction and `split` grouping for the common Ed25519-source-account shape.

## Mechanism

`TransactionFrame::checkSignature` builds a fresh `std::vector<Signer>` on every call, pushes the master-key signer when enabled, copies all account signers, and then `SignatureChecker::checkSignature` splits that vector by signer type before scanning decorated signatures. Soroswap benchmark accounts normally use the simple Ed25519 source-account path, so a specialized borrowed-view or stack-small representation could skip heap allocation and grouping for the common case. The deviation from expected Medium impact is that the entire signature-check caller is too small after apply-window filtering and parallelism normalization.

## Trigger

Run the current soroswap apply-load benchmark with the default generated accounts and timestamp-filter `checkSignature`, `checkOperationSignatures`, `processSignatures`, and `checkAllTransactionSignatures` against `applyLedger`. The candidate would trigger on every source-account and operation-source signature check where the account signer set is copied and then grouped.

## Target Code

- `src/transactions/TransactionFrame.cpp:499-514` — builds a fresh signer vector from master key plus `acc.signers`.
- `src/transactions/OperationFrame.cpp:217-229` — operation signature checks call back into `TransactionFrame::checkSignature`.
- `src/transactions/TransactionFrame.cpp:1583-1635` — apply-time `processSignatures` invokes operation signature checks and final signature-consumption validation.
- `src/transactions/SignatureChecker.cpp:46-76` — `split(signersV, ...)` groups signers by key type before scanning signatures.
- `src/crypto/KeyUtils.h:121-130` — `KeyUtils::convertKey<SignerKey>(acc.accountID)` constructs the Ed25519 signer key used for master-key checks.

## Evidence

The source has a concrete repeated-allocation shape: `checkSignature` constructs and populates a vector for each call even when the signer set is the common master-key-only or small-Ed25519 case, and `SignatureChecker` immediately copies/groups it again via `split`. The current trace shows `checkSignature` overlapping `applyLedger` windows 133,018 times with about 122.3 ms total event duration; `processSignatures` and `checkOperationSignatures` are also apply-reachable.

## Anti-Evidence

The measured ceiling is below the objective threshold. `checkSignature`'s whole apply-overlap is about 122.3 ms across 71 ledgers, or about 1.72 ms per ledger before subtracting mandatory signer-weight logic, signature-use bookkeeping, and cache-hit verification calls. This is under 1% of the ~207.6 ms soroswap baseline, and much of the work occurs in parallel worker stages that must be normalized by `NUM_CLUSTERS`. Prior crypto records also rejected adjacent signature-weight/proof-reuse hypotheses for the same reason: the complete signature-validation surface cannot clear Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — prior failures covered signature proof reuse and source-account signature-weight caching, but not the specific temporary vector construction plus `split` allocation path.

### Why It Failed

Avoiding signer-vector allocation and grouping would remove only a fraction of an already sub-threshold `checkSignature` envelope. Correctness-preserving changes must still evaluate signer weights, signer types, signature consumption, and protocol-specific branches, leaving realistic savings well below the 3% Medium floor.

### Lesson Learned

Small allocation cleanups in signature validation are not viable for optimize-soroswap unless a new trace shows the whole `checkSignature` caller at Medium scale after apply-window filtering and parallel-worker normalization.
