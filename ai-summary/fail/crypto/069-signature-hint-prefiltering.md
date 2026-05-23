# H069: Precompute Signature Hints Before Apply-Path Signer Verification

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by apply-path signature ceiling)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Apply-path source-account signature checks should avoid repeated work when filtering decorated signatures against account signers. For each signer, the 4-byte signature hint is a deterministic suffix of the public key or signed payload, so the efficient behavior would be to compute signer hints once per signer list and compare hints before entering any heavier `PubKeyUtils::verifySig` cache/proof path.

## Mechanism

`SignatureChecker::checkSignature` builds grouped signer vectors and its `verifyAll` lambda loops over every decorated signature and then every signer of the relevant type (`src/transactions/SignatureChecker.cpp:74-124`). For ED25519 signers, each candidate calls `SignatureUtils::verify`, which calls `doesHintMatch(pubKey.ed25519(), sig.hint)` at `src/transactions/SignatureUtils.cpp:38-45`; signed-payload signers similarly call `getSignedPayloadHint` and then `doesHintMatch` at lines 49-60. A precomputed `(hint, signer)` structure or per-hint signer bucket could reduce repeated suffix extraction and failed candidate checks without changing verification semantics.

## Trigger

Run soroswap with many source-account-authenticated transactions. The apply path invokes `TransactionFrame::checkSignature` (`src/transactions/TransactionFrame.cpp:499-514`) and `OperationFrame::checkSignature` (`src/transactions/OperationFrame.cpp:217-230`) during validation and signature processing, so transactions with multiple signers or multiple decorated signatures would exercise repeated hint prefiltering.

## Target Code

- `src/transactions/SignatureChecker.cpp:74-124` — nested `verifyAll` loop over decorated signatures and signers
- `src/transactions/SignatureUtils.cpp:38-45` — ED25519 hint precheck before `PubKeyUtils::verifySig`
- `src/transactions/SignatureUtils.cpp:49-60` — signed-payload hint construction and precheck
- `src/transactions/TransactionFrame.cpp:499-514` — transaction-level source account signer list construction
- `src/transactions/OperationFrame.cpp:217-230` — operation-level source account signature check caller

## Evidence

The source does reconstruct signer vectors on each `TransactionFrame::checkSignature` call and performs hint checks through lambdas inside a nested loop. Timestamp filtering against the current soroswap trace showed `checkSignature` events overlapping `applyLedger` (133,017 events, 126,017,579 ns in the Tracy build), so this code is reachable from the measured apply window. The transformation is deterministic because hint grouping only changes the order in which failed candidates are skipped; it must preserve the existing signer erase/weight accumulation semantics when a signer is accepted.

## Anti-Evidence

Existing crypto Meta-Patterns 5 and 10 already bound the whole apply-path signature-verification surface below 1%, and most signature crypto work in the full trace is outside `applyLedger`. In the current overlap measurement, `verifySig` itself contributes only 44,403,992 ns inside `applyLedger`, and `verify_ed25519_signature_dalek` has zero overlapping events. The proposed hint prefilter is only a small fraction of the already-small `checkSignature` envelope, while soroswap source-account auth typically has one relevant source signer and one decorated transaction signature, leaving little or no nested-loop fanout to eliminate. This cannot reach the objective's Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — signer-hint prefiltering was not previously recorded separately from verifySig cache and crypto-prelude micro-optimizations

### Why It Failed

The mechanism is real but too small. Apply-contained signature work is already structurally capped below Low, and hint extraction/`memcmp` is a tiny prefilter within that cap, especially for soroswap's simple source-account credential shape.

### Lesson Learned

Do not promote additional source-account signature micro-optimizations unless a trace shows multi-signer fanout inside `applyLedger` large enough to escape Meta-Pattern 5. Soroswap's apply-path signature checks are reachable but not large enough for Medium-tier performance work.
