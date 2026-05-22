# H002: Reuse validated txset stateless checks during apply

**Date**: 2026-05-22
**Subsystem**: ledger / transaction validation boundary
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by skipping repeated stateless transaction validation, hashing, and signature checks inside `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `applyLedger` receives an `ApplicableTxSetFrame` that was already validated for the same previous ledger hash, close-time bounds, ledger protocol, network ID, Soroban config, and txset contents hash, the apply path should not redo stateless checks whose results cannot change before transaction execution. It should still perform all stateful fee, sequence-number, source-account balance, Soroban resource-fee, and per-transaction result construction work against the current `LedgerTxn`, and it must fall back to full validation whenever the validation certificate is missing or stale.

## Mechanism

The current close path validates txsets before nomination/externalization, but `applyLedger` still walks transactions through `processFeesSeqNums`, `preParallelApplyReadOnly`, and related validation helpers that rebuild `SignatureChecker`s, recompute or probe transaction hashes, inspect signatures, and rerun `commonValidPreSeqNum` checks. Much of that work is stateless with respect to the applying ledger once the txset has been accepted for the exact LCL and close-time window. Adding a small validation certificate to `ApplicableTxSetFrame`/`TxSetPhaseFrame` — keyed by previous ledger hash, contents hash, protocol, close-time offsets, and Soroban config hash — would let apply consume prevalidated transaction flags and skip only the immutable checks while preserving deterministic stateful application order.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The benchmark constructs a valid Soroban txset, then `LedgerManagerImpl::applyLedger` applies the same `ApplicableTxSetFrame`; every ledger repeats transaction hash/signature/stateless checks for thousands of source-account-authenticated Soroban transactions before the parallel host execution phase.

## Target Code

- `src/herder/TxSetFrame.cpp:checkValidInternalWithResult:2565-2645` — validates every phase and is the natural point to mint a context-bound validation certificate after all phases pass.
- `src/herder/TxSetFrame.h:467-620` — `ApplicableTxSetFrame` stores immutable phases and contents hash but has no durable record that those phases were validated for a specific ledger context.
- `src/ledger/LedgerManagerImpl.cpp:applyLedger:1484-1565` — verifies the txset previous-ledger hash and contents hash before applying, the same context anchors a validation certificate.
- `src/ledger/LedgerManagerImpl.cpp:processFeesSeqNums:2303-2440` — loops all txs before parallel apply; stateful fee/seq updates must remain, but stateless revalidation flags can be consumed here.
- `src/transactions/TransactionFrame.cpp:checkValidWithOptionallyChargedFee:1893-1935` and `commonValidPreSeqNum:1327-1395` — rebuild signature/hash validation scaffolding and stateless Soroban checks that are candidates for certificate reuse.

## Evidence

The accepted diagnostic trace confirms these checks overlap `applyLedger`, not just txset construction. A timestamp-filtered unwrap pass found in-apply overlap of **149.420 ms** for `processFeesSeqNums`, **124.377 ms** for `checkSignature`, **52.367 ms** for `commonValidPreSeqNum`, **69.642 ms** for `getFullHash`, and **27.389 ms** for `getSize` across the 71 apply windows. Some of these totals are nested or partially mandatory, but unlike Soroban worker zones they are serial ledger-apply work and do not divide by `NUM_CLUSTERS`. Even reclaiming a conservative half of the repeated stateless subset is in the Medium range for the current soroswap baseline.

The source also already distinguishes public full validation from internal validation with `txsAreValidated` in `ApplicableTxSetFrame::checkValidInternalWithResult`, but that knowledge is not represented as a reusable apply-time artifact. A correct design would not trust transaction objects blindly: the certificate must bind the validation context to `txSet->previousLedgerHash()`, `txSet->getContentsHash()`, ledger protocol, close-time offsets, base fee/fee map, and Soroban config used during validation; `applyLedger` must invalidate it on any mismatch and run the existing full path.

## Anti-Evidence

Previous validation hypotheses failed when they projected from global Tracy totals dominated by TX-set construction or targeted a single sub-call such as signature caching. This hypothesis depends on the narrower in-apply overlap above and must prove that the removable stateless subset is still large after preserving stateful fee/sequence/account checks, result error surfaces, and replay behavior. It also needs careful production-path analysis: externally received SCP values may arrive as wire txsets without a local validated `ApplicableTxSetFrame`, so the optimization must be opportunistic and never skip validation unless the exact certificate was produced locally for the current LCL.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`makeTxSetFromTransactions` validates transactions during txset construction via `TxSetUtils::trimInvalid`, then uses `checkValidInternalWithResult(..., txsAreValidated=true)` only to re-check txset structure after XDR roundtrip. The externalized value carries a `TxSetXDRFrame`; `LedgerManagerImpl::applyLedger` reconstructs a fresh `ApplicableTxSetFrame` with `prepareForApply`, charges fees in `processFeesSeqNums`, and then re-enters validation-like work during classic `TransactionFrame::apply` or Soroban `preParallelApply(ReadOnly)`. That repeated work exists, but the cited measurements are totals across 71 ledgers, and the fully eliminable stateless subset is below the objective's Medium threshold.

### Code Paths Examined

- `src/herder/TxSetFrame.cpp:1090-1240` — txset construction trims invalid transactions, builds an applicable frame, roundtrips through XDR, then uses `txsAreValidated=true` to skip per-tx validation for the post-roundtrip shape check.
- `src/herder/TxSetFrame.cpp:2190-2258` — `TxSetPhaseFrame::checkValidWithResult` skips `TxSetUtils::getInvalidTxListWithErrors` when `txsAreValidated` is true, but still performs fee-map, phase-type, resource, cluster-count, and ordering checks.
- `src/herder/HerderSCPDriver.cpp:1393-1456` — herder has only a validity cache keyed by LCL hash, txset hash, and close-time offsets; it stores a boolean, not reusable per-transaction validation results for apply.
- `src/ledger/LedgerManagerImpl.cpp:1484-1582` — `applyLedger` verifies previous-ledger hash and contents hash, then calls `TxSetXDRFrame::prepareForApply`; it does not receive the originally validated `ApplicableTxSetFrame`.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — `processFeesSeqNums` charges fees and updates pre-v10 sequence numbers; it does not rebuild `SignatureChecker` or call transaction validation, so most of this cited zone is mandatory stateful fee/result work.
- `src/transactions/ParallelApplyUtils.cpp:386-428` and `:526-583` — Soroban parallel apply constructs global state and runs `preParallelApply(ReadOnly)` before worker execution, which redoes `commonValid` and signature checks for applicable transactions.
- `src/transactions/TransactionFrame.cpp:1665-1774`, `:2073-2198`, `:2261-2301`, `:2696-2725` — classic and Soroban apply paths rebuild `SignatureChecker`, run `commonValidPreSeqNum`, check signatures, and then apply operations if validation remains successful.
- `src/transactions/SignatureChecker.cpp:23-144` and `src/crypto/SecretKey.cpp:469-520` — Ed25519 verification is already backed by a process-wide signature verification cache, so repeated apply-time signature checks mostly pay cache-key, lock, signer-walk, and result-surface overhead rather than full cryptographic verification after txset validation.

### Why It Failed

The optimization cannot meet the objective's Medium floor. The hypothesis's own in-apply measurements total about 423 ms across 71 apply windows, or about 6 ms per ledger before removing nested overlap and before subtracting mandatory stateful work. Against the current soroswap apply baseline of roughly 272-305 ms/ledger, even eliminating every cited zone would be about 2%, and a correct implementation cannot eliminate all of it: `processFeesSeqNums` is fee/state mutation, `commonValid` includes sequence/account/balance/frozen-key checks that must remain or be carefully guarded, and signature verification already benefits from the existing verify-cache. The realistic removable subset is therefore below the 3% Medium threshold required by the optimize-soroswap objective.

### Lesson Learned

When Tracy totals are reported "across N apply windows", divide them by N before assigning severity. Validation reuse is architecturally plausible in a narrow sense, but for soroswap its apply-time ceiling is sub-Medium once mandatory fee/sequence/state checks and existing signature-cache mitigation are accounted for.
