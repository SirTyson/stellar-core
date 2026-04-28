# H011: Cache apply-path signature and transaction-hash validation results

**Date**: 2026-04-28
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Redundant validation/hash work during `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If a transaction has already been validated before application, the close-ledger apply path should not repeat expensive signature/hash work unless ledger-state-dependent checks require it. A viable optimization would reuse prior `getContentsHash`, `getFullHash`, and signature-check outcomes during `processFeesSeqNums`, `apply`, and Soroban pre-parallel validation while preserving all stateful sequence, balance, signer, and source-account checks.

## Mechanism

The current trace shows large whole-process totals for `verifySig`, `checkSignature`, `commonValidPreSeqNum`, `getContentsHash`, and `getFullHash`, suggesting repeated validation/hash work. However, the majority comes from transaction-set construction/validation outside the measured benchmark window, and the apply-window share is much smaller. Caching the remaining apply-path pieces would also need a subtle cache key covering protocol version, `chargeFee`, result-error side effects, signature-consumption state, and signer state.

## Trigger

Run the current soroswap apply-load trace and compare aggregate validation zones with timestamp-filtered events that start inside `applyLedger` windows.

## Target Code

- `src/transactions/TransactionFrame.cpp:121-159` — lazy `getFullHash` / `getContentsHash` computation.
- `src/transactions/TransactionFrame.cpp:504-578` — transaction signature checks.
- `src/transactions/TransactionFrame.cpp:1327-1490` — `commonValidPreSeqNum` stateless-looking but result-mutating validation.
- `src/transactions/TransactionFrame.cpp:1666-1750` — `commonValid` combines stateful and stateless checks.
- `src/ledger/LedgerManagerImpl.cpp:2308-2400` — apply-path fee/sequence and pre-parallel validation callers.

## Evidence

- Whole-trace self-time is superficially attractive: `verifySig,crypto/SecretKey.cpp:473` has 6.216 s self-time, `commonValidPreSeqNum,transactions/TransactionFrame.cpp:1327` has 3.390 s self-time, `getFullHash,transactions/TransactionFrame.cpp:124` has 182.980 ms self-time, and `getContentsHash,transactions/TransactionFrame.cpp:135` has 133.577 ms self-time.
- Timestamp filtering against the current trace's `applyLedger` intervals reduces the relevant totals sharply: `verifySig` is only 63.110 ms total event time inside apply windows, `commonValidPreSeqNum` 42.926 ms, `getFullHash` 56.246 ms, and `getContentsHash` 239.008 ms. These are spread across 65 apply windows and many validation contexts.
- A prior nearby failure (`010-cache-tx-stateless-validation-on-frame.md`) already found that caching `commonValidPreSeqNum`-style stateless validation is below threshold and risky because stateful/result-mutating details are easy to mis-key.

## Anti-Evidence

- `TransactionFrame::getContentsHash` and `getFullHash` already memoize on the frame, so much of the timestamp-filtered time is many cheap cache hits plus a smaller number of first computations. Reducing repeated calls would require wider API changes for a small remaining cost.
- Signature verification already uses `SignatureChecker` and lower-level verification caches; timestamp-filtered `verifySig` apply time is far below the 18 ms-per-ledger Medium threshold once spread over the benchmarked ledgers.
- Validation writes exact error codes into `MutableTransactionResultBase`, consumes signature state, and depends on ledger-state details such as source account, sequence, balances, and signer changes. A broad cache risks correctness for sub-1% to low-single-digit savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — specific apply-window signature/hash caching was checked separately from the prior stateless-prevalidation cache failure

### Why It Failed

The apparent validation hotspot is mostly outside the measured apply window. After filtering to events that start inside `applyLedger`, the remaining signature/hash/validation work is too small and too diffuse to plausibly meet the objective's 3% Medium threshold, especially because hashes are already lazily cached and signature verification uses existing caches.

### Lesson Learned

Do not rank validation hypotheses from whole-trace self-time in apply-load traces. Always timestamp-filter against `applyLedger`; TX-set validation and construction can dominate validation zones while remaining out of scope for optimize-soroswap.
