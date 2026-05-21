# H002: Accumulate signature verification cache metrics per thread instead of locking per cached signature

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / signature verification metrics
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing global mutex contention from cached signature checks in pre-parallel apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Signature verification cache hit/miss counters should be observability-only and should not require a global mutex acquisition for every cached signature checked during `applyLedger`. During apply, the transaction result must still depend on the same signature verification cache lookup results, used-signature tracking, signer weights, and extra-signature checks, but the metrics counters can be accumulated in thread-local or `SignatureChecker`-local counters and flushed into the global totals once per transaction, worker, or ledger.

## Mechanism

`SignatureChecker::checkSignature` calls `SignatureUtils::verify` for each Ed25519 signer/signature pair and then immediately calls `updateTxSigCacheMetrics`. That helper takes `gCheckValidOrApplyTxSigCacheMetricsMutex` for every lookup result before incrementing two global counters. In the current soroswap apply windows, unwrap filtering shows **82,981** in-apply `verifySig` events and **133,017** in-apply `checkSignature` events, while `verify_ed25519_signature_dalek` has **0** in-apply events, indicating that the apply path is mostly exercising cached verification results rather than expensive cryptography. The actual behavior therefore leaves a global lock and counter update in the hot pre-parallel validation path even when the cryptographic result is already cached; batching metrics removes the lock without changing validation semantics.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md`. During `applyLedger`, `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` calls `TransactionFrame::preParallelApply` / `preParallelApplyReadOnly`, which reaches `commonValid -> checkAllTransactionSignatures -> SignatureChecker::checkSignature`; operation signature checks then use the same checker in `processSignaturesReadOnly`.

## Target Code

- `src/transactions/SignatureChecker.cpp:117-124` — Ed25519 signature verification path calls `SignatureUtils::verify` and then `updateTxSigCacheMetrics` on every lookup.
- `src/transactions/SignatureChecker.cpp:130-137` — signed-payload signature path has the same per-lookup metrics update.
- `src/transactions/SignatureChecker.cpp:186-204` — `updateTxSigCacheMetrics` acquires the global metrics mutex and increments global counters.
- `src/transactions/TransactionFrame.cpp:1729-1735` — transaction-level signature checks in `commonValid`.
- `src/transactions/TransactionFrame.cpp:2226-2244` — operation-signature and extra-signature checks in read-only pre-parallel apply.
- `src/transactions/ParallelApplyUtils.cpp:526-583` — read-only pre-parallel apply fans validation across workers before the main apply stage.

## Evidence

Timestamp-filtered Tracy confirms the target is inside `applyLedger`, not TX-set construction: `checkSignature` accounts for **126.614 ms** of apply-contained self-time, `verifySig` for **44.496 ms**, and `verify_ed25519_signature_dalek` for **0 ms** inside apply windows. In the longest apply window, `checkSignature` contributes **9.208 ms** on the critical thread before worker apply starts, already at the approximate 3% threshold for the current non-Tracy soroswap median. Source inspection shows the only metrics-side synchronization in the cached verification path is the global mutex in `updateTxSigCacheMetrics`; replacing it with thread-local counters flushed by `flushTxSigCacheCounts` or a ledger-close hook should preserve the observable totals while removing one lock/unlock pair per cached lookup.

This is not a duplicate of prior `cache-apply-signature-results` or `stack-allocate SignatureChecker` failures. Those investigated avoiding signature validation work or the `SignatureChecker` allocation itself; this hypothesis keeps every validation and cache lookup intact and only changes how non-consensus cache metrics are counted.

## Anti-Evidence

The full `checkSignature` zone also includes signer grouping, signer/signature iteration, used-signature bookkeeping, and weight accumulation, so the mutex update is only a subset of the measured time. The PoC must add a narrow Tracy span or counter around `updateTxSigCacheMetrics` to prove that global-lock overhead, rather than loop structure, accounts for enough of the 9 ms hot-window cost to clear Medium. If most signature-cache lookups happen on a single pre-apply thread in the benchmark, the issue is lock overhead rather than contention; a thread-local design still helps, but an atomic counter or relaxed sharded counter may be simpler and should be benchmarked against the same three-run apply-load gate.
