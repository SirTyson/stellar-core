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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; distinct from `046-stack-allocate-signaturechecker-on-apply-path.md` and from the summarized `011-cache-apply-signature-results.md`
**Failed At**: reviewer

### Trace Summary

The claimed lock exists: every tracked Ed25519 and Ed25519-signed-payload verification attempt in `SignatureChecker::checkSignature` calls `updateTxSigCacheMetrics`, which takes a single process-global mutex before updating observability counters. The path is reached during Soroban pre-parallel apply through `GlobalParallelApplyLedgerState::readOnlyPreParallelApply` -> `readOnlyPreParallelApplyRange` -> `TransactionFrame::preParallelApplyReadOnly` -> `commonParallelPreApplyReadOnly` -> `commonValid` / `processSignaturesReadOnly`. However, the removable operation is only one tiny metrics lock/update per signature-cache result, while the measured `checkSignature` zone includes signer splitting, nested signer/signature iteration, used-signature bookkeeping, threshold accumulation, the sharded verification-cache lookup, and operation signature validation. With roughly 82,981 `verifySig` events across the diagnostic trace, this is about 1.2k tracked cache lookups per ledger, far below the volume needed for a reproducible 3-10% apply-time reduction unless each metrics update cost implausibly many microseconds.

### Code Paths Examined

- `src/transactions/SignatureChecker.cpp:117-137` — Ed25519 and signed-payload checks call `SignatureUtils::verify*` and immediately update tx signature-cache metrics before returning the validation result.
- `src/transactions/SignatureChecker.cpp:168-204` — `flushTxSigCacheCounts` and `updateTxSigCacheMetrics` share `gCheckValidOrApplyTxSigCacheMetricsMutex`; the update locks even for `NO_LOOKUP` tracked attempts, but only increments counters for cache lookup/hit results.
- `src/transactions/SignatureChecker.h:46-70` — the metrics are documented as scoped counters for transaction `checkValid` or apply flow; they are not consensus-visible.
- `src/transactions/SignatureUtils.cpp:30-60` — signature helpers return `NO_LOOKUP` on hint mismatch or call `PubKeyUtils::verifySig`, so the metrics lock is downstream of the actual cache lookup result and can be batched without changing validation.
- `src/crypto/SecretKey.cpp:469-520` — the underlying verification cache is already sharded across 16 mutex-protected caches and uses atomic hit/miss counters; the proposed change would not remove cache-key hashing or the sharded cache mutex.
- `src/transactions/ParallelApplyUtils.cpp:135-148,526-583` — read-only pre-parallel apply runs chunks on `std::async` workers and calls `preParallelApplyReadOnly` for each transaction.
- `src/transactions/TransactionFrame.cpp:2145-2197` — read-only pre-apply constructs a `SignatureChecker`, runs `commonValid`, then runs read-only signature processing.
- `src/transactions/TransactionFrame.cpp:573-598,1729-1735,2200-2248` — transaction-level signatures are checked in `commonValid`, and operation/extra-signature checks are handled before parallel execution.
- `src/main/ApplicationImpl.cpp:1308-1326` — metrics are flushed later into medida meters via `SignatureChecker::flushTxSigCacheCounts`, confirming they are observability counters.

### Why It Failed

The inefficiency is real but below the optimize-soroswap objective severity threshold. The authoritative baseline is about 272.9 ms median soroswap apply time, so Medium requires a reproducible 3-10% reduction, roughly 8.2-27 ms per ledger. The diagnostic counts imply about 82,981 tracked `verifySig` events over the trace, consistent with roughly 1.2k signature-cache lookups per ledger for the 71-ledger run documented by nearby signature-check hypotheses. Removing one process-global metrics mutex around two integer counters for that lookup volume cannot plausibly save 8+ ms per ledger: even a pessimistic 1 us per update is only about 1.2 ms/ledger, and more realistic uncontended or short-contention lock costs are substantially lower. The full 9.208 ms longest-window `checkSignature` self-time cannot be attributed to this metrics mutex because it includes required validation work and the existing sharded verification-cache mutex that the proposed batching does not remove.

Because this objective accepts only Medium and High findings, a real but Low/sub-1% metrics batching opportunity must be marked NOT_VIABLE rather than downgraded and promoted.

### Lesson Learned

For apply-path signature-validation hypotheses, distinguish the complete `checkSignature` zone from the specific removable operation inside it. Observability counters are safe optimization targets, but per-signature counter batching needs either millions of calls per ledger or narrow instrumentation proving multi-microsecond contention before it can clear the soroswap Medium floor.
