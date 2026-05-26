# H082: Signature Cache Metrics Mutex Coalescing Is Below Threshold

**Date**: 2026-05-26
**Subsystem**: crypto / transactions
**Severity**: Low
**Impact**: apply-path signature-cache metric counter overhead below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `closeLedger`, signature-cache metric accounting should not measurably serialize otherwise-parallel signature validation. Replacing the global `SignatureChecker::gCheckValidOrApplyTxSigCacheMetricsMutex` with relaxed atomics or per-thread counters should preserve the reported `(hits, lookups)` values modulo scrape timing while reducing soroswap apply time only if metric-counter locking is a meaningful descendant of `applyLedger`.

## Mechanism

`SignatureChecker::checkSignature` calls `updateTxSigCacheMetrics` after every Ed25519 and signed-payload verification result. That helper takes a process-wide mutex and updates two `uint64_t` counters, so a tempting optimization is to make these counters lock-free or worker-local and avoid a contended lock from parallel pre-apply/signature paths. The actual deviation from expected Medium impact is that all apply-path signature verification work is already structurally tiny for soroswap cache-hit validation.

## Trigger

Run the current soroswap apply-load Tracy trace from `ai-summary/CURRENT_STATE.md` and timestamp-filter `verifySig`, `checkSignature`, `processSignatures`, and `checkAllTransactionSignatures` against `applyLedger` windows. The metric-lock helper is not separately zoned, but it is reached from Ed25519 checks that produce `VerifySigCacheLookupResult::HIT` or `MISS`.

## Target Code

- `src/transactions/SignatureChecker.cpp:117-124` — Ed25519 verification path calls `SignatureUtils::verify` and then `updateTxSigCacheMetrics`.
- `src/transactions/SignatureChecker.cpp:130-136` — signed-payload verification does the same metric update.
- `src/transactions/SignatureChecker.cpp:186-203` — `updateTxSigCacheMetrics` takes the global mutex and increments hit/lookup counters.
- `src/transactions/SignatureChecker.h:60-70` — mutex/counter declarations.
- `src/crypto/SecretKey.cpp:469-520` — underlying `PubKeyUtils::verifySig` cache lookup result producer.

## Evidence

The current diagnostic trace has apply-window overlap for the signature path: `verifySig` appears 82,981 times inside `applyLedger` windows with about 43.7 ms total event duration, while `checkSignature` contributes about 122.3 ms across the same 71-ledger trace. Source review confirms every non-`NO_LOOKUP` verification result takes a separate mutex in `updateTxSigCacheMetrics`, so a lock-free counter implementation would be correctness-preserving for metric collection.

## Anti-Evidence

The entire caller is too small. The crypto failure summary's Meta-Patterns 5 and 10 already bound apply-path `verifySig` below 0.2% of apply and reject all narrower verification-cache micro-optimizations. In the current trace, even unrealistically eliminating all `verifySig` overlap would save only about 0.62 ms per ledger, and eliminating the whole `checkSignature` overlap would save about 1.72 ms per ledger before accounting for parallel-worker normalization, well below the 3% Medium floor for the ~207.6 ms baseline. The mutex counter is only a fraction of those already-sub-threshold zones.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — prior records cover verifySig cache atomics, cache mutexes, BLAKE2 keys, and signature proof reuse, but not the separate `SignatureChecker` metric mutex.

### Why It Failed

The metric mutex is nested inside an apply-path signature-validation surface that is already below Low severity for soroswap. A lock-free metric counter would be safe and tidy, but the maximum possible apply-time reduction is bounded by the existing verifySig/checkSignature ceilings and cannot reach the objective's Medium threshold.

### Lesson Learned

For signature-adjacent optimizations, size the complete apply-contained caller first. If the full verification path is below threshold, metric accounting, counters, and lock reshaping inside that path cannot become viable on their own.
