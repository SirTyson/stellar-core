# H068: OpenSSL One-Shot SHA256 Small-Buffer Dispatch

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — below objective severity threshold)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`sha256(ByteSlice const&)` should use the fastest deterministic SHA256 implementation for the small-to-medium buffers that appear during `closeLedger`. On the soroswap apply path, the expected efficient behavior would be to avoid any avoidable per-call provider dispatch, context setup, or heap traffic while still hashing byte-identical XDR preimages and returning the same 32-byte digest.

## Mechanism

The current implementation in `src/crypto/SHA.cpp:29-39` calls OpenSSL's one-shot `::SHA256` for every `sha256(ByteSlice)` invocation. A possible optimization angle is that many apply-path callers hash small buffers, so OpenSSL one-shot setup/dispatch might be more expensive than a specialized small-buffer path, a retained per-thread `SHA256_CTX`, or a return to libsodium's SHA-NI-selected `crypto_hash_sha256`. If the one-shot wrapper overhead dominated, replacing it could reduce apply time without changing deterministic output.

## Trigger

Run the current soroswap Tracy benchmark from `ai-summary/CURRENT_STATE.md` and timestamp-filter `sha256` events against `applyLedger` windows. In the trace at `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`, `crypto/SHA.cpp:33` has 386,564 events overlapping `applyLedger`, totalling 332,162,675 ns in the Tracy build.

## Target Code

- `src/crypto/SHA.cpp:29-39` — OpenSSL one-shot `sha256(ByteSlice const&)`
- `src/crypto/SHA.cpp:55-80` — streaming `SHA256::reset/add/finish` baseline for alternative implementations
- `src/ledger/LedgerTypeUtils.cpp:31-38` — one-shot SHA256 caller for TTL keys
- `src/transactions/SignatureUtils.cpp:79-90` — hash-X one-shot SHA256 caller family

## Evidence

The target zone is a real `applyLedger` descendant in the current trace: a direct overlap check against all 71 `applyLedger` windows found 386,564 in-apply `sha256` calls and 332 ms of Tracy-build time. The source recently switched from libsodium to OpenSSL (`c39cad021`, "Switch SHA256 from libsodium (pure C) to OpenSSL (SHA-NI hardware accel)"), so the exact provider choice is a current code path rather than stale history. The code path is deterministic and implementation-substitutable as long as it emits the same SHA256 digest.

## Anti-Evidence

This is still a SHA256-only hypothesis. Existing crypto Meta-Pattern 1 says the entire non-Tracy in-apply SHA256 budget is about 4 ms per ledger and below the 1% Low floor; the objective now requires Medium (3-10%) hypotheses. Even taking the current Tracy overlap number at face value, 332 ms across 71 ledgers is about 4.7 ms per ledger, which is only about 2.1% of the current 218 ms soroswap median, and a real implementation cannot eliminate the SHA256 work itself. Existing fail entries H012/H023/H026/H055 already reject SHA implementation/dispatch/context-reuse variants under the same budget ceiling, and Meta-Pattern 7 warns that fine-grained crypto zones are inflated by Tracy instrumentation absent from non-Tracy benchmark verdicts.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — OpenSSL one-shot small-buffer provider overhead after the OpenSSL switch was not previously recorded as its own investigation

### Why It Failed

The optimization surface is bounded by the global SHA256 budget ceiling. The complete apply-contained `sha256` one-shot work is below the Medium floor even under the optimistic Tracy overlap number, and provider/dispatch/context changes can only remove a fraction of that work.

### Lesson Learned

After the OpenSSL switch, SHA provider selection is still not a viable soroswap Medium target. Future crypto hypotheses should not target SHA256 wrapper/provider/context mechanics unless a new non-Tracy benchmark shows SHA256 alone exceeding the 3% objective floor.
