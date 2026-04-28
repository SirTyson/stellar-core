# H005: Reuse Threaded Transaction Contents Hashes in Apply Validation

**Date**: 2026-04-28
**Subsystem**: crypto / transactions
**Severity**: Low
**Impact**: reduce cached transaction-hash accessor overhead in soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `closeLedger`, Soroban apply should use the already-computed transaction contents hash when constructing `SignatureChecker` instances and passing hashes across pre-apply/apply helpers. The contents hash must remain exactly the same hash that signatures and pre-auth signers validate against, but apply should avoid repeated cache-hit calls to `TransactionFrame::getContentsHash()` when the caller has already threaded the hash through the function parameters.

## Mechanism

`TransactionFrame::preParallelApply`, `preParallelApplyReadOnly`, and `apply` already accept or pass an `envelopeContentsHash`, but `commonPreApply` and `commonParallelPreApplyReadOnly` ignore that parameter when constructing `SignatureChecker` and call `getContentsHash()` again. The current Tracy profile shows `getContentsHash,transactions/TransactionFrame.cpp:135` with 133.577 ms process-wide self-time across 633,198 calls, and timestamp overlap with `applyLedger` windows shows this accessor is called heavily while apply is active. Replacing the inner calls with the threaded `envelopeContentsHash` would remove some cache-hit hashing accessor and Tracy-zone overhead without changing cryptographic results.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and inspect the Tracy trace from `ai-summary/CURRENT_STATE.md`. The relevant path triggers when each Soroban transaction enters read-only pre-parallel apply or sequential apply and constructs a `SignatureChecker` for validation.

## Target Code

- `src/transactions/TransactionFrame.cpp:133-158` — `TransactionFrame::getContentsHash()` lazily computes and then returns the cached SHA256 contents hash.
- `src/transactions/TransactionFrame.cpp:2073-2143` — `commonPreApply` receives `envelopeContentsHash` but constructs `SignatureChecker` with `getContentsHash()`.
- `src/transactions/TransactionFrame.cpp:2145-2185` — `commonParallelPreApplyReadOnly` receives `envelopeContentsHash` but constructs `SignatureChecker` with `getContentsHash()`.
- `src/transactions/TransactionFrame.cpp:2251-2268` and `src/transactions/TransactionFrame.cpp:2696-2760` — callers already thread `getContentsHash()` into the apply helpers.

## Evidence

The code contains a clear redundant accessor pattern: `envelopeContentsHash` is passed to `commonValid`, but the adjacent `SignatureChecker` construction still calls `getContentsHash()`. The current trace's self-time export includes `getContentsHash` at 133.577 ms across the whole soroswap run, and an exact timestamp-overlap check against the 65 `applyLedger` intervals found 204,725 `getContentsHash` events whose execution lay inside those intervals. This is a crypto/hash boundary because `SignatureChecker` uses the contents hash for Ed25519 signature and pre-auth signer verification.

## Anti-Evidence

The accessor is cache-backed, so this does not remove SHA256 work after the first call per transaction. The crypto failure summary already establishes a hard ceiling for SHA256-only optimizations, and this narrower change removes only cache-hit accessor/profiler overhead, not host execution or BucketList writes. Some of the timestamp-overlapped events may also be concurrent tx-set construction rather than descendants of `applyLedger`, so the measurable wall-clock win is likely below the objective's 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — this exact threaded-hash accessor reuse was not listed in crypto fail/hypothesis/reviewed/poc records

### Why It Failed

The redundant calls are real, but they are cache hits around an already-computed hash. Even if every apply-path `getContentsHash()` cache hit were eliminated, the expected savings are dominated by accessor and Tracy instrumentation overhead and do not plausibly clear the optimize-soroswap Medium severity floor.

### Lesson Learned

When a contents-hash path is hot in Tracy, distinguish cold SHA256 computation from cache-hit accessor calls. Threading cached hashes is a clean micro-optimization, but cached hash accessors alone are not a Medium-tier soroswap apply bottleneck.
