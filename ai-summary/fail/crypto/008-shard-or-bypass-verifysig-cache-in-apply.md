# H008: Bypass `gVerifySigCache` BLAKE2 Cache-Key Computation for Apply-Path Signature Re-Verification

**Date**: 2026-04-28
**Subsystem**: crypto
**Severity**: Medium (projected, before review)
**Impact**: avoid redundant BLAKE2 cache-key construction and shard
mutex acquisition for signature verifications that occur during
`commonPreApply` / `commonParallelPreApplyReadOnly` re-validation in
soroswap apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a transaction's signatures have already been verified during
tx-set validation (and cached in `gVerifySigCacheShards`), the apply
path should not pay the cost of (a) BLAKE2-hashing the
`(public_key || signature || message)` triple to construct a cache
lookup key, (b) hashing the lookup key again to pick a shard, and
(c) acquiring the shard mutex, just to re-confirm a known result. A
sticky per-tx "signatures already verified this round" flag (or a
direct signature-set fast path on the `TransactionFrame`) would let
apply skip the cache probe entirely.

## Mechanism

In `PubKeyUtils::verifySig`
(`src/crypto/SecretKey.cpp:469-494`), every call computes
`verifySigCacheKey` (a fresh BLAKE2 over key+sig+msg), then
`std::hash<Hash>{}(cacheKey) % NUM_VERIFY_CACHE_SHARDS` to pick a shard,
then takes a `std::mutex` to probe the cache. During apply,
`commonPreApply` / `commonParallelPreApplyReadOnly` re-run
`SignatureChecker` on every operation/source/extra signer
(`processSignatures,transactions/TransactionFrame.cpp:1588` is 14.9 ms
self over 36,909 calls during apply; `checkAllTransactionSignatures`
TransactionFrame.cpp:578 is 31.2 ms self / 187,782 calls). Each
internally hits `verifySig` cache probes whose results are already
known to be `true` from tx-set validation. The hypothesis was: stamp
the `TransactionFrame` (or pass a "pre-verified" flag through
`SignatureChecker::checkSignature`) once tx-set validation has
confirmed all sigs, and have the apply-path checker skip the cache
probe.

## Trigger

Run the soroswap apply-load benchmark and inspect `verifySig` and
`processSignatures` zones inside `applyLedger` descendants. Each
successful Soroban transaction triggers re-verification on entry to
the apply helpers.

## Target Code

- `src/crypto/SecretKey.cpp:469-494` — `PubKeyUtils::verifySig` cache
  key + shard probe.
- `src/crypto/SecretKey.cpp:74-84` — `verifySigCacheKey` BLAKE2 over
  key+sig+msg (per call).
- `src/transactions/TransactionFrame.cpp:1588` — `processSignatures`
  during apply.
- `src/transactions/TransactionFrame.cpp:2073-2185` — `commonPreApply`
  and `commonParallelPreApplyReadOnly` construct fresh
  `SignatureChecker` per tx during apply.
- `src/transactions/SignatureChecker.cpp` — fanout into
  `PubKeyUtils::verifySig`.

## Evidence

- `verifySig,crypto/SecretKey.cpp:473` is the largest single self-time
  zone in the trace (6.22 s, 515,928 calls), but the apply share is
  bounded by `processSignatures` (14.9 ms self) +
  `checkAllTransactionSignatures` (31.2 ms self) +
  `checkSignature,transactions/TransactionFrame.cpp:504` (270 ms self
  / 515,928 calls — most of which is tx-set validation, not apply).
- `add,crypto/BLAKE2.cpp:50` is 58 ms self / 1.55M calls — the
  cache-key construction in every `verifySig`.
- `getContentsHash` is 133 ms / 633K calls (~204K of which overlap
  apply windows per H005 timestamp analysis), confirming the apply
  path performs many signature-related operations even for already-
  validated signatures.

## Anti-Evidence

- The total apply-window signature work (`processSignatures` 14.9 ms
  + `checkAllTransactionSignatures` 31.2 ms = 46 ms over the run)
  spread across 65 ledgers is ~0.7 ms per ledger out of a 596 ms
  median — well under 0.2% of apply time. Even fully eliminating
  every cache probe in apply cannot clear the Low (1%) floor, let
  alone the Medium (3%) floor.
- The BLAKE2 work in apply is bounded by the same proportional share:
  if 1.55M total `BLAKE2::add` calls produce 58 ms, then the 200K-ish
  apply-window calls produce ~7-8 ms — sub-0.1% of apply.
- The shard mutex acquisitions in apply are read-only cache hits;
  with `NUM_VERIFY_CACHE_SHARDS` distributing contention, the per-call
  lock cost is in the tens of nanoseconds — already well-amortized.
- A "pre-verified" flag on `TransactionFrame` adds state coupling
  between tx-set validation and apply, complicating correctness
  reasoning for fee-bump and inner transaction signer paths, in
  exchange for a sub-1% win.
- Crypto fail H001 already established that signature verification is
  mostly outside `applyLedger` and that targeting the cache for apply
  alone is structurally capped below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — bypassing the verify-sig cache probe (rather than
optimizing the verify itself) for already-validated apply-path
signatures was not investigated in prior crypto fail/hypothesis/
reviewed/poc records.

### Why It Failed

The apply-path share of `verifySig` work is bounded by the
`processSignatures` and `checkAllTransactionSignatures` zones, which
together consume well under 50 ms across the entire 65-ledger
soroswap run — far below 1% of the 596 ms median apply window. The
BLAKE2 cache-key + shard mutex overhead inside that work is a small
fraction of an already-tiny share. No restructuring of the cache
path can yield a Medium-tier soroswap apply-time improvement.

### Lesson Learned

The signature-verification meta-pattern from H001 generalizes: any
optimization targeting `verifySig`, its cache key, its shard mutex,
or its dispatch — when restricted to the apply window — is
structurally capped below the Medium severity floor for soroswap.
Future crypto-subsystem hypotheses must demonstrate that the targeted
zone has measurable wall-clock presence inside `applyLedger`
descendants, not just process-wide self-time.
