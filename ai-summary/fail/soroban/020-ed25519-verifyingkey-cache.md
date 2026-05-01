# H020: Cache ed25519 VerifyingKey decompressions across Soroban auth signature verifications

**Date**: 2026-04-30
**Subsystem**: soroban / crypto
**Severity**: Low
**Impact**: Reduce per-signature Edwards-point decompression cost in apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`verify_ed25519_signature_dalek` (`src/rust/src/ed25519_verify.rs:17-40`)
decompresses a 32-byte compressed Edwards point into a `VerifyingKey`
on every call via `VerifyingKey::from_bytes(pk_bytes)`. When the same
public key is used to verify multiple signatures within a single ledger
(e.g., a single signer authorizing multiple invocations across multiple
txs), only the first call should pay the decompression cost. Subsequent
verifications for the same key should reuse the decompressed point
representation.

## Mechanism

`verify_ed25519_signature_dalek` is called from
`PubKeyUtils::verifySig` (`src/crypto/SecretKey.cpp:496-505`) for every
Soroban auth signature that misses the `(pk, sig, msg)` content cache.
For soroswap, every auth signature has a unique message (binds to a
unique nonce + invocation), so the content cache always misses on the
apply path. Each miss therefore re-runs the relatively expensive Edwards
decompression. A per-ledger LRU keyed on the 32-byte public-key bytes
mapping to a cached `VerifyingKey` would skip decompression on repeat
signers.

## Trigger

Run soroswap apply-load. Tracy zone `verify_ed25519_signature_dalek`
shows 32945 invocations totaling 1.86s (18.1% of self-time). Of that,
the Edwards decompression is roughly half the cost; the actual scalar-mult
verification dominates the rest.

## Target Code

- `src/rust/src/ed25519_verify.rs:17-40` — entry point that always decompresses
- `src/crypto/SecretKey.cpp:469-520` — caller, already has content-keyed cache

## Evidence

`verify_ed25519_signature_dalek` is the second-largest applyLedger-resident
zone after `applySorobanStageClustersInParallel`. Reusing the decompressed
key would skip a constant-time-ish point decompression per repeat signer.

## Anti-Evidence

For soroswap the SIGNER set is essentially per-tx (each user signs only
their own swap). With ~2000 txs and ~2 sigs/tx = ~4000 signatures, but
~2000 unique signers, the cache hit rate is roughly 50% AT BEST. Even
assuming decompression is half the per-sig cost, the realistic upper
bound is `0.18 * 0.5 * 0.5 = 4.5%` apply-time reduction — and that
ignores the cache-management overhead (per-call lock + lookup + LRU
eviction) which would erode most of the win.

In reality each user signs ONCE per ledger, so the cache hit rate is
near zero for the dominant soroswap workload. The effective reduction
collapses to <1%, below benchmark noise. Per meta-pattern #5 in
`ai-summary/fail/soroban/summary.md`, signature/SHA-only optimizations
in this subsystem have repeatedly failed to clear the threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — `015-signature-validation-outside-apply.md` covered batching
sigs OUT of apply via TX-set-construction; this is a different angle (per-key
decompression cache during apply itself), but the analysis collapses to
sub-threshold for the same workload reason.

### Why It Failed

For the soroswap workload, signers are essentially unique per transaction —
each user signs their own swap once. The pubkey-keyed decompression cache
would have a near-zero hit rate, putting the realistic reduction below the
benchmark noise floor. Below the objective severity threshold (Low not
accepted at hypothesis stage).

### Lesson Learned

ed25519 decompression caching is only a viable win when the SIGNER set
is much smaller than the SIGNATURE set within a ledger — for example a
heavily-multiplexed protocol where one signing key authorizes many
contract calls across many txs. Soroswap is not such a workload. Future
hypotheses targeting `verify_ed25519_signature_dalek` should either
attack the scalar-mult step (e.g., dalek batch verification with
fall-back-on-failure semantics) or be evaluated against max-sac, not
soroswap.
