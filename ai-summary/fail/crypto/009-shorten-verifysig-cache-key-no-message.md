# H009: Shorten verifySig Cache Key by Hashing Only PubKey+Signature, Skip Message Bytes

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium (proposed) → rejected
**Impact**: reduce per-verify BLAKE2 hashing cost on the apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` should compute its cache key cheaply. Because Ed25519
signatures are deterministic (RFC 8032) and a 64-byte signature is itself a
collision-resistant function of `(secret_key, message)`, a cache key of
`BLAKE2(public_key || signature)` (96 bytes input) would be effectively as
strong as the current `BLAKE2(public_key || signature || message)` (96 + |msg|
bytes input). The cache lookup would still be unique-per-distinct
`(pubkey, signature)` pair, and any collision attack would require
forging a second message that produces the same signature under the same key —
infeasible given Ed25519's collision properties.

When the apply path re-verifies a signature it already verified during
tx-set validation, the cache key compute would drop from
`BLAKE2(96 + |msg|)` to `BLAKE2(96)`, eliminating the per-call message-bytes
hash work. Soroban tx envelopes can be hundreds to thousands of bytes, so
removing the message-bytes hash from each apply-path `verifySig` call should
measurably reduce total BLAKE2 work.

## Mechanism

`crypto/SecretKey.cpp:74-84` (`verifySigCacheKey`) currently feeds the entire
message into BLAKE2 alongside pubkey+signature. The marginal cost scales with
`|msg|`. Dropping the message would shave message-byte hashing from every
verify call (cache-hit or cache-miss). Because the apply path executes after
tx-set validation, nearly all apply-path `verifySig` calls hit the cache, so
the cache-key compute itself is the dominant per-call cost on the apply path.

## Trigger

Run `apply-load --mode soroswap` and measure `verifySig` self-time. With
the proposed change, `verifySig` self-time inside `applyLedger` should drop in
proportion to the message-bytes hashing share.

## Target Code

- `src/crypto/SecretKey.cpp:74-84` — `verifySigCacheKey`
- `src/crypto/SecretKey.cpp:469-520` — `PubKeyUtils::verifySig`
- `src/transactions/TransactionFrame.cpp:574-590` — `checkAllTransactionSignatures` (apply caller)
- `src/transactions/SignatureChecker.cpp` — `SignatureChecker::checkSignature`

## Evidence

- Trace `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy` shows
  `verifySig` at 4074 ms self-time, 327 928 calls (mean 12.4 µs).
- Within that, `BLAKE2::add` is 40.5 ms / 983 k calls — the cache-key compute
  feeds three `add()` calls per `verifySig`, so each verify spends ≈120 ns just
  on the BLAKE2 inputs (mostly the message-bytes path).
- The cache is already sharded 16-way (`gVerifySigCacheShards`), so reducing
  cache-key compute is the next mechanically obvious lever after sharding.

## Anti-Evidence

- The vast majority of `verifySig` total time is **outside** `applyLedger`. Per
  prior failure `001-verify-sig-mostly-outside-applyledger.md`, `verifySig` is
  dominated by `commonValidPreSeqNum` and tx-set construction zones, which are
  out of scope for the optimize-soroswap objective.
- Prior failure `008-shard-or-bypass-verifysig-cache-in-apply.md` established
  that even **bypassing the cache lookup entirely** on the apply path is below
  the 3% Medium floor because the apply-path `verifySig` share is small.
  Shrinking the cache-key compute is strictly weaker than bypassing it.
- BLAKE2 over a few hundred bytes is fast (~ns/byte). The marginal saving per
  verify is on the order of 100–300 ns; multiplied by the apply-path verify
  count, the total saving is sub-1%.
- Changing the cache-key shape changes a process-wide cache-hit relationship
  shared with the tx-set-validation path. Any benefit there is out of scope and
  cannot be claimed against the soroswap apply benchmark.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — shrinking the cache-key compute (rather than bypassing the
cache or sharding it) was not previously written up.

### Why It Failed

The apply-path share of `verifySig` work is bounded by
`checkAllTransactionSignatures` invoked from
`commonParallelPreApplyReadOnly` and `commonValid`, which is already small
relative to applyLedger (per fail/008's established ceiling). Even
optimistically removing 100% of the BLAKE2 cache-key compute on the apply
path cannot reach the 3% Medium floor on the soroswap benchmark because the
underlying apply-path verify share is below that ceiling to begin with. The
optimization is also strictly weaker than fail/008's "bypass the cache
probe entirely" alternative, which itself was rejected for the same reason.

### Lesson Learned

Once an entire subsystem zone (apply-path `verifySig`) is shown to be below the
Medium floor, no narrower micro-optimization within that zone can be promoted —
the per-call savings are bounded by the zone's total apply-path cost regardless
of mechanism. Future hypotheses on this surface must either find an apply-path
caller that prior failures did not bound, or target a structurally different
phase of `closeLedger`.
