# H036: Coalesce verifySigCacheKey BLAKE2 Three-add Prelude into Single Update

**Date**: 2026-05-20
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`verifySigCacheKey` (`src/crypto/SecretKey.cpp:73-84`) derives the
`gVerifySigCacheShards` lookup key from `(public_key || signature ||
message)`. The expected behavior is that the cache key is built with the
minimum number of libsodium `crypto_generichash_update` calls — ideally
one, when the inputs are small and contiguous-able — to minimise per-call
dispatch overhead on the apply-path verifySig prelude.

## Mechanism

The current implementation issues three sequential `BLAKE2::add(...)`
calls — one for the 32-byte `key.ed25519()`, one for the 64-byte
`signature`, and one for the variable-length `bin` message slice. Each
`add()` flows through `XDRHasher::queueOrHash` and ultimately
`crypto_generichash_update`, which performs an internal block-buffering
copy and (if a 64-byte block boundary is crossed) a compression round.
For typical apply-path inputs (~108 bytes total: 32 pub + 64 sig + 12-byte
contents-hash digest), the work could be coalesced by stack-buffering the
prelude into a single 96+N-byte array and calling
`crypto_generichash` (one-shot) once. The deviation from "minimum
update calls" is small: on the order of two `crypto_generichash_update`
dispatches and an extra block-buffer split per verify.

## Trigger

Apply path verifySig invocations during `processSignatures` /
`checkAllTransactionSignatures` — every soroswap tx triggers one
verifySig per signature, and the BLAKE2 cache-key prelude runs even on
cache hits.

## Target Code

- `src/crypto/SecretKey.cpp:73-84` — `verifySigCacheKey` with three
  `BLAKE2::add` calls
- `src/crypto/BLAKE2.cpp` — `BLAKE2::add` and the underlying
  `crypto_generichash_update` dispatch
- `src/crypto/XDRHasher.h` — `queueOrHash` buffer logic that backs the
  `add` path

## Evidence

- The cache-key prelude runs on every apply-path verifySig including
  cache hits (since the BLAKE2 hash *is* the cache key).
- libsodium's `crypto_generichash_update` performs an internal copy into
  a 64-byte block buffer per call; coalescing reduces dispatch and the
  associated Tracy `BLAKE2::add` zone overhead.
- Per H022's source review, the prelude is a measurable fraction of
  per-verify cost.

## Anti-Evidence / Why It Failed

- **Meta-Pattern 5 (verifySig + BLAKE2 apply-path ceiling <0.2%)**: the
  apply-path share of `verifySig` work is bounded by `processSignatures`
  + `checkAllTransactionSignatures` ≈ 46 ms across the full 65-ledger
  soroswap run (~0.7 ms/ledger ≈ <0.2% of apply median). The BLAKE2
  cache-key prelude is a fraction of that already-sub-0.2% envelope.
  Coalescing three updates into one cannot reach the 1% Low floor, let
  alone the 3% Medium floor required by this objective.
- H022 (cache the BLAKE2 result on `TransactionFrame`) was already
  rejected for the same ceiling, eliminating the *entire* prelude cost.
  H033 (replace BLAKE2 with SipHash) targets the same prelude cost via a
  different mechanism and was also rejected. This hypothesis recovers
  strictly less than either, since it only removes dispatch overhead and
  leaves the BLAKE2 compression rounds in place.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PARTIAL — H022 caches the entire BLAKE2 result on
`TransactionFrame`; H033 replaces BLAKE2 with SipHash; this proposal is
distinct (coalesce the existing BLAKE2 calls into a single update) but
strictly weaker than both, and falls under the same Meta-Pattern 5
ceiling that already rejected them.

### Why It Failed

Per Meta-Pattern 5, the apply-path verifySig share is structurally
capped below 0.2% of apply time. Coalescing three BLAKE2 updates into
one removes only libsodium dispatch overhead at one site within that
already-sub-0.2% envelope, recovering a fraction of a fraction. Even
generous assumptions cannot reach the 1% Low floor; the proposal is
two orders of magnitude below the 3% Medium threshold this objective
requires.

### Lesson Learned

The Meta-Pattern 5 ceiling bounds *all* sub-optimisations within the
apply-path verifySig zone — including dispatch-coalescing micro-fixes,
prelude relocation, and any other in-zone work. Future verifySig /
BLAKE2 hypotheses must cite a callsite that lies *outside* the
`processSignatures` / `checkAllTransactionSignatures` envelope (e.g., a
re-verification path triggered later in apply that bypasses the cache
shard, or a callsite reachable via a non-tx-signature code path inside
`closeLedger`).
