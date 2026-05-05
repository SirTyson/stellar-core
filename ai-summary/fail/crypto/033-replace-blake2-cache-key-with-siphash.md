# H033: Replace BLAKE2 verifySig Cache Key with SipHash

**Date**: 2026-05-05
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` should derive the cache lookup key for
`gVerifySigCacheShards` using the cheapest hash that still keeps collisions
acceptably rare. Each call to `verifySigCacheKey` (`SecretKey.cpp:73-84`)
constructs a `BLAKE2` hasher, adds 32 bytes (`key.ed25519()`), 64 bytes
(`signature`), and the message body, then calls `finish()`. For the
on-apply-path callers (transaction signature re-checks during fee processing
and parallel apply prelude) the message body is small and fixed (typically
the transaction contents `Hash` plus the network passphrase digest), so the
cache-key hash work itself is the only fixed-cost prelude on every apply-path
verify, regardless of cache hit/miss.

## Mechanism

BLAKE2b is a 64-byte-block compression function; for the ~108 input bytes
typical here it spends two compression rounds. SipHash-2-4 (already exposed
via `shortHash::computeHash`) compresses 8 bytes per round and would replace
the BLAKE2 prelude with ~14 SipHash compressions — measurably cheaper per
call. The deviation from "cheapest acceptable hash" is small but real on a
hot per-tx path. The optimization would change the cache-key derivation
(SipHash instead of BLAKE2), keeping cache semantics identical.

## Trigger

Each apply-path signature verification (`processSignatures` and
`checkAllTransactionSignatures` descendants of `applyLedger`) executes
`verifySigCacheKey`'s BLAKE2 prelude before probing the shard cache.

## Target Code

- `src/crypto/SecretKey.cpp:73-84` — `verifySigCacheKey` BLAKE2 construction
- `src/crypto/SecretKey.cpp:475-510` — `verifySig` cache probe and verify
- `src/crypto/ShortHash.cpp` — SipHash alternative

## Evidence

BLAKE2 has higher per-byte cost than SipHash; the cache key is internal and
not network-visible, so any 256-bit hash with cryptographic-grade collision
resistance suffices (and a well-keyed SipHash provides enough resistance for
a process-local cache).

## Anti-Evidence

The apply-path verifySig surface is structurally tiny on soroswap.
`processSignatures` + `checkAllTransactionSignatures` together totalled
~46 ms across the 65-ledger soroswap run (~0.7 ms / ledger), and the
BLAKE2 prelude is only one component of that already-tiny envelope. The
prelude itself is ~1–2 µs per call against a per-ledger budget of ~621 ms.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — not previously written as its own file (Meta-Pattern 5
covers the broader ceiling but does not enumerate the BLAKE2-vs-SipHash
substitution specifically).

### Why It Failed

This optimization is structurally bounded by **Meta-Pattern 5** in
`ai-summary/fail/crypto/summary.md`: the apply-path verifySig share is
capped at ~0.2% of apply (~0.7 ms/ledger, ~46 ms across the soroswap run).
The BLAKE2 prelude is only a fraction of that already-bounded envelope —
even total elimination of the prelude returns far less than 0.1% of apply
time, which is well below the 1% Low floor and far below the objective's
Medium 3% threshold. The cache is also already sharded 16 ways (H021), so
mutex/contention savings cannot be stacked on top.

### Lesson Learned

The verifySig apply-path ceiling (Meta-Pattern 5) bounds **all** crypto
prelude work inside `verifySigCacheKey`, including hash-algorithm
substitutions. Future cache-key-shape hypotheses (replacing BLAKE2 with
SipHash, XXH3, SHA-2 truncation, or any other primitive) inherit this
ceiling and cannot reach Medium severity. Reject up-front any verifySig
prelude redesign whose only surface is the existing apply-path verify
zone.
