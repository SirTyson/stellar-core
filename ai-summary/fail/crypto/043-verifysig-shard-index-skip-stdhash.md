# H043: Skip `std::hash<Hash>` SipHash for `verifySig` Shard Index

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (sub-1%)
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` (`src/crypto/SecretKey.cpp:469-520`) selects which of
the 16 cache shards to lock by hashing the BLAKE2-derived `cacheKey`:

```cpp
auto shardIdx = std::hash<Hash>{}(cacheKey) % NUM_VERIFY_CACHE_SHARDS;
```

The expected efficient implementation should not run a second hash function
over a value that is already a uniform 32-byte cryptographic hash. Reading 8
bytes of `cacheKey` directly (e.g. `*reinterpret_cast<uint64_t const*>(cacheKey.data()) & 0xF`)
yields a uniform shard index for free, since BLAKE2 output is already
indistinguishable from random.

## Mechanism

`std::hash<Hash>` is specialized in `xdr/Stellar-types.h` /
`util/HashOfHash.h` to call `shortHash::xdrComputeHash` (SipHash-2-4) over the
32-byte XDR-padded array. That is one full SipHash invocation per `verifySig`
call — including a `gKeyMutex`-protected key fetch (`shortHash::computeHash`
sets `gHaveHashed` under lock) — to derive 4 bits of shard index. The actual
behavior is a redundant cryptographic hash of an already-cryptographic hash,
plus the `gKeyMutex` round-trip, before the real verification work begins.

## Trigger

Every Soroban transaction signature check during apply hits this line. The
soroswap benchmark drives the per-tx signature pipeline (`processSignatures` /
`checkAllTransactionSignatures`) with one cache probe per signature.

## Target Code

- `src/crypto/SecretKey.cpp:483` — `std::hash<Hash>{}(cacheKey) % NUM_VERIFY_CACHE_SHARDS`
- `src/crypto/ShortHash.cpp:computeHash` — `gKeyMutex`-protected SipHash entry
- `util/HashOfHash.h` — `std::hash<Hash>` specialization

## Evidence

- The `cacheKey` is the output of BLAKE2 (`verifySigCacheKey`,
  `src/crypto/SecretKey.cpp:74-84`). It is already a uniform pseudo-random
  32-byte digest.
- `std::hash<Hash>` resolves to `shortHash::xdrComputeHash` (SipHash-2-4)
  with `gKeyMutex` acquisition for the key (`gHaveHashed` write).
- A direct byte-extract shard index is structurally cheaper and produces
  the same uniform distribution.

## Anti-Evidence

The proposed savings sit entirely inside Meta-Pattern 5's apply-path verifySig
ceiling and are subject to Meta-Pattern 6's index-walk-not-hash conclusion.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — the shard-index `std::hash<Hash>` SipHash call has not
been hypothesized for elimination in any prior crypto investigation (H008,
H009, H021, H034 target the cache probe / verify itself; H011, H025 target
SipHash globally; none touch the shard-index path).

### Why It Failed

This optimization is bounded by **Meta-Pattern 5: Apply-Path verifySig and
BLAKE2 Share Is Below 1%**. The total apply-path work in `verifySig` is
~46ms across 65 ledgers (~0.7ms/ledger ≈ <0.2% of soroswap apply median).
A single SipHash over 32 bytes is a small fraction of one verifySig call —
realistically a few hundred ns each. Even fully eliminating the shard-index
SipHash from every apply-path call returns single-digit percent of <0.2% =
well below the 0.01% noise floor. This cannot reach the 1% Low floor, let
alone the 3% Medium floor required by this objective.

The optimization is also independently bounded by **Meta-Pattern 6**: the
real shard-locking cost is the mutex acquisition and the per-shard `RandomEvictionCache`
probe, not the index derivation.

### Lesson Learned

When a cryptographic hash output is itself the input to a secondary hash,
direct byte extraction is a valid micro-cleanup, but for crypto subsystems
already capped by a verifySig apply-path ceiling (~0.2%), removing the
secondary hash returns a fraction of that ceiling and remains structurally
sub-Low. Any future shard-routing or hash-of-hash hypothesis in this code
should be sized against Meta-Pattern 5, not against the absolute SipHash
cost.
