# H025: Replace SipHash with a faster non-crypto hash (xxh3/wyhash) for in-memory `unordered_map`/`unordered_set<LedgerKey>` lookups in apply

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low (sub-threshold)
**Impact**: Apply-time micro-optimization (rejected: below objective floor)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In-memory hash containers used during apply (e.g., `InMemoryBucketState`'s
`unordered_set<InternalInMemoryBucketEntry>`, the `LedgerHashUtils`
specializations consumed by `LedgerTxn` mod-tracking maps, and the
`std::unordered_map<LedgerKey, ...>` instances inside
`InMemorySorobanState` / `ParallelApplyUtils`) should hash each lookup
key in roughly one to two cycles per byte, with no global lock.

## Mechanism

`src/crypto/ShortHash.cpp:34-43` — `shortHash::computeHash` calls
libsodium's `crypto_shorthash` (SipHash-2-4) and grabs `gKeyMutex`
first to set the `gHaveHashed` flag. SipHash-2-4 is a cryptographic
PRF designed to defeat hash-flooding adversaries; it is notably
slower than non-crypto hashes (xxh3, wyhash, ahash). For
*in-memory*, *single-process*, non-adversarial hash containers used
inside apply, the cryptographic property is unnecessary, and the
mutex-guarded keyed initialization can be replaced with a faster
unkeyed/seedless hash. Replacing SipHash with xxh3 for these
specific containers (keeping SipHash for any container exposed to
external/untrusted input) would skip both the mutex and the slower
ARX rounds.

The deviation from expected: the apply path pays for cryptographic
hash flood resistance on every `unordered_set`/`unordered_map` probe
where it is not needed, and additionally pays for the
`gKeyMutex`-guarded `gHaveHashed` flag set on every call.

## Trigger

A soroswap apply ledger performs many CONTRACT_DATA / TTL key probes
into `InMemoryBucketState::scan` and into `InMemorySorobanState`'s
`unordered_map`s. Each probe pays a SipHash + mutex cost.

## Target Code

- `src/crypto/ShortHash.cpp:34-50` — `computeHash` and
  `xdrComputeHash` entry points.
- `src/util/HashOfHash.h` and `src/ledger/LedgerHashUtils.h:178-185`
  — apply-path hash function specializations.
- `src/bucket/InMemoryIndex.cpp` (`InMemoryBucketState` lookup
  surface).

## Evidence

- xxh3 and wyhash are well-known to be 4-10x faster than SipHash
  on small keys.
- The current SipHash backend has a documented mutex on `gKey`
  read; H011 explored eliminating that mutex.
- Soroswap's per-ledger lookup volume is high (hundreds of
  CONTRACT_DATA probes plus per-tx footprint resolution).

## Anti-Evidence

- Meta-Pattern 6 ("In-Memory Bucket Scan Cost Is Index Walk, Not
  Hash"): the dominant scan cost is `unordered_set` chain walk plus
  XDR `operator==`, not hash computation; even removing the hash
  step entirely returns a small fraction of scan time.
- Meta-Pattern 5: apply-path BLAKE2/SipHash share is structurally
  below 1%.
- H011 already showed that even removing `gKeyMutex` entirely
  yields ~5 ms aggregate wall time, far below 1%; replacing the
  algorithm is bounded by the same surface.
- The `std::hash<uint256>` path used for the most common
  `SC_ADDRESS_TYPE_CONTRACT` half is already a cheap inline 64-bit
  load and does not go through `shortHash` at all (per H024
  analysis), so the realistic SipHash-replacement impact is on the
  SCVal half only — bounded further.
- Algorithm substitution introduces a new dependency
  (xxh3/wyhash/ahash) and a maintenance surface for crypto-vs-fast
  hash separation across the codebase. Risk-vs-reward is poor at
  sub-1% projected impact.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis (self-rejected during analysis)
**Novelty**: PASS — distinct from H007/H011 (cache-on-prefetch /
mutex-removal at the same SipHash callsite) and from H024
(SCAddress-component cache); this targets the algorithm itself.

### Why It Failed

Meta-Pattern 6 caps the achievable gain: the dominant per-probe
cost in `unordered_set<LedgerKey>` and `unordered_map` containers
is XDR `operator==`, not the hash function. Replacing SipHash with
xxh3 leaves the equality side untouched, so the recovered share is
a fraction of an already-sub-1% slice. H011 confirmed empirically
that the *entire* SipHash + mutex path is ~5 ms aggregate across
the run; a faster hash recovers a fraction of that. Below the 3%
Medium severity floor by an order of magnitude.

### Lesson Learned

For in-memory hash-map optimizations on the apply path, treat the
hash function as already-fast-enough. Genuine wins require
restructuring the container's key shape so that BOTH hash AND
equality become cheap byte-buffer operations (e.g., precomputing
canonical serialized bytes once on insert). Algorithm substitution
on the hash side alone is bounded by Meta-Pattern 6 and cannot
reach Medium severity.
