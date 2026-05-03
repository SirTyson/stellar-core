# H024: Cache `SCAddress` SipHash component on prefetched CONTRACT_DATA `LedgerKey` to skip per-lookup hashing

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low (sub-threshold)
**Impact**: Apply-time micro-optimization (rejected: below objective floor)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The hash for a CONTRACT_DATA `LedgerKey` mixes three components:
`hash(SCAddress)`, `xdrComputeHash(SCVal key)`, and a small int. When the
same `LedgerKey` (or a key that shares the same `SCAddress` contract) is
probed against an `unordered_map`/`unordered_set` repeatedly during a
single soroswap apply (footprint lookup, prefetch resolution, then
read/write paths), the `SCAddress` half should be hashed once per *unique*
SCAddress — not once per *every* LedgerKey lookup that targets that
contract.

## Mechanism

`src/ledger/LedgerHashUtils.h:178-185` (CONTRACT_DATA case of
`std::hash<LedgerKey>`) computes both `std::hash<SCAddress>` (which itself
runs `shortHash::xdrComputeHash` for muxed-account variants and a
`std::hash<uint256>` for contract-id variants) and a SipHash over the
SCVal key. Soroswap's working set has only a handful of unique contract
IDs per swap (the swap router contract, a few token contracts), but
hundreds of CONTRACT_DATA entries per swap. The per-LedgerKey hash
recomputes the SCAddress half for every entry that shares a contract,
even though that half is constant across all of those entries.

This differs from H014 (which proposed caching the full LedgerKey hash on
the `LedgerKey` itself): the angle here is to cache only the `SCAddress`
hash component on a per-contract basis (e.g., a small thread-local LRU)
so consecutive lookups against the same contract reuse the precomputed
half.

## Trigger

A soroswap apply ledger contains many CONTRACT_DATA entries grouped by a
small set of contract addresses (router, swap pair, two underlying
tokens). Each lookup recomputes the SCAddress hash component.

## Target Code

- `src/ledger/LedgerHashUtils.h:102-134` — `std::hash<SCAddress>`
  specialization.
- `src/ledger/LedgerHashUtils.h:178-185` — CONTRACT_DATA branch of
  `std::hash<LedgerKey>`.
- `src/transactions/ParallelApplyUtils.cpp` and
  `src/ledger/InMemorySorobanState` — heavy CONTRACT_DATA lookup sites.

## Evidence

- Soroswap workload has high contract-data fan-out per contract (many
  storage entries per pair contract per swap).
- `std::hash<SCAddress>` already does pointer chasing through an XDR
  union plus either a `std::hash<uint256>` or a SipHash invocation
  (which goes through the `gKeyMutex`).

## Anti-Evidence

- Meta-Pattern 6 ("In-Memory Bucket Scan Cost Is Index Walk, Not Hash"):
  the dominant cost in `InMemoryBucketState::scan` is not hashing but
  `unordered_set` chain walk plus XDR `operator==` over the SCVal key.
  Removing the SCAddress hash component contributes a small fraction of
  per-probe cost.
- `std::hash<uint256>` (the most common contract-id branch) is already a
  cheap inline 64-bit load; it does not go through `shortHash` and does
  not touch `gKeyMutex`. The SipHash mutex cost only applies to the much
  rarer muxed-account SCAddress variant, which soroswap does not
  generate.
- Meta-Pattern 5 + the SHA256/SipHash budget ceilings: total apply-path
  hash work is structurally below 1%; isolating the SCAddress-half of
  the LedgerKey hash recovers a fraction of a fraction.
- A per-thread LRU on SCAddress hashes adds its own probe + branch cost
  per lookup, partially negating the savings; achieving net positive
  speedup is not guaranteed.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis (self-rejected during analysis)
**Novelty**: PASS — distinct from H014 (which proposed caching the full
LedgerKey hash) and from H007/H011 (which targeted the SipHash mutex /
prefetch SipHash caching at the BucketList scan level).

### Why It Failed

Below objective severity threshold. The dominant per-lookup cost in
`unordered_set<LedgerKey>` and `unordered_map` containers used in apply
is XDR `operator==` over the SCVal key (Meta-Pattern 6); the hash is a
much smaller component, and the SCAddress-half of the hash is a smaller
component still. The most common SCAddress branch for soroswap
(`SC_ADDRESS_TYPE_CONTRACT`) already uses an inline `std::hash<uint256>`
that does not go through `shortHash` or any mutex — so the proposed cache
would only help the rarer muxed-account branch which soroswap does not
exercise. Even with optimistic accounting, this is sub-1% of apply.

### Lesson Learned

When proposing a hash-cache on a multi-component XDR key, compute the
share of the *specific* component(s) being cached, not the total hash
cost. For `std::hash<LedgerKey>` the SCAddress component is dominated by
a single inline 64-bit load on soroswap's actual address shape; caching
it cannot move the needle. Future `LedgerKey` hash-side hypotheses
should target the SCVal key half (which is the genuine variable-length
component) AND must offer matching gains on the equality side, per
Meta-Pattern 6.
