# H031: LedgerTxn::EntryMap Rehash-Burst SipHash Recompute During Apply

**Date**: 2026-05-05
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerTxn::Impl::mEntry` (`UnorderedMap<InternalLedgerKey, LedgerEntryPtr>`,
`src/ledger/LedgerTxnImpl.h:91-97`) holds the in-flight modified-entry map
for a child `LedgerTxn` during apply. When the std::unordered_map's load
factor is exceeded, the container rehashes every key — re-running
`std::hash<InternalLedgerKey>` (which dispatches to `shortHash::xdrComputeHash`
SipHash for non-`SC_ADDRESS_TYPE_CONTRACT` keys per H024 lesson) on every
existing entry. The expected behavior is that bulk insertions into `mEntry`
over a soroswap apply call do NOT trigger repeated rehashes, because the map
is reserved up-front to its final size before insertion.

## Mechanism

If `mEntry` were filled incrementally without `reserve()`, each rehash event
would re-SipHash every key already present. For a soroswap ledger with
~thousands of dirty entries, naive growth from 0 would trigger ~log2(N)
rehash events with N total work each — order-of-magnitude more SipHash
invocations than steady-state lookups. This rehash burst is structurally
distinct from the per-lookup SipHash already bounded by H011/H024/H025/H028,
so the established Meta-Pattern 6 ceiling does not directly apply: it would
be a one-shot growth-driven amplification rather than a steady-state lookup
cost. Self-rejected after verifying that the production code already calls
`mEntry.reserve(newSize)` from `prepareNewObjects`
(`src/ledger/LedgerTxn.cpp:2649-2662`), which is invoked before bulk
insertion paths populate the map. With the reservation in place, no
rehash burst occurs and there is no SipHash amplification beyond the
steady-state per-insert cost already covered by Meta-Pattern 6.

## Trigger

Apply soroswap ledgers (TX=2000, T=8) and observe whether `mEntry`'s
internal bucket count grows during the apply call (which would indicate
unreserved growth and a rehash-burst SipHash amplification).

## Target Code

- `src/ledger/LedgerTxnImpl.h:91-100` — `EntryMap` typedef and `mEntry`,
  `mActive` declarations
- `src/ledger/LedgerTxn.cpp:2640-2662` — `prepareNewObjects` reserve call
- `src/ledger/LedgerTxn.cpp:2480-2540` — `updateEntry` insertion path
  (the high-volume insert site during apply)
- `src/crypto/ShortHash.cpp` — `xdrComputeHash` SipHash entry point
  reached by `std::hash<InternalLedgerKey>`

## Evidence

- `mEntry` is a SipHash-keyed `UnorderedMap` over variable-length
  `InternalLedgerKey` values; rehash work scales with N × per-key SipHash.
- Soroswap touches thousands of dirty entries per ledger, so an unreserved
  map would experience multiple rehash events per apply.
- Rehash-burst SipHash is a different cost shape than the steady-state
  per-lookup cost bounded by Meta-Pattern 6.

## Anti-Evidence

- `LedgerTxn::Impl::prepareNewObjects` (`src/ledger/LedgerTxn.cpp:2649-2662`)
  explicitly calls `mEntry.reserve(newSize)` to size the map before bulk
  insertions, eliminating the rehash burst.
- `commit()`/`maybeUpdateLastModifiedThenInvokeThenSeal` paths
  (`src/ledger/LedgerTxn.cpp:1427,1482,1703`) similarly `reserve` their
  output containers based on `mEntry.size()` before copying.
- Even if a rehash event slipped through, per-key SipHash on the dirty
  entry set is bounded by Meta-Pattern 6 — the dominant cost in
  rehash-then-lookup is the equality compare on collision, not the
  hash function itself.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — H011/H024/H025/H028 bounded steady-state per-lookup
SipHash on `LedgerKey`/`InternalLedgerKey` containers, but none addressed
the distinct rehash-burst growth-amplification cost shape on `mEntry`.

### Why It Failed

The production `LedgerTxn::Impl::mEntry` is reserved up-front via
`prepareNewObjects` (`LedgerTxn.cpp:2661`) before bulk insertion, so no
rehash burst occurs during apply. The hypothesized SipHash amplification
does not exist in production. Even hypothetically, rehash-driven SipHash
work is bounded by Meta-Pattern 6 (the per-key equality compare dominates
the hash recompute side).

### Lesson Learned

When proposing a hash-function-cost hypothesis on an `UnorderedMap` /
`UnorderedSet`, verify both the steady-state lookup cost (already bounded
by Meta-Pattern 6) and the growth-amplification cost (rehash bursts).
For `LedgerTxn::Impl::mEntry`, the production code already reserves the
container up-front, so growth-amplification SipHash hypotheses are also
ruled out. Future hash-cost hypotheses on apply-path containers must cite
a specific call site that lacks `reserve()` AND is not already covered by
Meta-Pattern 6.
