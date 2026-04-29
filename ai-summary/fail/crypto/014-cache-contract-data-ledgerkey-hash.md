# H014: Specialize `std::hash<LedgerKey>` for CONTRACT_DATA to skip per-lookup XDR SipHash

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`std::hash<LedgerKey>::operator()` for a `CONTRACT_DATA` key should produce a
size_t hash combining the contract address, durability, and key components,
with overhead bounded by a few SipHash rounds and pointer chasing into the
LedgerKey union.

## Mechanism

The `CONTRACT_DATA` case in
`src/ledger/LedgerHashUtils.h:178-185` calls
`shortHash::xdrComputeHash(lk.contractData().key)`, which serializes the
entire SCVal key into the XDRShortHasher buffer and SipHashes it under the
`gKeyMutex`. Each `unordered_map`/`unordered_set` probe of a CONTRACT_DATA
LedgerKey pays this cost. For soroswap, the same pool/balance/instance
SCVal keys are hashed repeatedly across many lookups during apply.
Caching a precomputed SipHash for hot SCVal keys (or storing a precomputed
hash inside `LedgerKey` itself for in-memory containers) could eliminate the
XDR-serialize+SipHash work on each lookup.

## Trigger

Run the soroswap apply-load benchmark with Tracy. Container probes against
`std::unordered_set<LedgerKey>` and `std::unordered_map<LedgerKey, ...>`
during `parallelApply`, `commitChangesToLedgerTxn`, and similar zones
trigger `xdrComputeHash<SCVal>` on each CONTRACT_DATA lookup.

## Target Code

- `src/ledger/LedgerHashUtils.h:178-185` — `CONTRACT_DATA` hash branch
- `src/crypto/ShortHash.cpp` — `shortHash::computeHash` /
  `shortHash::xdrComputeHash` (mutex-locked SipHash)
- `src/transactions/ParallelApplyUtils.cpp:606,464` —
  `unordered_set<LedgerKey>` usage during parallel-apply state init
- `src/ledger/InMemorySorobanState.cpp` — already uses 32-byte TTL hash as
  the set key, bypassing this path

## Evidence

The CONTRACT_DATA hash branch is the only LedgerKey hash variant that
serializes a variable-length XDR object (`SCVal key`) on each call.
Soroswap's apply path repeatedly looks up the same pool, reserve, and
balance keys per swap operation across multiple data structures.
Eliminating the per-lookup SipHash by caching the hash on the LedgerKey
(or by a parallel-array of precomputed hashes) would convert each probe
from "serialize+SipHash+mutex" to a single load.

## Anti-Evidence

This hypothesis is squarely defeated by Meta-Pattern 6 in
`ai-summary/fail/crypto/summary.md`: "In-memory bucket scan cost
(~2.1µs mean) is dominated by `unordered_set` bucket traversal and XDR
equality compare, not by SipHash computation or `gKeyMutex` acquisition.
Eliminating hashing or locking returns a small fraction of scan cost and
cannot reach Medium severity; genuine wins require restructuring the index
data structure."

The dominant per-lookup cost is the XDR `operator==` over the SCVal key
(which must walk the same XDR structure SipHash already walks), not the
hash computation itself. Even if hash caching eliminated the entire
SipHash side of the probe, the equality compare on collision (and on
final match validation) would still dominate. The InMemorySorobanState
contract-data set already side-steps this by keying on the 32-byte
SHA256 TTL hash, so the highest-volume CONTRACT_DATA container does not
even use this hash path. The remaining `unordered_set<LedgerKey>` usages
during parallel-apply init are one-shot per-ledger, not per-operation.

H011 also already covered the gKeyMutex angle and was rejected for the
same reason: total mutex-elimination savings are ~5ms aggregate, far
below the 1% Low floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PARTIAL — the specific angle of caching SCVal-key SipHash on
the LedgerKey itself is not in prior fails, but the underlying SipHash
ceiling is already established by H007/H011 and Meta-Pattern 6.

### Why It Failed

The dominant per-lookup cost in `unordered_set<LedgerKey>` containers is
XDR `operator==` over the SCVal key, which has identical structural
walking complexity to the SipHash. Eliminating the hash side does not
eliminate the equality side. The highest-volume CONTRACT_DATA container
(`InMemorySorobanState`) already keys on a precomputed 32-byte hash and
does not exercise this code path. The remaining containers
(`collectModifiedClassicEntries`, `mergeChangesFromThread`) are one-shot
per ledger / per stage commit, not per-operation, so per-probe savings
are bounded at sub-1% of apply.

### Lesson Learned

Hash-caching schemes for variable-length XDR keys must be justified by
both hash cost AND equality-compare cost — caching only the hash side
leaves the equality work intact and yields at most ~50% of the per-probe
crypto cost, which is already structurally sub-1% per Meta-Pattern 6.
Future LedgerKey-container hypotheses should target restructuring the
container itself (e.g., bypassing XDR with precomputed 32-byte digests
as InMemorySorobanState does) rather than caching the hash in place.
