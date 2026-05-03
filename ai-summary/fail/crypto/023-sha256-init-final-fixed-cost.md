# H023: Skip `SHA256_Init` per-instance cost via lazy/inline init for short apply-path SHA256 streams

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low (sub-threshold)
**Impact**: Apply-time micro-optimization (rejected: below objective floor)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each short streaming SHA256 hash on the apply path (TTL key derivation,
`subSha256` PRNG sub-seed, `txResultSet` interim states, header hash) should
incur only the unavoidable SHA-NI compression rounds for its payload, not a
full per-instance OpenSSL `SHA256_Init` round (which initializes the 8x32-bit
H state and zeros the 64-byte block buffer + counters in the 112-byte
`SHA256_CTX`).

## Mechanism

`src/crypto/SHA.cpp:50-60` — `SHA256::SHA256()` calls `reset()` which calls
`SHA256_Init(ctx)`. For short, fixed-shape inputs (e.g., the 36-byte LedgerKey
preimage for a TTL key, or the 8-byte counter in `subSha256`), the Init step
zeroing/seeding the 112-byte context is non-trivial relative to the actual
single SHA-NI block this work compresses. A specialized one-shot path that
fuses Init + a single SHA-NI block + Final without exposing the streaming
class would skip the separate Init store/zero pass.

## Trigger

Each soroswap apply ledger derives many TTL keys (one per CONTRACT_DATA
footprint entry), each constructing a fresh `SHA256` and calling
`SHA256_Init`. Soroban's `subSha256` is also called per-tx for PRNG
sub-seeding.

## Target Code

- `src/crypto/SHA.cpp:50-86` — `SHA256` class Init/Update/Final wrappers.
- `src/crypto/SHA.cpp:42-48` — `subSha256` constructs `SHA256` per call.
- `src/transactions/TransactionUtils.cpp` (`getTTLKey`) — per-CONTRACT_DATA
  TTL key derivation.

## Evidence

- The new OpenSSL backend (commit `c39cad021`) brought SHA-NI hardware
  acceleration but kept the streaming class shape intact, so `SHA256_Init`
  still runs once per streaming hasher.
- 112-byte context size is not free to zero/seed even on modern CPUs.
- ~thousands of TTL key derivations and per-tx sub-seeds per ledger.

## Anti-Evidence

- Meta-Pattern 1 ("SHA256 Budget Ceiling"): the entire in-apply SHA256
  budget for soroswap is ~4 ms / ledger ≈ 0.67% of apply. Any portion
  attributable to the Init step alone is a small fraction of that
  ceiling — well under 0.1%.
- Meta-Pattern 7 ("Tracy Overhead Inflates Crypto Self-Times"): the
  apparent per-Init cost in Tracy traces includes ZoneScoped overhead,
  not a real production cost.
- The `sha256()` free function already calls one-shot `::SHA256()` for
  the cases where streaming is unnecessary; the streaming form is used
  precisely when fields are appended in pieces (e.g., `getTTLKey` adds
  the LedgerKey via xdrpp archive into the hasher rather than
  pre-serializing).
- H012 already considered replacing the streaming class with one-shot
  for short callers and was rejected at the same SHA256 ceiling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis (self-rejected during analysis)
**Novelty**: PASS — distinct angle from H012 (which targeted full streaming
class replacement), but bounded by the same Meta-Pattern 1 ceiling.

### Why It Failed

The total in-apply SHA256 budget for soroswap is structurally capped at
~0.67% of apply time (Meta-Pattern 1). The `SHA256_Init` portion alone is
a small fraction of that — even a hypothetical zero-cost Init implementation
would yield well below the 1% Low floor and far below the 3% Medium minimum
required by this objective. The Init cost is also inherent to OpenSSL's
streaming API contract; eliminating it would require switching to a custom
inline assembly SHA-NI path, which contradicts the recent decision to
delegate to OpenSSL precisely so the project does not maintain hand-rolled
crypto.

### Lesson Learned

Sub-decompositions of the SHA256 streaming class (Init alone, Update alone,
Final alone) inherit the same 0.67% apply ceiling as the class itself.
Future SHA256-side hypotheses must demonstrate a callsite that escapes this
ceiling — e.g., a previously-uncounted SHA256 caller reachable from
`closeLedger` whose call frequency is materially higher than the known
TTL-key / subSha256 / header / txResultSet sites.
