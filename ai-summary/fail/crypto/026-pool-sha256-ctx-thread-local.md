# H026: Pool / thread-local-reuse `SHA256_CTX` storage to eliminate per-hasher 112-byte stack-zeroing on apply path

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low (sub-threshold)
**Impact**: Apply-time micro-optimization (rejected: below objective floor)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each apply-path streaming SHA256 hasher (constructed in
`getTTLKey`, `subSha256`, `xdrSha256<T>`, `XDRSHA256` archiver
construction, etc.) should reuse a per-thread cached `SHA256_CTX`
buffer rather than constructing a fresh 112-byte `mState` array on
every call and re-running `SHA256_Init` (which writes the 8x32-bit
H constants and zeros 64 bytes of block buffer + 8 bytes of
length).

## Mechanism

`src/crypto/SHA.h` declares `SHA256` with an inline 112-byte
`mState[112]` aligned storage that holds the OpenSSL `SHA256_CTX`.
Every construction of a `SHA256` hasher (and every `XDRSHA256`
archiver, used by `xdrSha256<T>`) embeds this 112-byte object on
the stack and calls `SHA256_Init`. For the apply-path call sites
that build a fresh hasher per work item (per-CONTRACT_DATA TTL
key, per `subSha256` PRNG sub-seed, per per-result XDR hash if
streamed), the Init store and the implicit
`mState`-default-construction zeroing occur once per item.

A pool / thread-local design would carry one `SHA256_CTX` per
thread, reset it with `SHA256_Init` between uses, and skip the
per-hasher object construction. This is a strict superset of the
H023 lazy-init angle: it also removes the per-hasher storage
construction overhead.

## Trigger

A soroswap apply ledger constructs many short-lived `SHA256`
hashers (one per CONTRACT_DATA TTL key, per-tx PRNG seed, per
header hash, per archiver instantiation).

## Target Code

- `src/crypto/SHA.h` — `SHA256` class layout.
- `src/crypto/SHA.cpp:50-60` — `SHA256` constructor / `reset`.
- `src/crypto/XDRHasher.h` — `XDRSHA256` derived hasher
  construction.
- `src/transactions/TransactionUtils.cpp` (`getTTLKey`) —
  per-CONTRACT_DATA TTL key derivation.
- `src/crypto/SHA.cpp:42-48` — `subSha256` constructs `SHA256` per
  call.

## Evidence

- The 112-byte `SHA256_CTX` is non-trivial to default-construct
  and re-init compared to the actual SHA-NI compression of a
  one-block input.
- Apply-path constructs fresh hashers per work item rather than
  reusing one across many items.
- Thread-local storage avoids any locking and amortizes init cost
  across many calls.

## Anti-Evidence

- Meta-Pattern 1 ("SHA256 / Hashing Budget Ceiling"): the entire
  in-apply SHA256 budget for soroswap is ~4 ms / ledger ≈ 0.67% of
  apply. Per-hasher construction + Init is a fraction of that —
  well below the 1% Low floor.
- Meta-Pattern 7 ("Tracy Overhead Inflates Crypto Self-Times"):
  the apparent per-hasher cost in Tracy includes ZoneScoped
  overhead for `add`/`finish`, not actual production cost.
- The H023 review explicitly extended the SHA256 ceiling to
  "sub-decompositions of the SHA256 streaming class (Init alone,
  Update alone, Final alone)" — a thread-local context pool
  inherits the same ceiling.
- Thread-local storage adds its own setup/access cost (TLS lookup,
  branch on first-use), which partially negates the savings on hot
  callers and risks subtle lifetime bugs on worker thread reuse.
- The `sha256()` free function already calls one-shot `::SHA256()`
  for callers that don't need streaming, so the pool only helps the
  remaining streaming callers — which are exactly the ones bounded
  by Meta-Pattern 1.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis (self-rejected during analysis)
**Novelty**: PASS — distinct from H012 (one-shot vs streaming
class), H018 (one-shot serialize+hash for short XDR objects), and
H023 (`SHA256_Init` lazy/inline init). H026's angle is per-thread
context reuse, but it inherits the same Meta-Pattern 1 ceiling.

### Why It Failed

The total in-apply SHA256 budget for soroswap is structurally
capped at ~0.67% of apply time (Meta-Pattern 1). Per-hasher
construction + Init is one component of that budget — even a
hypothetical zero-cost design (perfect TLS, no init) yields well
below the 1% Low floor and far below the 3% Medium minimum.
Thread-local pooling also adds non-trivial complexity (lifetime
management across worker threads, interaction with the Tracy
profiler, code-review burden) that is not justified by sub-1%
projected savings. The H023 review already condensed this class
of hypothesis under Meta-Pattern 1.

### Lesson Learned

Per-hasher object construction is part of the overall SHA256
apply-path budget and inherits the 0.67% ceiling. Future
SHA256-side hypotheses must demonstrate a callsite that escapes
this ceiling — e.g., a previously-uncounted SHA256 caller
reachable from `closeLedger` whose call frequency is materially
higher than the known TTL-key / `subSha256` / header /
`txResultSet` sites. Object-pooling primitives within the
existing SHA256 budget cannot reach Medium severity.
