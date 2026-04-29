# H018: Replace `XDRHasher`'s buffered streaming archive with one-shot serialize+hash for short XDR objects on the apply path

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction by removing per-`add` Tracy zone overhead and per-call buffer flush bookkeeping in fine-grained `SHA256::add` / `BLAKE2::add` calls invoked from `xdrSha256` / `xdrBlake2` on the apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`xdrSha256(t)` / `xdrBlake2(t)` for a small fixed-size XDR object should
serialize the object once into a small stack buffer and hash that buffer in
a single `crypto_hash_sha256` / `crypto_generichash` call. Per-byte and
per-element archiver dispatch should not cost more than the actual hashing
work for objects whose total serialized size fits inside `XDRHasher`'s
256-byte internal buffer.

## Mechanism

`XDRHasher<D>` (`src/crypto/XDRHasher.h`) drives serialization through
xdrpp's archiver, which calls `operator()` per scalar / per byte-slice and
dispatches to `queueOrHash` → `mBuf` copies → eventual `Derived::hashBytes`
flushes. For each `xdrSha256(t)` / `xdrBlake2(t)` call on a small struct
this generates dozens of `add()` calls, each instrumented with
`ZoneScoped`. Tracy reports `SHA::add` at 1,278,995 events and `BLAKE2::add`
at 983,784 events in the soroswap diagnostic trace — almost all of these
events come from xdrpp dispatch into the buffered archiver, not from large
data being hashed. A specialization that serializes small fixed-layout XDR
types into a single contiguous buffer (e.g., via `xdr::xdr_to_opaque` into
a stack-allocated `std::array`, or a one-shot `XDRHasher::archive_one`
helper with no Tracy zones inside the inner loop) would let the SHA256 /
BLAKE2 backend hash the entire object in one libsodium call.

## Trigger

Run the soroswap apply-load benchmark and inspect `add` zones in
`crypto/SHA.cpp:65` and `crypto/BLAKE2.cpp`. The combined `SHA::add` +
`BLAKE2::add` self-time is 285 ms in the diagnostic Tracy trace; the
underlying libsodium `crypto_hash_sha256` for the same data would complete
in a fraction of that time.

## Target Code

- `src/crypto/XDRHasher.h:1-180` — buffered archiver and `queueOrHash`
- `src/crypto/SHA.cpp:65` — `SHA256::add` (Tracy `ZoneScoped`)
- `src/crypto/BLAKE2.cpp` — `BLAKE2::add` (Tracy `ZoneScoped`)
- `src/crypto/SHA.h:39-58` — `xdrSha256<T>` template entry point

## Evidence

The Tracy trace shows the streaming archiver pattern accumulates over 2.2M
fine-grained `add` events, accounting for ~285 ms of self-time, even though
each call hashes only a few bytes. Replacing the per-element archiver with
a one-shot serialize-into-buffer + single libsodium call would collapse
this to one `add` per `xdrSha256` invocation.

## Anti-Evidence

The SHA/BLAKE `add` paths already use libsodium's incremental API
efficiently; the visible per-call overhead may be entirely Tracy
instrumentation. Per fail meta-pattern #7, fine-grained crypto-primitive
self-times are inflated by `ZoneScoped` and do not exist in non-Tracy
production builds. The actual libsodium update cost per small `add` is
nanoseconds.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a distinct hypothesis
(closely related to fail meta-pattern #7 but with a different proposed fix)

### Why It Failed

Two compounding problems make this sub-threshold:

1. **Tracy ZoneScoped overhead inflates the per-`add` self-time**. Fail
   meta-pattern #7 (and the verdict on H012) explicitly captures this:
   fine-grained crypto-primitive self-times in Tracy traces do not exist
   in non-Tracy benchmark builds. The 285 ms `SHA::add`+`BLAKE2::add`
   self-time is largely Tracy zone entry/exit, not real work in the
   non-Tracy benchmark used for the authoritative apply-time numbers.

2. **The total in-apply SHA256 + BLAKE2 budget is below the 1% Low floor**.
   Per fail meta-pattern #1, the entire in-apply SHA256 budget for soroswap
   is ~4.17 ms per ledger (~0.67% of apply). BLAKE2 in apply is even
   smaller (its primary user, `verifySig` cache key, is bounded below 1%
   per meta-pattern #5). Even an idealized one-shot rewrite that removes
   100% of `xdrSha256`/`xdrBlake2` work from the apply path cannot reach
   the 3% Medium floor required by the objective.

The candidate set of `xdrSha256` apply-path callers is also small and
already-investigated: `getTTLKey` (H003/H004), `txResultSet` (H015),
streaming success preimage (already optimized), `prevHeader`/`lcl.header`
(once per ledger, microseconds each). The remaining callers
(`MetaUtils::sortChanges` per H017, claimable balance / liquidity pool /
balance ID hashing) are not exercised by soroswap.

### Lesson Learned

When a crypto-primitive `add` zone shows millions of events in a Tracy
trace, treat the headline self-time as Tracy overhead rather than real
work — size proposed savings against the **non-Tracy** SHA/BLAKE2 budget
ceiling (~0.67% combined for soroswap apply), not against the inflated
trace number. Per-element archiver redesigns hit the same SHA256-budget
ceiling that already retired H003/H004/H012/H015.
