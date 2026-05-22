# H055: Force libsodium SHA-NI / Hardware Crypto Path Selection

**Date**: 2026-05-21
**Subsystem**: crypto / libsodium build configuration
**Severity**: Low
**Impact**: Per-call libsodium hash dispatch overhead (sub-Medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

All apply-path callers of `crypto_hash_sha256`, `crypto_generichash`
(BLAKE2b), `crypto_auth_hmacsha256`, and `crypto_sign_verify_detached`
should use the fastest hardware-accelerated implementation available on
the host CPU (SHA-NI / AVX2 / SSSE3) with the lowest possible per-call
dispatch overhead.

## Mechanism

libsodium uses runtime CPU-feature detection (`sodium_runtime_*_is_*`)
to select between scalar, SSSE3, AVX2, and SHA-NI implementations of its
primitives. Each `crypto_hash_sha256` call performs an indirect dispatch
through `sodium_runtime` state and then calls into the selected backend.
For workloads with many small inline hashes (e.g., `SHA256::add` from
`XDRHasher`), the runtime-dispatch + function-pointer indirection could
in principle be removed by compiling the C++ side against a fixed,
CPU-feature-locked libsodium build, eliminating the indirect call cost
per primitive invocation.

## Trigger

Run the current soroswap apply-load case from `ai-summary/CURRENT_STATE.md`
on the production bench host (which supports SHA-NI). Inspect per-call
overhead of `SHA256::add` / `BLAKE2::add` apply-contained zones.

## Target Code

- `src/crypto/SHA.cpp:SHA256::add` — wraps `crypto_hash_sha256_update`
  (libsodium dispatch).
- `src/crypto/BLAKE2.cpp:BLAKE2::add` — wraps `crypto_generichash_update`.
- `src/main/main.cpp:357 sodium_init()` — single-shot runtime feature
  detection on process start.

## Evidence

The apply-path crypto budget includes per-call libsodium dispatch overhead
on top of the actual hash compute. Each call traverses libsodium's
`implementation` pointer table before reaching the SHA-NI / AVX2 backend.

## Anti-Evidence

- `sodium_init()` is called once at process startup; the dispatch
  table is populated to point directly at the SHA-NI backend on
  this CPU, and the indirect call is a single L1-cached jump (~1 cycle).
- Meta-Pattern 1: the entire in-apply SHA256 budget is ~0.67% (~4 ms per
  ledger). Even removing every cycle of libsodium dispatch overhead — a
  cycle-class saving on what is at most a 4 ms budget — saves nanoseconds
  per ledger, deep below the 1% Low floor.
- Meta-Pattern 5 / 10: apply-path verifySig and BLAKE2 are <0.2%; the
  same dispatch argument applies to those primitives.
- Locking libsodium to a single feature set at compile time would also
  break portability across hosts (the binary would no longer run on
  older CPUs), without a measurable apply-time benefit on the bench host.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — libsodium dispatch indirection vs static-link
selection was not previously considered.

### Why It Failed

libsodium's runtime dispatch already resolves to SHA-NI on the bench host
after `sodium_init()` and reduces to a single L1-cached indirect call per
primitive invocation. The entire apply-path crypto budget is sub-1%
(Meta-Patterns 1, 5, 10), so even a perfect elimination of dispatch
overhead — measured in single cycles per call — produces nanosecond-class
per-ledger savings, orders of magnitude below the 1% Low floor and far
below this objective's 3% Medium minimum. The portability cost of locking
the libsodium binary to a fixed CPU feature set is real and outweighs the
zero measurable apply-time benefit.

### Lesson Learned

Library-dispatch micro-optimizations against libsodium primitives are
bounded by the same SHA256/BLAKE2 ceilings as the primitives themselves
(Meta-Patterns 1, 5, 10). A primitive whose total apply-path time is
sub-1% cannot be made multi-percent better by removing dispatch cycles.
Reject up-front any libsodium configuration / static-selection hypothesis
unless it cites a primitive whose apply-path total exceeds 3%, which no
crypto primitive does for the soroswap workload.
