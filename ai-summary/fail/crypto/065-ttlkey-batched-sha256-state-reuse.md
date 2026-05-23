# H065: Batch consecutive `getTTLKey` SHA256 calls by reusing a single `crypto_hash_sha256_state` across footprint iteration

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by Meta-Pattern 1 SHA256 budget)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The pre-parallel-apply helpers in
`src/transactions/ParallelApplyUtils.cpp` (`collectReadWriteTTLKeys` at
lines 120-131 and `collectReadOnlyTTLKeys` at lines 240-252) walk a
transaction's full Soroban footprint and invoke `getTTLKey(lk)`
(`src/ledger/LedgerTypeUtils.cpp:30-38`) once per applicable entry.
Each call independently:

1. Allocates a fresh `std::vector<uint8_t>` via `xdr::xdr_to_opaque(e)`.
2. Calls `sha256(...)` → `crypto_hash_sha256_init` →
   `crypto_hash_sha256_update` → `crypto_hash_sha256_final`.
3. Frees the vector.

The correct efficient form would amortise the per-call `init` / `final`
overhead and the per-call heap allocation by walking the footprint in a
single pass that:

- Maintains one `crypto_hash_sha256_state` on the stack.
- For each entry, resets the state, streams the entry's XDR bytes into
  it via `XDRSHA256`, and finalises into the TTL key — without any
  intermediate `std::vector` allocation.

The N TTL keys produced should be byte-identical to the current
implementation; only the per-call constant-factor overhead changes.

## Mechanism

For a soroswap transaction with ~6 footprint entries needing TTL keys,
the current code performs ~6 heap allocations, ~6 `sha256_init` calls,
~6 `sha256_final` calls, and ~6 heap frees per tx. Aggregated across
~2000 soroban txs × 65 ledgers, that is on the order of 800K
allocation/free pairs and 800K `sha256_init`/`sha256_final` cycles in
the diagnostic run, each costing tens to low hundreds of nanoseconds.
A batched streaming form would remove the heap allocations entirely
(stack-buffered XDR archiver) and reduce constant-factor crypto overhead
to roughly one `sha256_init`+`final` per key (with no allocation).

This is structurally similar to H062 (`getttlkey-xdrsha256-streaming`)
but expands the scope: H062 proposed converting `getTTLKey` itself to
use `xdrSha256`; this hypothesis additionally proposes batching at the
caller level so that the SHA256 work for an entire footprint is done in
a tight loop with hot CPU caches and a hot libsodium dispatch path.

## Trigger

Run soroswap. The optimization would yield savings proportional to TTL
key construction count × per-call allocation + init/final savings
(~100-200 ns each). With ~6 footprint TTL keys × 2000 txs × 65 ledgers,
the theoretical ceiling is ~80-160 ms across the whole run, or
~1.2-2.5 ms per ledger out of a ~218 ms soroswap median apply.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:120-131` —
  `collectReadWriteTTLKeys` per-entry `getTTLKey`
- `src/transactions/ParallelApplyUtils.cpp:240-252` —
  `collectReadOnlyTTLKeys` per-entry `getTTLKey`
- `src/transactions/ParallelApplyUtils.cpp:691,781,794,980,1017` —
  additional apply-path `getTTLKey` callsites
- `src/transactions/InvokeHostFunctionOpFrame.cpp:406,685,761,1159` —
  apply-path `getTTLKey` callsites
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)`
- `src/crypto/SHA.h` — `XDRSHA256` streaming form
- `src/crypto/SHA.cpp:31-39` — one-shot `sha256` (current implementation)

## Evidence

Across the apply path, `getTTLKey` is called at minimum 11 distinct
callsites, several of which iterate over a transaction's footprint
(footprint sizes are typically 2-8 entries for soroswap). The
`sha256(xdr::xdr_to_opaque(e))` anti-pattern is genuine and unconverted
at this callsite. Aggregated per-call constant overhead across the full
soroswap run is non-trivial in microbenchmarks of libsodium SHA256
(~150-200 ns per init+final cycle on modern x86-64 with SHA-NI).

## Anti-Evidence

Meta-Pattern 1 (SHA256 / Hashing Budget Ceiling) explicitly states: the
entire in-apply SHA256 budget for soroswap is ~4 ms per ledger
(~0.67% of apply). This already represents the upper bound on all
SHA256 work — init, update, final, and the actual hashing — across
every callsite combined. Even a 100% reduction of TTL-key SHA256 cost
would save at most ~3 ms per ledger (~0.5% of apply), structurally
below the 1% Low floor and far below the 3% Medium minimum required
by this objective.

Additionally, the heap allocation overhead (`std::vector` alloc/free)
is bounded by jemalloc/tcmalloc small-object fast paths in the
benchmark build — typically 20-40 ns per allocation pair under steady
state — which further compresses the realistic savings ceiling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H062 (single-callsite streaming
conversion in `getTTLKey` itself) and from H003/H004 (caching the
result of TTL-key derivation across calls); this hypothesis is about
batching the SHA256 computation primitive across multiple consecutive
`getTTLKey` invocations within a single footprint walk

### Why It Failed

The entire in-apply SHA256 budget for soroswap is structurally capped
at ~4 ms per ledger by Meta-Pattern 1. TTL-key derivation is one
contributor to that ceiling, alongside `xdrSha256(LedgerHeader)`,
`xdrSha256(txResultSet)`, `xdrSha256(success)` in
`InvokeHostFunctionOpFrame`, and several smaller callers. Even a
hypothetical implementation that eliminated 100% of TTL-key SHA256 cost
(impossible: the hashing itself is irreducible) could save at most the
TTL-key-attributable fraction of that 4 ms — a small fraction of 1%.
This is below the objective's 3% Medium floor and below the 1% Low
floor. The batched streaming form is also more complex than the current
per-call interface; the optimization is not worth the API surface
change at this severity.

### Lesson Learned

TTL-key SHA256 batching, caching, deduplication, and conversion are
all bounded by the same Meta-Pattern 1 ceiling. The combined in-apply
SHA256 budget is the hard cap on any crypto-side TTL-key optimization;
no permutation of init/final amortisation, streaming, or batching can
clear the Medium severity floor. Future TTL-key hypotheses must
target the *non-crypto* portion of TTL handling (storage probe count,
container restructuring, parallel-worker normalisation) rather than
the SHA256 primitive itself, which is structurally exhausted.
