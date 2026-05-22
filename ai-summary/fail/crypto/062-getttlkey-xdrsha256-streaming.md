# H062: Replace `sha256(xdr::xdr_to_opaque(e))` with `xdrSha256(e)` in `getTTLKey`

**Date**: 2026-05-22
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by Meta-Pattern 1)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`getTTLKey(LedgerKey const&)` (`src/ledger/LedgerTypeUtils.cpp:30-38`)
constructs a TTL ledger key by hashing the input `LedgerKey`. The correct
behavior is to compute SHA256 of the canonical XDR serialization of `e`.
The most efficient form is the streaming `xdrSha256<LedgerKey>(e)` provided
by `src/crypto/SHA.h`, which uses the `XDRSHA256` archiver to feed the
serialized bytes directly into the libsodium SHA256 state without materializing
an intermediate `std::vector<uint8_t>`. The current code instead materializes
the full XDR opaque buffer via `xdr::xdr_to_opaque(e)` and then hands the
resulting vector to one-shot `sha256()`, paying for an extra allocation,
copy, and free on every call.

## Mechanism

For each `CONTRACT_DATA` / `CONTRACT_CODE` lookup that needs a TTL key,
`getTTLKey` runs an `xdr_to_opaque(e)` allocation (a few hundred bytes for
a `LedgerKey::contractData`), then runs SHA256 over those bytes, then frees
the buffer. The streaming `xdrSha256` form avoids the heap allocation
entirely: the `XDRHasher` 256-byte stack buffer batches the serializer's
small writes, and a single `crypto_hash_sha256_final` produces the digest.
The replacement is mechanical and observably equivalent (same bytes hashed,
same SHA256 output). Apply-path callers of `getTTLKey` are reachable from
`closeLedger` via `InMemorySorobanState::get`, `SearchableLiveBucketListSnapshot`
TTL lookups, and `recordStorageChanges` TTL-entry construction.

## Trigger

Run soroswap; every CONTRACT_DATA storage probe and TTL synthesis call
exercises `getTTLKey`. The optimization would yield savings proportional to
TTL key construction count × per-call allocation savings (~50-100 ns per
allocation pair).

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)`
- `src/ledger/LedgerTypeUtils.cpp:25-28` — `getTTLKey(LedgerEntry const&)` (calls into the above)
- `src/crypto/SHA.h` — `xdrSha256<T>(T const&)` template
- `src/crypto/XDRHasher.h` — `XDRHasher<XDRSHA256>` 256-byte buffered archiver

## Evidence

The pattern `sha256(xdr::xdr_to_opaque(x))` is a well-known anti-pattern in
the codebase: `xdrSha256(x)` exists specifically to avoid the intermediate
allocation. Several callers were converted historically (e.g., callers in
`TransactionFrame::computeFullHash`), but `getTTLKey` still uses the
`xdr_to_opaque` form. TTL key derivation is invoked on hot paths
(InMemorySorobanState lookups, recordStorageChanges TTL synthesis,
parallel apply per-entry existence checks per the comment at
`src/transactions/ParallelApplyUtils.cpp:743`).

## Anti-Evidence

The headline ceiling is Meta-Pattern 1: the entire in-apply SHA256 budget
for soroswap is ~4 ms per ledger (~0.67% of apply). `getTTLKey` SHA256 is
one component of that budget. Even eliminating 100% of the allocation
overhead (the SHA256 compute itself cannot change — the same bytes must be
hashed) saves a tiny fraction of that already sub-1% slice. The replacement
removes a `std::vector<uint8_t>` of ~100-200 bytes per call; a malloc/free
pair on a small allocation is in the ~50-100 ns range with a tcmalloc-style
allocator. At soroswap's TTL-key invocation rate (a few thousand per ledger),
the total saving is single-digit microseconds per ledger, two orders of
magnitude below the 1% Low floor and three orders of magnitude below the
3% Medium floor required by this objective.

This is also bounded by the related historical rejections:

- H002 (specialize-soroban-subseed-hash) rejected the same allocation-removal
  pattern for `subSha256`, citing Meta-Pattern 1.
- H047 (stream-metered-hash-xdr) rejected the same streaming-over-buffered
  pattern for `metered_hash_xdr`, citing the apply-contained hash xdr zone
  below 1%.
- H003/H004 already cover caching the TTL key hash itself, which would
  remove far more cost than removing the allocation, and even those were
  sub-1%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — `getTTLKey` `xdr_to_opaque` → streaming replacement not
previously written as a standalone hypothesis (the related H003/H004 cover
caching the hash result, not removing the per-call allocation when caching
is not viable).

### Why It Failed

Bounded by Meta-Pattern 1: the entire in-apply SHA256 budget for soroswap
is ~0.67% of apply; removing the per-call `xdr_to_opaque` allocation in
`getTTLKey` saves a fraction of a fraction of that already-sub-1% slice.
Single-digit µs/ledger savings cannot reach the 1% Low floor, let alone the
3% Medium minimum required by this objective. The pattern is also a duplicate
in spirit of H002 and H047, both rejected under the same ceiling.

### Lesson Learned

For any `sha256(xdr::xdr_to_opaque(x))` → `xdrSha256(x)` rewrite on the
apply path, size the savings against the per-call allocation cost (single
malloc/free), not against the SHA256 compute itself (which is invariant).
Then apply Meta-Pattern 1: the combined apply-path SHA256 surface is
structurally ~0.67%, so allocation-elimination subsets cannot reach Medium.
Future hypotheses in this family should be auto-rejected unless they
present a callsite that escapes the SHA256 budget ceiling.
