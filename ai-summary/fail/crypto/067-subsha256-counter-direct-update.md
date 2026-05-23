# H067: Replace `xdr_to_opaque(counter)` allocation in `subSha256` with direct 8-byte SHA256_Update of the big-endian counter

**Date**: 2026-05-23
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by Meta-Pattern 1; near-duplicate of H002)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`subSha256` (`src/crypto/SHA.cpp:41-48`) computes a SHA256-derived sub-seed
from a base seed and a 64-bit counter. The current code does:

```
SHA256 sha;
sha.add(seed);
sha.add(xdr::xdr_to_opaque(counter));   // heap-allocates a Vec<uint8_t>
return sha.finish();
```

The correct efficient form would avoid the heap allocation entirely by
directly streaming the 8 bytes of the canonical XDR encoding of `counter`
into the SHA256 state. The XDR encoding of a `uint64_t` is simply the
big-endian 8-byte representation (`xdr::swap64le` on a little-endian host
yields the wire bytes). The optimal implementation is:

```
SHA256 sha;
sha.add(seed);
uint64_t be = xdr::swap64le(counter);
sha.add(ByteSlice(&be, sizeof(be)));
return sha.finish();
```

This eliminates one `std::vector<uint8_t>` allocation + free per call,
collapsing the per-counter cost to two `SHA256_Update` calls plus one
finalize. The bytes hashed are byte-identical to the current
implementation (XDR encoding of a uint64 is the same big-endian 8 bytes).

## Mechanism

`subSha256` is called once per Soroban tx during apply in
`LedgerManagerImpl::applyTransactions` cluster workers
(`src/ledger/LedgerManagerImpl.cpp:2500`) and once per
op in `TransactionFrame::applyOperations`
(`src/transactions/TransactionFrame.cpp:2552`). For the soroswap
benchmark with ~2000 soroban txs per ledger × 65 ledgers in the
diagnostic trace, that's ~130K `subSha256` calls per run. Each call
currently triggers a `std::vector<uint8_t>` allocation of 8 bytes plus
SBO overhead, an `xdr::xdr_to_opaque` serialization, a `SHA256_Update`
over the vector, and a vector destruction. The proposed inline form
eliminates the allocation/destruction pair (~50-100 ns per call,
optimistically) and one indirection through the vector data pointer.

## Trigger

Every soroban tx applied in `applySorobanStageClustersInParallel` runs
`subSha256` to derive its PRNG sub-seed; the call is on the per-tx
parallel critical path inside each cluster worker.

## Target Code

- `src/crypto/SHA.cpp:41-48` — `subSha256` implementation
- `src/ledger/LedgerManagerImpl.cpp:2500` — per-tx cluster-worker call
- `src/transactions/TransactionFrame.cpp:2552` — per-op call
- `src/crypto/SHA.h:21` — `subSha256` declaration

## Evidence

The current code's `xdr_to_opaque(counter)` heap-allocates a `Vec<uint8_t>`
of 8 bytes for every call. Modern libcxx `std::vector<uint8_t>` does NOT
have SBO, so this is an unconditional heap round-trip. With ~2000
soroban-tx/ledger × 65 ledgers × ~100 ns/alloc-free pair ≈ ~13 ms across
the trace. Per Meta-Pattern 8, FFI-bridge overhead at ~50 ms total is
considered sub-threshold; this is in the same ballpark.

## Anti-Evidence

This hypothesis is structurally near-identical to H002
("specialize-soroban-subseed-hash"), which is already documented in
the fail summary as below the 1% threshold (entry on line 8 of
`ai-summary/fail/crypto/summary.md`). The reasoning is the same:
PRNG seeding overhead is negligible relative to Soroban host execution.

Per Meta-Pattern 1, the entire in-apply SHA256 budget for soroswap is
~4 ms per ledger (~0.67% of apply). `subSha256` is one of many SHA256
callsites within that budget; even eliminating its full overhead saves
a fraction of the already-sub-1% SHA256 ceiling. The allocation
elimination saves ~13 ms across the full diagnostic trace — divided by
65 ledgers and normalized by parallel workers, that's well under
single-digit µs per ledger on the serial critical path.

The work also runs inside `applySorobanStageClustersInParallel` cluster
workers, so the cost is divided by `NUM_CLUSTERS=4` (apply-load max-sac
config); the per-ledger serial-equivalent impact is even smaller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: BORDERLINE — H002 ("specialize-soroban-subseed-hash") proposed
specializing this exact callsite. This hypothesis differs only in the
specific implementation form (big-endian inline store vs alternative
specialization). Treat as redundant with H002 for severity purposes.

### Why It Failed

1. **Near-duplicate of H002**: H002 already evaluated specialization of
   `subSha256`'s PRNG-seed allocation and rejected at below-threshold.

2. **Meta-Pattern 1 ceiling (SHA256 budget <0.67%)**: `subSha256` lives
   inside the in-apply SHA256 budget; any single-callsite optimization
   here cannot escape the structural ceiling.

3. **Parallel-worker normalization**: The per-tx subseed derivation
   runs inside cluster workers; serial-equivalent impact is divided by
   `NUM_CLUSTERS`, further reducing the headline-metric impact below
   the Low floor.

### Lesson Learned

`subSha256` is a closed optimization surface for this objective: H002
covered the specialization angle, Meta-Pattern 1 caps the SHA256
envelope, and the call runs in parallel workers (additional 1/NUM_CLUSTERS
normalization). Future hypotheses targeting per-tx PRNG seeding are
exhausted; any new angle must target a fundamentally different mechanism
(e.g., eliminating the per-tx subseed entirely via protocol change),
which falls outside the optimize-soroswap scope.
