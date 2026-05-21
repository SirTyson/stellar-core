# H004: Single-Pass LedgerHeader XDR Encoding Reused Across Hash + DB Persistence

**Date**: 2026-05-21
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply critical path — eliminates redundant XDR re-serialization of `LedgerHeader`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The 200-byte `LedgerHeader` should be XDR-encoded **once per close** and the resulting
byte buffer reused for: (a) the `xdrSha256(prevHeader)` call at the *next*
`applyLedger` (LedgerManagerImpl.cpp:1506), (b) the `xdrSha256` for the closing-ledger's
own `LedgerHeader.previousLedgerHash` field embedded in the next header, and (c) the
`LedgerHeaderUtils::encodeHeader` invocation during DB persistence in
`storePersistentStateAndLedgerHeaderInDB`. Each consumer currently re-runs the XDR
serializer over the same struct.

## Mechanism

`xdrSha256(prevHeader)` on LedgerManagerImpl.cpp:1506 invokes a fresh `xdr_to_opaque`
which allocates a `std::vector<uint8_t>`, walks every field, and produces ~200 bytes,
which then feed SHA256. The same `LedgerHeader` was already encoded one ledger ago to
compute *its* hash (after close) and again to write the row into the DB via
`LedgerHeaderUtils::encodeHeader`. Three encodings of the same struct per ledger pair.
The actual behavior deviates from expected because the encoded buffer is not cached on
`mLastClosedLedgerState` or any equivalent — each consumer re-serializes from scratch.

## Trigger

Every `closeLedger` invocation (every benchmark ledger).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1506` — `xdrSha256(prevHeader)` re-encodes the prior
  header on every applyLedger entry.
- `src/ledger/LedgerHeaderUtils.cpp` — `encodeHeader`, called during DB persistence.
- `src/ledger/LedgerManagerImpl.cpp:3371-3429` — `sealLedgerTxnAndStoreInBucketsAndDB`
  invokes header encoding for both hash and DB write.
- `src/ledger/LedgerManagerImpl.h` — `mLastClosedLedgerState` is the natural cache slot.

## Evidence

- The `xdr_to_opaque` codepath allocates a fresh vector on every call; no caching
  layer exists between callers.
- `LedgerHeader` is small enough (≤256 bytes) that the dominant cost of XDR encoding
  is the function-call + branch overhead inside the XDR walker, not actual byte work —
  but it still amounts to a few hundred nanoseconds per encoding.

## Anti-Evidence

- Sizing the impact: ~200-byte struct × 3 encodings × ~200 ns/encoding ≈ ~600 ns/ledger.
  Soroswap baseline is 272 ms/ledger; this is 0.0002% — five orders of magnitude below
  the 3% Medium floor and four orders of magnitude below the 1% noise floor.
- SHA256 over 200 bytes is ~1 µs/call regardless of caching the buffer; the buffer
  allocation savings do not compound.
- `mLastClosedLedgerState` is rebuilt every close; threading a cached encoded buffer
  through it adds invariants (must be invalidated on any header mutation) that exceed
  the value of the optimization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — `LedgerHeader` re-encoding has not been investigated in any prior
fail or success entry.

### Why It Failed

Below objective severity threshold. The total per-ledger time spent in `LedgerHeader`
XDR encoding across all three call sites is on the order of single-digit microseconds —
well below the 1% noise floor (~2.7 ms/ledger), let alone the 3% Medium floor required
by this objective ("Findings below 1% (within benchmark noise) are not valid"). Per
the optimize-soroswap-hypothesis skill: "If your projected impact is Low (1–3%), do
**not** write the hypothesis to ai-summary/hypothesis/ — write it to fail/ instead",
and this projection is below even Low.

### Lesson Learned

Small fixed-size structs (LedgerHeader, LedgerKey, LedgerEntry meta) re-serialized a
handful of times per ledger are a tempting target but quantitatively negligible at
soroswap's per-ledger entry/operation budget. The next time a "deduplicate XDR
encoding" angle surfaces, sanity-check by multiplying (struct size × call count ×
~5 ns/byte for the XDR walker) before reading further code. Targets must total
> 2.7 ms/ledger to be in scope.
