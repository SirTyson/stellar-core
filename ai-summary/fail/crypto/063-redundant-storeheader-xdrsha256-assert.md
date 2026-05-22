# H063: Eliminate redundant `xdrSha256(header)` recompute in `storePersistentStateAndLedgerHeaderInDB` assert

**Date**: 2026-05-22
**Subsystem**: crypto
**Severity**: Low
**Impact**: Apply-time reduction (rejected — bounded by Meta-Pattern 1)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::storePersistentStateAndLedgerHeaderInDB`
(`src/ledger/LedgerManagerImpl.cpp:3165-3171`) is invoked once per closed
ledger from inside `closeLedger`. Its first statement is
`releaseAssert(!isZero(xdrSha256(header)))`, which recomputes the SHA256 of
the full `LedgerHeader` just to assert the result is non-zero. The correct
behavior is to either (a) accept the precomputed `lcl.hash` produced a few
lines earlier in `closeLedger` (`src/ledger/LedgerManagerImpl.cpp:2208`:
`lcl.hash = xdrSha256(header)`) and pass it in as a parameter, or (b) drop
the assert entirely since SHA256 collisions with all-zero output are not a
real failure mode for a deterministically constructed `LedgerHeader`. The
function should not pay for a second full XDR-serialized SHA256 of the
ledger header on every close.

## Mechanism

`xdrSha256(LedgerHeader)` runs the `XDRSHA256` archiver over the entire
`LedgerHeader` (~200-300 bytes after XDR encoding), then calls
`crypto_hash_sha256_final`. The same hash was already computed milliseconds
earlier in `closeLedger` (line 2208) and stored in `lcl.hash`. The current
assert form recomputes it instead of taking it as a parameter or reading
the cached value, wasting one full ledger-header SHA256 per ledger close.
The savings would be approximately one ledger-header SHA256 per ledger:
~1 µs per ledger at most.

## Trigger

Every `closeLedger` invocation runs this code path. On the soroswap
benchmark (65 ledgers in the diagnostic trace), eliminating the recompute
saves at most ~65 × 1 µs = ~65 µs across the whole run, or ~1 µs per
ledger out of a ~620 ms median apply.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3165-3171` —
  `storePersistentStateAndLedgerHeaderInDB` entry-point assert
- `src/ledger/LedgerManagerImpl.cpp:2208` —
  `lcl.hash = xdrSha256(header)` (the precomputed value that could be
  reused)
- `src/crypto/SHA.h` — `xdrSha256<LedgerHeader>`

## Evidence

The grep `xdrSha256(header)` finds two callsites in `LedgerManagerImpl.cpp`
within a single `closeLedger` invocation (lines 2208 and 3171); the second
is unambiguously redundant work. Pattern-wise, this is identical to other
"recompute instead of reuse" findings (H005, H019). The change to thread
the precomputed hash through `storePersistentStateAndLedgerHeaderInDB` is
mechanical and low-risk.

## Anti-Evidence

The savings are bounded by Meta-Pattern 1 and by the prior LedgerHeader
hash rejection H020:

- **H020 (ledgerheader-prev-final-hash)** rejected an incremental-hashing
  replacement for per-ledger `xdrSha256(LedgerHeader)` at "~130 SHA256
  finalisations across the 65-ledger soroswap run ≈ 130 µs total ≈ 0.0007%
  of apply time; bounded by fixed-size payload (~200 bytes) and two calls
  per ledger". The structure here is identical: removing one of the two
  per-ledger header hashes saves at most 65 µs across the trace, ~1 µs
  per ledger, four orders of magnitude below the 3% Medium floor.

- **Meta-Pattern 1**: the entire in-apply SHA256 budget for soroswap is
  ~4 ms per ledger (~0.67% of apply); a single fixed-size LedgerHeader
  SHA256 is a single-digit-µs fraction of that.

The savings are also bounded by Meta-Pattern 7 conceptually (any per-ledger
single-event work is too coarse-grained to move the apply-time needle).
Even if the assert were removed entirely (rather than rewired to take a
precomputed hash), the LedgerHeader still needs hashing once per ledger for
`lcl.hash`, so the optimization surface is at most one header SHA256 per
ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — the specific recompute at line 3171 (assert form, inside
`storePersistentStateAndLedgerHeaderInDB`) has not been written as a
standalone hypothesis; H020 covered the incremental-hashing approach for
per-ledger `xdrSha256(LedgerHeader)` in general but did not identify the
duplicate-call pattern between line 2208 and line 3171.

### Why It Failed

A single fixed-size SHA256 of a ~200-byte `LedgerHeader` once per ledger is
~1 µs per ledger (per H020's measurement: ~1 µs per LedgerHeader
finalisation, two per ledger). Removing the second of two such finalisations
saves ~1 µs per ledger out of a ~620 ms soroswap median apply: ~0.00016% of
apply time, four orders of magnitude below the 1% Low floor and five orders
of magnitude below the 3% Medium minimum required by this objective.

### Lesson Learned

For any "remove a duplicate per-ledger SHA256 of a fixed-size structure"
hypothesis on the apply path, the structural ceiling is single-digit µs per
ledger (per H020's measurement); these are inherently four-orders-of-magnitude
below the objective's Medium severity floor. Per-ledger one-shot SHA256 work
on small fixed-size structures (LedgerHeader, TransactionResultSet header,
single contract-id preimage) cannot reach Medium regardless of how cleanly
the diff removes the recompute. Future per-ledger duplicate-hash hypotheses
should be auto-rejected unless the duplicate is per-entry or per-tx (not
per-ledger).
