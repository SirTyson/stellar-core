# H006: Cache `xdr_size(mEnvelope)` on TransactionFrame

**Date**: 2026-05-25
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: per-tx envelope overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getSize()` returns the XDR-serialized byte length of
`mEnvelope`. `mEnvelope` is immutable for the lifetime of a `TransactionFrame`
(constructed once, never mutated outside the `txbridge` test-only path).
Therefore `getSize()` should compute `xdr::xdr_size(mEnvelope)` at most
once per frame instance and return the cached value on subsequent calls —
the same lazy-cache pattern already used for `mFullHash` and `mContentsHash`.

## Mechanism

`TransactionFrame::getSize()` at `src/transactions/TransactionFrame.cpp:2827-2832`
unconditionally re-walks the envelope via `xdr::xdr_size(mEnvelope)` on
every call. Tracy reports ~333K `getSize` calls across the trace (~4.7K
calls / ledger) at ~470 ns each = ~2.2 ms / ledger of raw self-time when
counted across the whole 71-ledger window, with the apply-window portion
roughly ~40% of that (~0.9 ms / ledger). Lazy-caching the result on the
frame would eliminate all but the first call per frame at zero correctness
cost, since the envelope is immutable post-construction (the only mutator,
`txbridge::setMinFee` / sig vector mutators, is test-only).

## Trigger

Run the soroswap apply-load benchmark. Hot path: surge pricing reads
`getSize`, ledger close reads it again during fee accounting and during
result-set composition, and meta-builder paths read it under `BUILD_TESTS`
guarded checks. With 2000 txs/ledger and 2–3 calls/tx, the recomputation
runs ~5K times per ledger.

## Target Code

- `src/transactions/TransactionFrame.cpp:2827-2832` — `getSize()` calls
  `xdr::xdr_size(mEnvelope)` every invocation.
- `src/transactions/TransactionFrame.h` — add `mutable uint32_t mCachedSize{0}`
  field; sentinel `0` is unambiguous because a valid tx envelope is never
  zero bytes.
- `src/transactions/FeeBumpTransactionFrame.cpp` — mirror the cache.

## Evidence

- Tracy `csvexport -e` on the current soroswap baseline shows `getSize`
  with 333,435 calls and 156 ms of total self-time — comparable order of
  magnitude to known per-tx envelope hot zones.
- The envelope is immutable post-construction; same lazy pattern is
  already established by `mFullHash` and `mContentsHash`.
- Diff would be ~10 lines, low-risk.

## Anti-Evidence

- Most `getSize` calls are during TX-set construction / surge pricing,
  which are **outside the measured `applyLedger` window** (Tracy Trap from
  the skill). The apply-window share is bounded by callers inside
  `applyTransactions` / `applyParallelPhase` / fee accounting only.
- Even if all 333K calls landed in the apply window, that would be only
  ~2.2 ms / ledger = ~1% of the 207 ms baseline.
- Realistic apply-window share is ≤40%, putting the ceiling at ~0.4–0.5%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — `xdr_size` caching for `mEnvelope` specifically (not
footprint keys / not InMemorySorobanState entries) is not in the prior
fail corpus; however the *projected impact* fails the objective severity floor.

### Why It Failed

Projected apply-time improvement is ≤0.5%, well below the objective's
Medium floor (3%) and even below the Low floor (1%). The win is dominated
by TX-set-construction call sites that are out-of-scope per the Tracy
Trap meta-pattern (#9). The remaining apply-window callers each absorb
only a few hundred nanoseconds per tx; with 2000 txs / ledger that
caps the in-window benefit at sub-millisecond magnitudes — within
benchmark noise.

### Lesson Learned

Per-call envelope micro-optimizations (xdr_size, hash recomputation,
small lazy caches) that *could* be cleaned up still don't move the
apply-time needle once you split the call counts between TX-set
construction (out-of-scope) and the apply window. Apply this filter
before pursuing any "obvious missing cache" hypothesis: bound the
in-window call count first, then multiply by per-call ns to project
ms / ledger savings against the 3% Medium floor (~6.2 ms / ledger).
