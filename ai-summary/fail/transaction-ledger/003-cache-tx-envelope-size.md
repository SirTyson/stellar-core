# H003: Cache `TransactionFrame::getSize()` to skip per-call `xdr::xdr_size(mEnvelope)` walks

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / TransactionFrame
**Severity**: Low
**Impact**: Removes one redundant XDR-tree walk per call site that asks for tx wire size; potential micro reduction in fee/validation overhead.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame` is constructed once from an immutable `TransactionEnvelope`. After construction `mEnvelope` is never mutated. The wire size returned by `getSize()` is therefore a deterministic function of the constructor input and should be computed once and memoized; every subsequent caller (fee scaling, surge pricing, byte-budget accounting) should obtain the cached value with a load instead of re-walking the entire XDR tree.

## Mechanism

`TransactionFrame::getSize()` (TransactionFrame.cpp:2828) currently calls `xdr::xdr_size(mEnvelope)` on every invocation. Because `mEnvelope` is non-const but in practice immutable post-construction, every caller pays a full recursive XDR-size traversal. Inside `applyLedger`, callers include `computeSorobanResourceFee` (per-tx), `commonValidPreSeqNum` (per-tx), and a byte-size logging path. Adding an `mutable std::atomic<uint32_t> mCachedSize{0}` (or a one-shot lazy init) would let the second-and-later calls read the cached size without traversing the envelope.

## Trigger

Run the soroswap apply-load benchmark; the trace shows 297,174 `getSize` calls totaling 134.2 ms self-time across the full trace.

## Target Code

- `src/transactions/TransactionFrame.cpp:2828-2832` — `getSize()` recomputes xdr_size on every call.
- `src/transactions/TransactionFrame.cpp:238,979,1095` — apply-window callers in commonValidPreSeqNum, computeSorobanResourceFee, byte-budget tracking.
- `src/transactions/TransactionFrame.h:54,65` — declaration site for adding a cached size member alongside the existing `mContentsHash`/`mFullHash` lazy caches.

## Evidence

- Trace self-time for `getSize` is 134.2 ms across 297,174 calls, ~451 ns/call.
- The same lazy-cache pattern is already used for `mContentsHash` and `mFullHash` on `TransactionFrame`, so the codebase precedent is established.
- `mEnvelope` is set in the constructor and not mutated thereafter; caching is safe.

## Anti-Evidence

- Most `getSize` calls happen during TX-set construction (surge pricing, sorting), which is **outside** the `applyLedger` window per the established Tracy Trap meta-pattern.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — caching `getSize` specifically has not been previously investigated (distinct from the rejected cross-call CxxBuf precompute and from cached `mContentsHash`/`mFullHash`).

### Why It Failed

Even attributing the entire 134 ms aggregate self-time to the apply window — which over-attributes, since the dominant call sites are TX-set construction surge pricing/sorting paths outside `applyLedger` — the per-ledger saving is at most 134 / 71 ≈ 1.9 ms / ledger sequential. Against the 272 ms soroswap median that is ≈ 0.7%, well below the objective's Medium 3% floor and below the 1% benchmark-noise floor. Realistically the in-apply share is a small fraction of those calls (the apply-window callers `computeSorobanResourceFee`, `commonValidPreSeqNum`, and byte-budget tracking are O(tx count) not O(N log N) like surge pricing), so the actual recoverable apply-window cost is sub-millisecond per ledger. This is exactly the failure mode of meta-pattern #5 ("Sub-Threshold Narrow Fixes") and meta-pattern #9 ("Validation Zone Tracy Trap").

### Lesson Learned

Lazy-caching memoizable XDR computations on `TransactionFrame` (envelope size, encoded-size sub-fields, etc.) is a legitimate clean refactor but cannot reach the Medium severity bar in isolation under the optimize-soroswap objective. Any future hypothesis bundling such caches must (a) timestamp-filter call counts to the `applyLedger` window before sizing, and (b) combine with at least one Medium-class structural change rather than relying on aggregating sub-1% memoizations.
