# H070: Cache `TransactionFrame::getSize()` envelope XDR size

**Date**: 2026-05-25
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: per-tx apply-window CPU
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getSize()` should compute `xdr::xdr_size(mEnvelope)` once and
cache it on the frame (the envelope is immutable after construction). Each
subsequent call should return the cached value in a few cycles.

## Mechanism

Currently `TransactionFrame::getSize()` at
`src/transactions/TransactionFrame.cpp:2827-2832` recomputes
`xdr::xdr_size(mEnvelope)` on every call. The Tracy soroswap diagnostic trace
shows ~333k calls with ~467 ns/call self-time (156 ms total trace self-time).
Caching the value would eliminate all recomputations.

## Trigger

Each apply-window call path that hits `getSize()`:

- `commonValidPreSeqNum` (line 979) checks tx size against
  `config.txMaxSizeBytes()` — once per tx per pre-apply pass.
- `updateSorobanMetrics` (line 1095) records `mTxSizeByte.Update(txSize)` —
  gated by `!DISABLE_SOROBAN_METRICS_FOR_TESTING` (disabled in benchmark).
- `getResources()` (line 238) — used in TX-set construction (outside the
  measured `applyLedger` window).

## Target Code

- `src/transactions/TransactionFrame.cpp:2827-2832` — `getSize()` itself
  (recomputes `xdr_size(mEnvelope)` every call).
- `src/transactions/TransactionFrame.cpp:979` — apply-window call site in
  `commonValidPreSeqNum`.
- `src/transactions/TransactionFrame.cpp:1095` — `updateSorobanMetrics`
  call site, gated off in benchmark.
- `src/transactions/TransactionFrame.cpp:238` — `getResources()` call site,
  TX-set construction (out of scope).

## Evidence

- Tracy aggregate self-time: 156 ms / 333,435 calls.
- Apply-window calls per tx are dominated by the single `commonValidPreSeqNum`
  invocation (line 979) because `updateSorobanMetrics` is gated off and
  `getResources()` is TX-set construction.
- At 2000 txs/ledger × ~467 ns = ~934 µs/ledger of apply-window savings on the
  soroswap shape if the size is cached on first use.

## Anti-Evidence

- `updateSorobanMetrics` (`DISABLE_SOROBAN_METRICS_FOR_TESTING=true`) is the
  call site that would have multiplied per-tx hits; with metrics disabled,
  only one apply-window call per tx remains.
- Tracy includes a `ZoneScoped` macro in `getSize()` that exaggerates the
  measured self-time vs. production builds; the production cost is even
  smaller than the Tracy number suggests.
- The fail summary already captures the broader cross-call XDR-size caching
  pattern in `007-cache-footprint-xdr-sizes-cross-call.md` as sub-threshold
  (capped at ~1.5%), and that hypothesis aggregates footprint-key xdr_size
  caching across `addReads` and `recordStorageChanges` which together hit
  this ceiling. A single-site cache for the envelope size is even narrower.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — envelope-level `getSize()` caching has not been previously
investigated; prior cross-call xdr_size caching (007) targets footprint keys
on the Soroban host bridge, not the transaction envelope itself.

### Why It Failed

Apply-window savings are bounded at ~934 µs/ledger (~0.45% of the 207 ms
soroswap baseline), well below the 1% Low floor and orders of magnitude below
the 3% Medium floor accepted by this objective. The Tracy total (156 ms across
the trace) is dominated by `getResources()` calls during TX-set construction,
which the objective explicitly excludes from the apply window. With
`DISABLE_SOROBAN_METRICS_FOR_TESTING` set in the benchmark, only
`commonValidPreSeqNum` (one call per tx) remains in scope — the per-tx hit
count is too low to clear any objective threshold.

### Lesson Learned

When Tracy shows high aggregate call counts on per-tx helpers
(`TransactionFrame::getSize`, similar XDR helpers), break the call count down
by call site and filter to apply-window-only contributors before projecting.
For soroswap, helpers that are mostly hit by `getResources()`/TX-set
construction and gated metrics paths leave only a single apply-window call per
tx, which falls below the Low floor at typical tx density.
