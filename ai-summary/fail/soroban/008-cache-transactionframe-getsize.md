# H008: Cache `xdr::xdr_size(mEnvelope)` in `TransactionFrame::getSize()`

**Date**: 2026-05-24
**Subsystem**: soroban (parallel apply / per-tx validation)
**Severity**: Low (sub-Low, below objective threshold)
**Impact**: per-tx XDR walk overhead during apply-window `commonValidPreSeqNum`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getSize()` (`src/transactions/TransactionFrame.cpp:2827-2832`)
returns the wire byte-size of the transaction envelope, which is an immutable
property of the constructed `TransactionFrame` (the envelope cannot be mutated
once the frame is constructed — `mEnvelope` is set in the constructor and only
read thereafter). Each `TransactionFrame` should therefore compute this size at
most once across its lifetime, with subsequent calls returning a cached value
in constant time.

## Mechanism

Each call to `getSize()` calls `xdr::xdr_size(mEnvelope)`, which walks the full
XDR tree of the envelope (operations, signatures, conditions, soroban
resources) every time. For soroswap-shaped transactions the envelope contains
a Soroban operation with a populated footprint (readOnly / readWrite vectors)
and an auth-entries vector, so the walk visits dozens of XDR fields per call.
The apply path invokes `getSize()` once per transaction during
`commonValidPreSeqNum` at `TransactionFrame.cpp:979` (the
`txMaxSizeBytes` admission check), so each apply-window transaction pays the
full walk cost even though the size is invariant per frame.

## Trigger

Soroswap apply-load benchmark: each parallel-apply worker calls
`TransactionFrame::commonValidPreSeqNum` once per assigned transaction in
`preParallelApplyReadOnly`, and that call invokes `getSize()` exactly once.

## Target Code

- `src/transactions/TransactionFrame.cpp:2827-2832` — `TransactionFrame::getSize` calls `xdr::xdr_size(mEnvelope)` on every invocation
- `src/transactions/TransactionFrame.cpp:979` — apply-path caller inside `commonValidPreSeqNum`
- `src/transactions/TransactionFrame.h` — add `mutable std::optional<uint32_t> mCachedSize` member

## Evidence

Tracy soroswap trace (`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`)
shows `getSize` zone (`TransactionFrame.cpp:2830`) with `total_ns =
153,692,008`, `counts = 334,289`, `mean_ns ≈ 459`. The `mEnvelope` field is set
once in the `TransactionFrame` constructor and not mutated thereafter, so the
return value is a pure function of construction-time state and is safe to
cache.

## Anti-Evidence

The 334k Tracy counts span the entire benchmark process — TX-set construction
(`tryAdd`, `buildSurgePricedParallelSorobanPhase`), validation
(`getInvalidTxListWithErrors`, `checkValidInternalWithResult`), and admission,
in addition to apply. None of these out-of-`applyLedger` callers count toward
the objective.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — `getSize` caching has not been previously hypothesized
(distinct from rejected `014-xdr-size-walks-in-addreads.md`, which targets
`xdr::xdr_size(LedgerKey)` walks inside `addReads`, not the envelope-size walk).

### Why It Failed

The savings are sub-Low after correctly bounding the apply-window slice. With
the Tracy mean of ~459 ns/call and ~184 transactions per ledger
(`invoke_host_function` count = 7,891 / 43 ledgers ≈ 184), the per-ledger
apply-window apply-thread time spent in `getSize` is at most:

    184 calls × 459 ns ≈ 84 µs/ledger total CPU

Distributed across 8 cluster workers (since `preParallelApplyReadOnly` is the
parallelized half), wall-clock impact is ≈ 10.5 µs/ledger ≈ 0.005% of the
218 ms soroswap baseline — three orders of magnitude below the 3% Medium floor
and well below the 1% Low floor. Even attributing every apply-window call to
the apply-thread critical path puts the ceiling at ~84 µs/ledger ≈ 0.04%.

The `updateSorobanMetrics` caller (`TransactionFrame.cpp:1095`) early-returns
under `DISABLE_SOROBAN_METRICS_FOR_TESTING=true` (the benchmark configuration —
confirmed by Meta-Pattern 7 noting classic-tx medida is not on the soroswap
hot path and by the benchmark config disabling soroban metrics), so its
`getSize` call is not on the measured path. The `getResources` caller
(`TransactionFrame.cpp:238`) is TX-set construction (called from
`tryAdd`/`buildSurgePricedParallelSorobanPhase`), which is explicitly out of
scope (Meta-Pattern: Tracy Trap; see also retained fail
`015-signature-validation-outside-apply.md`).

### Lesson Learned

`TransactionFrame` per-tx XDR-walk micro-optimizations on a single apply-path
caller are bounded by `N_apply_txs_per_ledger × walk_µs / NUM_CLUSTERS`. For
soroswap shape (~184 txs/ledger, 8 workers, sub-µs walk), even total
elimination is sub-0.05%/ledger. This reinforces Meta-Pattern 14
(sub-millisecond serial paths are exhausted) and extends it to per-tx XDR
walks invoked once per transaction during pre-apply validation: any caching of
a single such walk cannot clear Low, let alone Medium. Future
TransactionFrame-level caching proposals targeting apply-window pre-validation
must aggregate impact across multiple distinct callers and verify each caller
is actually on the apply-critical path.
