# H003: Reduce Per-Op `medida::Counter::inc` Atomic Storm in Soroswap Apply

**Date**: 2026-05-02
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction (per-op metrics overhead)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`medida::Counter::inc` is an atomic increment on a contended counter
`std::atomic<int64_t>`; under `DISABLE_SOROBAN_METRICS_FOR_TESTING=true`
(which the apply-load benchmark sets), all *Soroban-specific*
`HostFunctionMetrics` increments early-return without touching medida
(see fail summary item 7 / fail #004-batch-medida-host-function-metrics).
However, the trace shows **1,062,707 calls to `medida::counter::inc`**
during the benchmark, which means a different family of counters — those
*not* gated by `DISABLE_SOROBAN_METRICS_FOR_TESTING` — fires unconditionally
across the parallel-apply hot path. A correct optimization would either
gate these counters under the same testing flag, replace them with
batched per-thread accumulators that flush once per ledger, or hoist the
increments outside per-tx/per-op loops.

## Mechanism

Each `Counter::inc` performs a `fetch_add` on a shared atomic. At
~50 ns/call × 1,062,707 calls = ~53 ms of per-counter aggregate CPU.
Across NUM_CLUSTERS=8 parallel workers, this is wall-time ~6.6 ms per
benchmark = ~0.13 % of `applyLedger`. The per-call cost is small but the
call count is the highest of any zone in the trace, suggesting a
per-operation or per-host-function counter that is not gated by the
testing flag.

## Trigger

Run the soroswap apply-load benchmark with
`DISABLE_SOROBAN_METRICS_FOR_TESTING=true` (the standard config) and
observe `inc,libmedida/src/medida/counter.cc,57` in Tracy CSV output.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2742-2752` — Soroban tx-result
  succeeded/failed counters (called per parallel tx; ~143K times).
- `src/transactions/TransactionFrame.cpp:2494,2691` —
  `internalErrorCounter.inc()` (called rarely; not the source).
- Unknown additional Counter sites contributing to the 1.06M call total —
  needs `perf record` to attribute.

## Evidence

Tracy `csvexport-release -e` on
`1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy` shows
`inc,libmedida/src/medida/counter.cc,57` at 57.16 ms self / 1,062,707 calls
(54 ns/call). 1.06M calls is greater than the total tx count (143K),
total op count (~150K), and total host-function-call count (~30K), which
implies multiple counter increments per inner-loop iteration somewhere in
the apply path.

## Anti-Evidence

- Even an upper bound assuming 100 % of these counters could be removed
  yields a wall-time saving of 6.6 ms / 5092 ms = 0.13 % of apply.
- `medida::Counter` is intentionally lightweight (single atomic add);
  removing it would only return the cost of one `fetch_add` per call,
  which is already very cheap.
- Many of these counters provide operational visibility that production
  operators rely on; the `DISABLE_SOROBAN_METRICS_FOR_TESTING` flag
  intentionally only gates the Soroban-specific metric set.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (distinct from fail
#004-batch-medida-host-function-metrics, which targets only the
Soroban-specific `HostFunctionMetrics` counters that *are* gated by
`DISABLE_SOROBAN_METRICS_FOR_TESTING` and contribute zero in this benchmark;
this hypothesis targets the *un*gated counter family contributing 1.06 M
calls).

### Why It Failed

The aggregate wall-time is bounded at ~6.6 ms across the 70-ledger
benchmark = **0.13 % of `applyLedger`**, which is well below both the
1 % Low noise floor and the 3 % Medium severity threshold required by
the optimize-soroswap objective. The per-call cost (54 ns) is already
near the lower bound for an atomic `fetch_add` on a shared counter,
so even a perfect rewrite (e.g., per-thread sharded counters with
periodic flush) cannot recover meaningful apply-time. This is the same
class of finding as fail #006-dispatch-tracing-enabled-refcell-checks
("optimistic upper bound … only ~1–2 %") and below it — high call count
× tiny per-call cost is structurally below the Medium floor.

### Lesson Learned

A high call-count zone (>1 M calls) is not by itself evidence of a
Medium-tier opportunity. Multiply call count by per-call self-time
*and divide by NUM_CLUSTERS for parallel zones* before promoting. For
medida atomic counters specifically: the per-call cost floor is
~50 ns (atomic fetch_add), so to reach Medium impact (3 % × 5 s =
150 ms wall) on an 8-way parallel path you need >24 M counter calls to
remove. soroswap has only ~1 M, so no medida-counter hypothesis can
clear Medium. Future hypotheses targeting per-call atomic overhead
should target call counts of >10 M before promotion.
