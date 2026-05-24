# H005: Coalesce per-tx Counter::inc calls in processResultAndMeta into one apply-tail bulk update

**Date**: 2026-05-24
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`processResultAndMeta` (LedgerManagerImpl.cpp:2727-2782) is called once
per applied transaction and increments up to two medida counters per
call: `mTransactionApplySucceeded`/`mTransactionApplyFailed` and the
Soroban variants. Each `medida::Counter::inc` is a hot atomic
fetch-add. Because the per-tx counts only need to be reflected in
metric state by end-of-ledger, the operation could be replaced with a
local accumulator in the per-ledger result-collection state, with a
single bulk `inc(N)` call per counter once `applyTransactions`
finishes — reducing apply-thread atomic traffic and instruction count.

## Mechanism

If the per-tx atomic counter increments are non-trivial in aggregate,
folding them into a per-ledger bulk update would remove ~N×Counter::inc
cost (per-call overhead is the std::atomic fetch_add + branch+ inline
medida bookkeeping). For ~2000 txs/ledger × 2 inc/tx that's ~4000
atomic ops per ledger on the apply path.

## Trigger

soroswap apply-load matrix (TX=2000, T=8); measure
`medida::Counter::inc` and `processResultAndMeta` self-time per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2727-2782` — `processResultAndMeta`
- `lib/libmedida/src/medida/counter.cc:57` — `Counter::inc` (atomic fetch_add)

## Evidence

Direct Tracy measurement on the accepted soroswap diagnostic trace:

| Zone | Self-time | Calls | per-call | per-ledger (71 L) |
|------|-----------|-------|----------|-------------------|
| `inc` (Counter::inc, all sites) | 63 ms | 1,149,709 | 55 ns | 0.89 ms |
| `processResultAndMeta` | not separately zoned | ~2000/L | — | — |

If we attribute the worst case — all 1.15 M `inc` calls falling inside
`applyLedger` — that is 0.89 ms/ledger of apply-path atomic work.
Realistically, the slice attributable to `processResultAndMeta` is at
most 4 of 1.15 M calls × 4000 ≈ 14% of the zone, ≈ 125 µs/ledger.

## Anti-Evidence

The `Counter::inc` zone is process-wide and covers many call sites
(metrics throughout codebase, including tx-set construction,
overlay, bucket, history). The fraction attributable to
`processResultAndMeta` is at most ~14% per the per-call count above.
Even the worst-case zone-total of 0.89 ms/ledger sits at 0.41% of the
218 ms baseline. The realistic addressable slice from per-tx success/
failure counter coalescing is ~125 µs/ledger ≈ 0.06%.

Additionally, `DISABLE_SOROBAN_METRICS_FOR_TESTING=true` is set in the
benchmark config, which already gates the bulk of Soroban-specific
medida traffic; remaining counters are the very few "always-on"
results counters and the prefetch hit-rate histogram, which is already
batched at end of ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — prior medida fails (transaction-ledger/003, 144, 180;
ledger/002, 024; transactions/029) targeted histogram `Update` calls,
host-function metric publication, and `TimerContext` construction, but
not the per-tx success/failure `Counter::inc` calls in
`processResultAndMeta` specifically.

### Why It Failed

Even attributing 100% of the per-ledger `Counter::inc` zone (0.89 ms,
0.41%) to `processResultAndMeta` falls below the 1% Low floor; the
realistic addressable slice (~0.06%) is in benchmark noise. Per-tx
result counter atomics are too cheap individually (55 ns) and too
infrequent per ledger (~4000) to clear any severity tier.

### Lesson Learned

The general pattern "coalesce per-tx atomic counter increments at end
of ledger" is not viable on this codebase: result counters are the
only always-on per-tx atomic medida sites, and they sum to under
0.1% of apply time. Future per-tx atomic-coalescing investigations
must size the addressable atomic-op count × per-op cost × N
ledgers before proposing — not pattern-match from generic atomic-traffic
profiling intuition.
