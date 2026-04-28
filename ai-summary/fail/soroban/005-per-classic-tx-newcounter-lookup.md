# H005: Per-classic-tx NewCounter registry lookup in applyOperations

**Date**: 2026-04-28
**Subsystem**: soroban (apply path; classic-tx loop in soroswap benchmark)
**Severity**: Low
**Impact**: per-tx allocation / mutex contention on apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::applyOperations` is called once per classic transaction
during `applyTransactions`. The metrics registry lookup for the
`{"ledger","transaction","internal-error"}` counter should be performed once
(e.g., as a member pointer cached at construction or hoisted out of the
per-tx loop), since that counter is only incremented on the rare exception
path. Doing the lookup inside the per-tx function performs an unnecessary
mutex acquisition + std::map lookup keyed on three short strings, which
contends with the medida reporter thread.

## Mechanism

`src/transactions/TransactionFrame.cpp:2513` calls
`app.getMetrics().NewCounter({"ledger","transaction","internal-error"})`
unconditionally on every classic-tx invocation of `applyOperations`. medida's
`MetricsRegistry::NewMetric` takes an `std::mutex` and probes a
`std::map<MetricName, std::shared_ptr<Metric>>` keyed by three short
strings. With ~36k classic txs/ledger in the soroswap benchmark, this is
~36k mutex acquisitions on a registry that the reporter thread also
periodically iterates, producing the same kind of contention pattern
identified in H001 for `mTransactionApply.TimeScope()`.

## Trigger

Run the soroswap apply-load benchmark; classic-tx phase invokes
`applyOperations` ~36k times per ledger.

## Target Code

- `src/transactions/TransactionFrame.cpp:2513` — per-tx `NewCounter` lookup
- `src/transactions/TransactionFrame.cpp:2675` — only consumer (catch path
  for internal-error increment)

## Evidence

- Lookup happens unconditionally per tx (not inside the rare exception
  branch).
- Identical contention class as H001 (medida registry/timer mutex shared
  with reporter thread).
- 36k calls/ledger inflates any per-call cost ~36000x.

## Anti-Evidence

- Per-call cost of `NewMetric` is small (a hash-less ordered map lookup
  on three short strings); even pessimistically estimated at ~1.5µs
  including mutex, that's only ~54M ns/ledger ≈ 1.2% of the 4.33B ns
  `applyLedger` budget — below the Medium threshold (3%).
- The Tracy trace does not show a distinct hot zone for `NewMetric`
  (uninstrumented), so the actual cost is bounded by what's left of
  the `applyTransaction` zone after H001's medida-Stop/~Impl/Update
  zones (462M ns) are accounted for. Headroom is small.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc/success record covers
this specific call site.

### Why It Failed

Below objective severity threshold. Even charitable estimates put the win
at ~1% of `applyLedger` — within benchmark noise and below the Medium
(3%) cutoff for this objective. H001 already targets the dominant
medida-mutex contention on the same apply path; bundling this fix into
H001's PR is reasonable, but it does not justify a standalone
hypothesis at this stage.

### Lesson Learned

When a per-tx call has uncertain (~µs) cost and 36k calls/ledger, the
upper-bound impact is ~3-5% of `applyLedger`. Without instrumentation
showing a distinct hot zone, the hypothesis cannot be promoted to
Medium without measurement. Document and defer to the broader
"hoist medida lookups out of per-tx hot path" follow-on of H001.
