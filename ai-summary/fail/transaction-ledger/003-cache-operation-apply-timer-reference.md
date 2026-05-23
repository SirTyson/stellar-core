# H003: Cache `operation.apply` Timer Reference to Eliminate Per-Tx Medida Registry Mutex Contention

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: registry-mutex-contention
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A Soroban transaction applying in a parallel cluster worker should not have to
acquire a process-global mutex to obtain a reference to a `medida::Timer` that
records its apply latency. The natural design is to stash a `Timer&` once at
`LedgerApplyMetrics` construction time (as already done for `mTransactionApply`
= `transaction.apply`) and reuse it via the cached reference on the per-tx hot
path. With 8 worker threads each applying ~250 txs per ledger, the registry
should be consulted O(1) times per process for this metric — not O(#txs) times
per ledger across all threads.

## Mechanism

`TransactionFrame::parallelApply` at `src/transactions/TransactionFrame.cpp:2418`
calls `app.getMetrics().NewTimer({"ledger", "operation", "apply"}).TimeScope()`
on every Soroban transaction in every cluster worker. `medida::MetricsRegistry`
serializes the underlying `NewMetric` call behind a single
`std::mutex` (see `lib/libmedida/src/medida/metrics_registry.cc:131-140`); the
critical section performs `metrics_.find(name)` and then a second
`metrics_[name]` red-black-tree lookup over a `std::map<MetricName, ...>`,
followed by a `dynamic_cast`. With NUM_CLUSTERS=8 worker threads each calling
this every tx (~250 txs/worker × 8 workers ≈ 2000 NewTimer calls per ledger),
all 8 workers serialize through one process-global mutex on a code path that
should be a single field load. The cached `mTransactionApply` `Timer&` member
already in `LedgerApplyMetrics` proves the cache-once pattern is the intended
shape; this call site simply wasn't migrated.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py` with
`--scenario soroswap --tx 2000 --threads 8`). Every Soroban tx (8 workers ×
~250 txs each) acquires the registry mutex once via the `NewTimer` call inside
`TransactionFrame::parallelApply`. With `DISABLE_SOROBAN_METRICS_FOR_TESTING=false`
(default for the benchmark) all 2000 calls/ledger contend on the registry
mutex.

## Target Code

- `src/transactions/TransactionFrame.cpp:2414-2420` — per-tx `NewTimer` call inside `parallelApply`'s `opTimer.emplace(...)`
- `lib/libmedida/src/medida/metrics_registry.cc:130-140` — `MetricsRegistry::Impl::NewMetric` template, mutex + `std::map` find + `dynamic_cast`
- `src/ledger/LedgerManagerImpl.cpp:195-220` — `LedgerApplyMetrics` constructor, where the cached `Timer&` members live (e.g., `mTransactionApply`); the proposed fix adds an `mOperationApply` member here and threads it through to `parallelApply` (likely via `AppConnector` or by passing a pointer through `applyThread`)

## Evidence

- Direct source read confirms one `NewTimer` call per Soroban tx in the
  parallel worker path; `MetricsRegistry::Impl::NewMetric` acquires a
  `std::mutex` and does two `std::map<MetricName, ...>` lookups in the
  critical section before returning.
- `LedgerApplyMetrics` already pre-caches related timers (`mTransactionApply`,
  `mLedgerClose`, `mMetaStreamWriteTime`) as `Timer&` members, demonstrating
  that the lookup-once pattern is the established style — `operation.apply`
  was missed.
- The corresponding `applyOperations` (classic-tx path) also calls
  `NewTimer({"ledger","operation","apply"})` once per call at
  `TransactionFrame.cpp:2532`, but classic apply is single-threaded so
  contention is irrelevant there; the parallel-apply call site is the unique
  hot path that hits 8-way contention.

## Anti-Evidence

- Critical-section sizing: `std::map<MetricName, ...>::find` over a registry
  with ~50–150 metrics is ~100–300ns; `map[]` adds another ~100–300ns;
  `dynamic_cast` is ~10–50ns; mutex acquire/release ~30–80ns. Total ~300–700ns
  per call. Even with 8-way contention fully serializing 2000 calls per
  ledger, the serialized wall-time ceiling is ~2000 × ~500ns ≈ 1.0 ms/ledger,
  or roughly **0.45–0.7% of the 218 ms soroswap median**. Mutex bounce
  overhead and cache-line ping-pong could realistically push this to
  ~1–1.5 ms/ledger (~0.5–0.7%) but remain firmly below the objective's 1%
  Low floor and well below the 3% Medium floor.
- The closely related `H001-batched-apply-medida-timer-updates` was rejected
  at final-review with 0.27% regression on soroswap; that hypothesis targeted
  the per-Timer histogram-update mutex (which is per-Timer, not shared), so
  it's not directly comparable, but it shows that even structurally clean
  medida modifications can introduce more overhead than they remove on this
  benchmark.
- `getMetrics()` itself is a simple pointer-deref (no lock), so the
  contention is precisely localized to `NewMetric` and removable by caching
  the `Timer&` once.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — the registry-mutex angle is distinct from the H001
`UpdateBatch` failure (which targeted the per-Timer histogram mutex, not the
registry mutex), and no prior fail/hypothesis record targets the per-tx
`NewTimer({"ledger","operation","apply"})` call.

### Why It Failed

Direct sizing places the maximum recoverable wall-time at ~1.0–1.5 ms/ledger
(~0.45–0.7%), comfortably below the 1% Low floor and ~5× below the 3% Medium
floor that this objective requires. The math: critical-section cost
~300–700ns × 2000 per-tx serializations per ledger × full 8-way contention
caps at ~1.4ms/ledger. Any realistic overhead reduction (mutex bouncing,
TLS contention reduction) cannot raise the ceiling enough to clear Medium.
Additionally, H001's final-review regression on a similar medida call-site
reduction (0.27% regression despite passing tests) demonstrates that
structurally clean medida changes can paradoxically slow down soroswap by
disturbing cache/branch-prediction state that the current hot path has
adapted to.

### Lesson Learned

Per-tx process-global mutex contention sized at ≤1 ms/ledger on soroswap is
below the objective's Low floor and cannot clear Medium even under fully
contended worst-case sizing. When proposing to cache a `Timer&` to avoid
medida registry lookups, project the critical-section cost × tx-count × full
serialization against the 3% floor before treating the lookup as a
performance defect — `medida::MetricsRegistry::Impl::NewMetric`'s
`std::map<MetricName,...>::find + dynamic_cast` under one shared mutex is
~300–700ns per call, capping per-ledger savings well below 1% for the
soroswap shape. Future hot-path mutex investigations must measure raw
critical-section duration (not just call count) before promoting the angle
to a hypothesis.
