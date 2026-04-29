# H002: Defer Soroban Host-Function Metric Updates off Worker Hot Path

**Date**: 2026-04-29
**Subsystem**: transactions
**Severity**: Medium
**Impact**: reduce soroswap apply time by replacing per-transaction Medida updates on parallel Soroban workers with thread-local aggregation and deterministic flushing
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban invoke-host-function application should keep charging resources, enforcing declared limits, recording success/failure, and exposing comparable operational metrics, but metric publication should not materially slow the consensus apply path. Ledger state, transaction results, fees, events, metadata, and resource-metering decisions must remain unchanged; only non-consensus metrics emission timing and aggregation strategy should change.

## Mechanism

Every `InvokeHostFunctionApplyHelper` owns a `HostFunctionMetrics` object whose destructor publishes many Medida meter, timer, and histogram samples for each transaction on the worker thread. In the current soroswap trace, apply-window overlap for Medida update zones is large enough to be measurable: `medida::timer::Update` at `libmedida/src/medida/timer.cc:155` overlaps `applyLedger` by 134.678 ms across 19,819 calls, and `medida::histogram::Update` at `libmedida/src/medida/histogram.cc:115` overlaps by 131.984 ms across 20,231 calls. Accumulating host-function metrics in a plain per-thread or per-stage structure and flushing them once after cluster work completes should remove repeated synchronized Medida updates from the parallel worker critical path while preserving deterministic transaction execution and not increasing worker count.

## Trigger

Run the current soroswap Tracy benchmark from `ai-summary/CURRENT_STATE.md` and export `applyLedger` plus `Update` events with `csvexport-release -u`. The issue triggers on every successful soroswap invoke-host-function transaction: `HostFunctionMetrics::~HostFunctionMetrics` emits read/write byte metrics, CPU/memory metrics, invoke timers, ratio histograms, max-size meters, and success/failure meters after contract execution, so a 2000-tx soroswap ledger produces thousands of Medida updates inside the measured `closeLedger` window.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:130-230` — `HostFunctionMetrics` stores per-tx counters and publishes them to Medida in its destructor.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:170-230` — the destructor performs many `Mark` and `Update` calls, including the hot timer/histogram updates observed in the trace.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:308-328` — each invoke helper constructs `HostFunctionMetrics` with `app.getSorobanMetrics()` and the current `DISABLE_SOROBAN_METRICS_FOR_TESTING` flag.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:985-986` — the host execution timer is taken from the same metrics object around the Rust host invocation.
- `src/ledger/SorobanMetrics.h:25-120` and `src/ledger/SorobanMetrics.cpp:8-83` — `SorobanMetrics` owns the Medida meters/timers/histograms and already has atomic ledger-wide counters that could be extended or complemented by a batch-flush API.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is a natural place to accumulate per-cluster metrics and return them with the thread state before deterministic main-thread flushing.

## Evidence

The Medida update zones are descendants of the measured apply path by timestamp overlap with `applyLedger`: `timer.cc:155` contributes 134.678 ms overlap and `histogram.cc:115` contributes 131.984 ms overlap in the current soroswap diagnostic trace. The update counts align with per-transaction host-function metrics publication rather than setup work: `HostFunctionMetrics` publishes several timers/histograms per invoke, and the trace has 3,335 `InvokeHostFunctionOpFrame doParallelApply` calls inside `applySorobanStageClustersInParallel`. The destructor currently runs on the same worker threads that execute `parallelApply`, so any locking, reservoir update, or histogram bookkeeping directly extends the stage's critical path. A thread-local accumulator can preserve consensus determinism because metrics are observational only and can be flushed after the stage in a fixed cluster/thread order.

## Anti-Evidence

Exact Medida histogram reservoir semantics may depend on one sample per transaction and update order, so a PoC must decide whether exact sample preservation is required. If exact preservation is required, batching only moves the updates to the main thread and may reduce contention but not total apply work; if approximate aggregate metrics are acceptable, the observability change must be explicitly reviewed. The `DISABLE_SOROBAN_METRICS_FOR_TESTING` flag already removes some metric work in test configurations, so the PoC must verify the benchmark's production-like configuration still has these updates enabled and that repeated non-Tracy apply-load runs show a stable 3-10% median improvement.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/transactions`, `success/transactions`, or the cross-subsystem fail/success records
**Failed At**: reviewer

### Trace Summary

The code path exists: parallel Soroban workers enter `LedgerManagerImpl::applyThread`, call `TransactionFrame::parallelApply`, then `OperationFrame::parallelApply`, then `InvokeHostFunctionOpFrame::doParallelApply`, which constructs an `InvokeHostFunctionParallelApplyHelper` containing `HostFunctionMetrics`. `HostFunctionMetrics::~HostFunctionMetrics` would publish many Medida meters, timers, and histograms on helper destruction, and Medida `Timer::Update`, `Histogram::Update`, and `Meter::Mark` all take locks and update CKMS/EWMA state. However, the authoritative `scripts/run_apply_load_matrix.py` soroswap scenario uses `Scenario.disable_metrics = True` by default and writes `DISABLE_SOROBAN_METRICS_FOR_TESTING = true`, so the targeted destructor returns before every Medida call and the host-function execution timer is not created in the measured benchmark.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:34-42,120-124,417-424` — the active soroswap scenario does not override `disable_metrics`, so the default `True` is rendered into the benchmark config as `DISABLE_SOROBAN_METRICS_FOR_TESTING = true`.
- `ai-summary/CURRENT_STATE.md:60-73` — the accepted baseline and diagnostic trace were produced by `scripts/run_apply_load_matrix.py`, making that generated config the objective's measured path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:170-230` — `HostFunctionMetrics::~HostFunctionMetrics` performs the claimed `Mark` and `Update` calls only after checking `mDisableMetrics`; when the benchmark flag is true it returns immediately.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:269-277,982-987` — the host-function execution timer is also gated by the same `mDisableMetrics` flag, so this timer update is absent from the benchmark path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:308-328,1270-1280,1358-1378` — every parallel invoke helper constructs `HostFunctionMetrics` from `app.getConfig().DISABLE_SOROBAN_METRICS_FOR_TESTING`; `doParallelApply` does not use the passed `SorobanMetrics&` to bypass that gate.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` and `src/transactions/TransactionFrame.cpp:2385-2430` — the worker-thread apply path has additional transaction/operation timers, but these are separate from the proposed `HostFunctionMetrics` batching target and are also disabled by the same benchmark flag.
- `lib/libmedida/src/medida/timer.cc:154-157,273-279`, `lib/libmedida/src/medida/histogram.cc:237-258`, `lib/libmedida/src/medida/meter.cc:186-193`, and `lib/libmedida/src/medida/stats/ckms_sample.cc:151-160` — Medida updates are synchronized and nontrivial when enabled, confirming the mechanism in production-like metrics-on runs but not in the measured soroswap objective run.

### Why It Failed

The inefficiency is real only when Soroban metrics are enabled, but the optimization objective is tied to the apply time reported by `scripts/run_apply_load_matrix.py`, whose active soroswap scenario disables Soroban metrics. In that measured configuration, the proposed host-function metric aggregation removes no worker-path work because `HostFunctionMetrics` already early-returns and the related timers are not started. This is therefore not on the objective's measured hot path and cannot produce the required 3-10% Medium improvement in the authoritative benchmark.

### Lesson Learned

For this objective, Medida traces must be reconciled with the generated apply-load config before promotion. `DISABLE_SOROBAN_METRICS_FOR_TESTING=true` removes `HostFunctionMetrics` destructor publication from the benchmark, so host-function metric batching is not a viable soroswap apply-time optimization unless the objective explicitly changes to a metrics-enabled scenario.
