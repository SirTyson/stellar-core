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
