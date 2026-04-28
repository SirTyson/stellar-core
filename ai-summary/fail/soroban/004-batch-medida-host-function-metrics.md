# H004: Buffer Per-Tx `HostFunctionMetrics` medida Updates Into Per-Thread Aggregates Flushed Once Per Ledger

**Date**: 2026-04-28
**Subsystem**: soroban (per-tx metric reporting)
**Severity**: Medium
**Impact**: Eliminate medida histogram lock contention across parallel-apply
worker threads on the soroban hot path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Per-tx telemetry produced by `InvokeHostFunctionOpFrame` (read/write entry
counts, byte counts, CPU instructions, invoke-time nanoseconds, ratio
metrics, success/failure marks) should be aggregated cheaply on the apply
hot path and flushed to the shared `SorobanMetrics` histograms / counters
exactly once per ledger (or once per worker thread per ledger). The
parallel-apply workers must not contend on a global mutex on every
`HostFunctionMetrics` destruction.

The expected efficient implementation buffers the ~25 medida
`Mark` / `Update` calls into a per-thread `SorobanMetricsLocalAccumulator`
during apply, then performs a single critical-section merge into the
shared `SorobanMetrics` instance at end-of-ledger (or at thread-local
unwind from `applySorobanStageClustersInParallel`).

## Mechanism

`HostFunctionMetrics::~HostFunctionMetrics` (`InvokeHostFunctionOpFrame.cpp:175-230`)
performs **at least 24** medida operations per Soroban tx. With 4000
soroswap txs per ledger and 8 worker threads, that's roughly 96000 medida
touches per ledger funnelled through a small set of shared
`SorobanMetrics` histograms. `medida::Histogram::Update` and
`medida::Timer::Update` take a per-instance mutex internally
(reservoir/exponentially-decaying-sample protection); under high
contention from N worker threads slamming the same histogram these locks
serialize.

Tracy on the optimized soroswap baseline shows:
- `Update,libmedida/src/medida/timer.cc:155` ≈ 460 ms self-time / 38k calls
- `Update,libmedida/src/medida/histogram.cc:115` ≈ 455 ms self-time / 39k
  calls
- `Stop,libmedida/.../timer_context.cc` ≈ 462 ms self-time
- `~Impl,libmedida/.../histogram.cc` ≈ 463 ms self-time

Aggregated medida self-time inside the in-apply window is roughly 1.8 s
across the 65-ledger measured trace ≈ **~28 ms / ledger ≈ 4.7% of the
596 ms baseline**. Per-call mean ~12 µs with very high variance (max ~17 ms)
strongly indicates lock contention, not arithmetic cost — Per-thread
aggregation removes the contention almost entirely because the merge step
is a single per-thread mutex acquisition per ledger instead of per tx.

The deviation: the actual implementation calls into shared mutex-protected
medida instances per-tx; the expected implementation is per-thread
batching. Determinism is preserved because the metrics values are pure
counters/histograms; the order of `Mark` operations on a histogram does
not affect the resulting samples (medida histograms use sample reservoirs
that are commutative for the purposes of the values reported, and counters
are trivially associative).

## Trigger

Run the soroswap apply-load benchmark with parallel apply enabled and
8 threads (`scripts/run_apply_load_matrix.py` default config). Tracy will
show medida `Update`/`Stop`/`~Impl` zones with high call count, large
self-time, and high std-dev within the `applyLedger` subtree, especially
descended from `applySorobanStageClustersInParallel`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:131-230` —
  `HostFunctionMetrics` struct and destructor where 24+ medida
  `Mark`/`Update` calls happen per tx.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:201-212` — particularly
  hot calls: `mHostFnOpInvokeTimeNsecs.Update`,
  `mHostFnOpInvokeTimeNsecsExclVm.Update`,
  `mHostFnOpInvokeTimeFsecsCpuInsnRatio.Update`,
  `mHostFnOpInvokeTimeFsecsCpuInsnRatioExclVm.Update`,
  `mHostFnOpDeclaredInsnsUsageRatio.Update` — these all hit
  contended histograms.
- `src/main/SorobanMetrics.{h,cpp}` — add a thread-local accumulator
  type and a `flush()` method that takes the per-instance medida lock
  exactly once per worker per ledger.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` (and the corresponding
  thread driver in `LedgerManagerImpl.cpp`) — invoke the per-thread flush
  at the end of each cluster's parallel apply, merging accumulators back
  into the shared `SorobanMetrics`.
- `src/main/AppConnector.{h,cpp}` — expose the per-thread accumulator
  through `AppConnector` so the apply helpers (which already go through
  `AppConnector`) can record into the local accumulator instead of the
  shared `SorobanMetrics`.

## Evidence

- Tracy baseline self-time on medida zones inside `applyLedger`:
  ~1.8 s / 65 ledgers ≈ 28 ms/ledger ≈ **4.7% of 596 ms baseline**.
- Per-call mean ~12 µs with max ~17 ms is the signature of mutex
  contention; uncontended medida `Update` is sub-microsecond.
- `HostFunctionMetrics::~HostFunctionMetrics` makes 24+ medida calls,
  multiplied by 4000 txs/ledger × 8 threads = ~32 calls/tx hitting the
  same shared histograms in parallel.
- The parallel-apply code path
  (`ParallelApplyUtils.cpp:applySorobanStageClustersInParallel`) is the
  caller for all of those tx destructions, on 8 worker threads with no
  per-thread metric isolation.
- Counter and histogram aggregation is commutative for medida's
  exponentially-decaying-sample reservoir at the granularity stellar-core
  consumes (mean / count / quantiles over reservoir samples), so
  per-thread batching does not change observable telemetry outcomes
  beyond minor reservoir-sampling jitter.

## Anti-Evidence

- Some medida histograms (notably timers) reflect an externally-observed
  value (invoke time in nanoseconds). Aggregation must preserve every
  individual sample to keep quantile reporting accurate; per-thread
  batching with deferred individual-sample replay still requires N
  `Update` calls but moves them off the hot path. If the cost is pure
  mutex contention (not the arithmetic itself), batched replay still
  amortizes the lock acquisition into one per-thread acquisition per
  ledger.
- Some metrics may be consumed mid-ledger (e.g. by an admin endpoint).
  Verify that no in-apply consumer reads `SorobanMetrics` between the
  per-tx mark and end-of-ledger flush. The admin metrics endpoint runs
  on the main thread, which is blocked in `applyLedger`, so the only
  risk is a separate observer thread.
- Determinism: medida histogram updates are not consensus-visible (they
  are operator metrics, not part of `LedgerCloseMeta` or any
  hash-included structure). Reordering / batching is safe.
- A simpler alternative would be to thin out the metrics surface in
  `HostFunctionMetrics::~HostFunctionMetrics` (e.g. drop the four
  ratio histograms in lines 206–212). That would yield a smaller win
  but with even lower risk; the PoC should compare both approaches.
- If Tracy zone overhead is inflating the medida self-time
  (`tracy::Profiler` zones add ~500 ns per zone), the in-apply medida
  cost could be over-attributed. A cross-check should run a non-Tracy
  benchmark sample to confirm the savings translate.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related medida-mutex records exist, but none previously investigated `HostFunctionMetrics` batching
**Failed At**: reviewer

### Trace Summary

The per-transaction `HostFunctionMetrics` destructor does contain the claimed `Meter::Mark`, `Timer::Update`, and `Histogram::Update` calls, and those updates would hit shared `SorobanMetrics` objects from parallel Soroban worker threads. However, the optimize-soroswap benchmark path explicitly disables Soroban metrics: `run_apply_load_matrix.py` defaults each `Scenario` to `disable_metrics=True` and writes `DISABLE_SOROBAN_METRICS_FOR_TESTING = true` into the generated config. `InvokeHostFunctionApplyHelper` passes that flag into `HostFunctionMetrics`, and the destructor returns before issuing any medida updates, so the claimed hot-path cost is absent from the measured default soroswap apply time.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:170-230` — `HostFunctionMetrics` stores `mDisableMetrics`; when false, its destructor performs the claimed per-tx medida marks/updates, but when true it returns at lines 175-180 before touching medida.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:316-328` — every invoke-host-function apply helper constructs `HostFunctionMetrics` with `app.getConfig().DISABLE_SOROBAN_METRICS_FOR_TESTING`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — parallel Soroban workers call `parallelApply` for each `TxBundle`, so enabled host-function metrics would execute inside `applyThread`.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1360-1377` — transaction parallel apply dispatches to the single Soroban operation and constructs the invoke helper for the worker path.
- `src/transactions/TransactionFrame.cpp:1085-1110` — tx-wide Soroban metric publication is also gated by `DISABLE_SOROBAN_METRICS_FOR_TESTING`, confirming the benchmark intentionally suppresses Soroban apply-path metrics.
- `scripts/run_apply_load_matrix.py:35-40,120-124,417-424` — the default soroswap scenario is `model_tx="soroswap", tx_count=4000, thread_count=8` and inherits `disable_metrics=True`, which is rendered as `DISABLE_SOROBAN_METRICS_FOR_TESTING = true`.
- `docs/apply-load-benchmark-sac.cfg:14-18` — the benchmark template documents that medida histograms in the apply path cause severe non-deterministic degradation and are disabled while optimizing anything besides metrics.
- `src/main/Config.cpp:183,1193-1196` — the runtime default is metrics enabled, but the generated benchmark config overrides the flag.
- `lib/libmedida` submodule commit `b2caac89d54c9ec2b6be7fa7c020aa1b0859206b`, `src/medida/histogram.cc` and `src/medida/meter.cc` — `Histogram::Impl::Update` and `Meter::Impl::Mark` lock per call, so the contention mechanism is plausible only when the disabled metrics path is re-enabled.

### Why It Failed

The claimed inefficiency is not on the objective's measured hot path. The default `scripts/run_apply_load_matrix.py` soroswap run used for this optimization objective disables Soroban metrics, and the exact `HostFunctionMetrics` destructor targeted by the hypothesis short-circuits under that flag. Therefore eliminating or batching these medida calls cannot produce the required 3-10% improvement in the current optimize-soroswap benchmark because those calls are already absent from the benchmark's top-line apply-time measurement.

There is also a correctness/API problem with the proposed "single critical-section merge" framing. With medida's public API, preserving timer and histogram sample fidelity requires replaying individual samples through `Update`; `Timer::Update` delegates to `Histogram::Update` plus `Meter::Mark`, and both lock per update. A local accumulator could move enabled-metrics contention to a flush point or aggregate pure counters, but it cannot merge arbitrary histograms/timers into shared medida state with one lock acquisition without changing medida internals or changing reported quantiles/rates.

### Lesson Learned

For optimize-soroswap, first verify whether a metric path is enabled in the generated apply-load config before projecting from Tracy medida zones. Soroban-specific metrics are intentionally disabled in the benchmark matrix, so a metric optimization is only viable for this objective if the benchmark is explicitly run with `disable_metrics=False` and the resulting top-line improvement still clears the Medium threshold under the objective rules.
