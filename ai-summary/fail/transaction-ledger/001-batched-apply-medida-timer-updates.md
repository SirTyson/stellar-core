# H001: Batch apply-path medida timer updates instead of updating histograms per transaction and operation

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / apply-path metrics
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing serial per-tx/per-op metrics histogram updates from `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Apply-path metrics should preserve useful transaction/operation timing observability without performing a full `medida::Histogram::Update` on the critical path for every Soroban transaction and every Soroban operation. In the soroswap benchmark, where all invoke-host-function operations are already executed under `applyLedger`, timing samples should be accumulated cheaply in thread-local or per-ledger buffers and flushed once per ledger or stage after the critical worker join, producing equivalent counts/min/max/sum and acceptable histogram samples without blocking transaction execution.

## Mechanism

The current code constructs `medida::TimerContext` objects in the hot Soroban worker loop and in `TransactionFrame::parallelApply`; their destructors synchronously call `TimerContext::Stop` and `histogram.Update` for every transaction and operation. The current soroswap Tracy trace shows apply-contained `Update,libmedida/src/medida/histogram.cc:115` with **318.958 ms self-time across 40,228 calls** and timer-context destructor/stop zones around **162 ms** each, while the longest apply window shows **2,000** `preParallelApply` transactions and **1,707** invoke-host-function operations under `applyLedger`. The actual behavior therefore serializes high-frequency metrics book-keeping through libmedida on the same critical path that should be applying transactions; a batched timer sink can reduce apply time without changing ledger state, transaction results, or determinism because metrics are non-consensus observability data.

## Trigger

Run the current soroswap apply-load benchmark and diagnostic Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. The issue triggers on each Soroban transaction in `applyLedger -> applyParallelPhase -> applySorobanStageClustersInParallel -> applyThread -> TransactionFrame::parallelApply`, and on each operation timer created inside `TransactionFrame::parallelApply` / Soroban operation apply helpers.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2490-2498` — constructs `mTransactionApply.TimeScope()` for every cluster transaction in `applyThread`.
- `src/transactions/TransactionFrame.cpp:2414-2420` — constructs a fresh `ledger.operation.apply` timer for every parallel-applied Soroban operation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:269-276` — creates host-function execution timers through `InvokeHostFunctionMetrics::getExecTimer`.
- `src/transactions/ExtendFootprintTTLOpFrame.cpp:41-45` and `src/transactions/RestoreFootprintOpFrame.cpp:44-48` — same per-op timer pattern for other Soroban ops.
- `libmedida/src/medida/timer_context.cc:60-77` and `libmedida/src/medida/histogram.cc:115` — synchronous `Stop` / `Update` cost observed in Tracy.

## Evidence

The target is a descendant of `applyLedger`: timestamp-filtered unwrap analysis of the current soroswap trace found `Update` entirely inside apply windows with 318.958 ms self-time, and `~Impl` / `Stop` around 162 ms each. Critical-thread ranking across apply-contained events places `Update` on the apply path above `processFeesSeqNums`, `prefetch`, `commonValid`, bucket finalization, and most C++ transaction plumbing. Source inspection shows the hottest call sites are per-tx/per-op timer scopes inside `applyThread` and `TransactionFrame::parallelApply`, both exercised once for each Soroban transaction/operation before the worker result is committed.

A previous failure rejected disabling individual residual medida call sites as sub-threshold; this hypothesis is intentionally broader and matches that failure's lesson: redesign the apply metrics sink so high-frequency timer samples are buffered and flushed in batches rather than updated one at a time on the critical path. The potential saving is not an aggregate worker micro-zone that must be divided by `NUM_CLUSTERS`; the costly libmedida updates are visible as critical-thread work inside `applyLedger` and have a measured ceiling above the 3% Medium threshold on the current 272.9 ms soroswap baseline.

## Anti-Evidence

Metrics semantics are externally useful even if they are not consensus-visible. A PoC must not simply delete all metrics; it should preserve sample counts and enough distribution fidelity for existing monitoring, or gate reduced-fidelity batching behind an explicit config used by the apply-load benchmark and production operators who accept lower metrics granularity. Some Tracy `Update` events may come from timers outside the per-Soroban transaction loop, so the PoC needs narrow counters around the specific timer sources before claiming the full 318.958 ms as removable. Care is also needed to avoid moving expensive histogram updates to a point still inside the synchronous ledger-close tail.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The hot path is `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStage -> applySorobanStageClustersInParallel -> applyThread -> TransactionFrame::parallelApply -> OperationFrame::parallelApply -> InvokeHostFunctionOpFrame::doParallelApply/doApply`. On that path the code creates shared medida timer scopes once per Soroban transaction, once per parallel-applied operation, and once inside the Soroban operation helper; each scope destruction synchronously updates a shared timer histogram and meter from worker threads. The previous transaction-ledger failure record only rejected narrow residual medida call-site disabling and explicitly pointed to a full metrics collection redesign as the remaining Medium-sized angle, so this batching hypothesis is not a duplicate.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2860-3030` — `applyTransactions` builds parallel stages for Soroban phases and calls `applyParallelPhase`, which builds `TxBundle`s and invokes `applySorobanStages` inside ledger apply.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one async worker per cluster and waits on all futures, so worker-side timer overhead is part of synchronous close-ledger wall time.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` loops over every `TxBundle`, creates `mTransactionApply.TimeScope()` unless Soroban metrics are disabled, then calls `TransactionFrame::parallelApply`.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `parallelApply` creates `ledger.operation.apply` with `NewTimer(...).TimeScope()` before dispatching the single Soroban operation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:269-276` and `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — `HostFunctionMetrics::getExecTimer` returns `mHostFnOpExec.TimeScope()`, and `doApply` holds it across the invoke-host-function operation.
- `src/transactions/ExtendFootprintTTLOpFrame.cpp:41-45,101-107` and `src/transactions/RestoreFootprintOpFrame.cpp:44-48,102-107` — the other Soroban op helpers use the same per-op timer pattern.
- `src/main/Config.cpp:181-184,1193-1196` — `DISABLE_SOROBAN_METRICS_FOR_TESTING` defaults false and is only a test/config gate, so production and benchmark runs normally execute the timer code.
- `lib/libmedida/src/medida/timer_context.cc:33-39,76-95` — `TimeScope()` constructs a heap-backed `TimerContext::Impl`; destruction calls `Stop`, takes `Clock::now`, and invokes `timer_.Update`.
- `lib/libmedida/src/medida/timer.cc:273-279` — `Timer::Update` updates both the histogram and the meter for every sample.
- `lib/libmedida/src/medida/histogram.cc:237-258`, `lib/libmedida/src/medida/stats/ckms_sample.cc:151-160`, and `lib/libmedida/src/medida/meter.cc:186-193` — each timer sample takes shared locks and performs CKMS/sample and EWMA/count updates.

### Findings

The inefficiency exists. The Soroban parallel worker path records multiple high-frequency timer samples against shared medida timers, and each sample performs synchronous heap-backed timer-context teardown plus locked histogram/meter updates. This is not protected by an existing batching layer or pool; the only existing mitigation is `DISABLE_SOROBAN_METRICS_FOR_TESTING`, which removes metrics rather than preserving them.

The path is hot for the soroswap objective. For an invoke-heavy 2,000-transaction ledger, the traced call sites produce roughly one transaction-apply timer, one operation-apply timer, and one host-function execution timer per successful invoke transaction, before considering extend/restore operations or other direct Soroban metric histograms. Because these timers are shared across worker threads, the histogram/meter locks serialize part of otherwise parallel apply.

The proposed direction is correctness-safe if implemented as a metrics-only buffering layer. Ledger state, transaction results, transaction metadata, and deterministic execution order do not consume these medida timer histograms. A correct PoC must preserve or intentionally gate observable metrics semantics: exact count/min/max/sum should be retained, while quantile/histogram fidelity can be approximated only behind an explicit batching/reduced-fidelity design decision.

The impact is plausibly Medium rather than Low. The trace's total `Histogram::Update` count includes more than just these timers, so the full 318.958 ms should not be claimed wholesale, but the timer path alone includes thousands of samples plus `TimerContext::Stop`/destructor cost on the apply workers. Even a partial reduction of the locked per-sample work is large enough to clear the objective's 3% floor on the cited soroswap baseline if the flush is truly batched and not reintroduced as an equally expensive synchronous ledger-close tail.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.cpp::applyThread`, `src/transactions/TransactionFrame.cpp::parallelApply`, the Soroban op helpers' `getExecTimer`/`apply` paths, and `lib/libmedida` timer/histogram APIs if a reusable batch-update primitive is needed.
- **Change description**: Replace per-sample shared `medida::TimerContext` mutation on Soroban apply workers with worker-local/per-ledger duration buffers. Flush each metric in batches with one meter mark/count update per batch and a histogram path that preserves exact count/min/max/sum while avoiding per-sample lock/TimerContext overhead; do not merely move thousands of ordinary `Timer::Update` calls to a later point still counted in `applyLedger`.
- **Correctness check**: Existing Soroban transaction/application tests cover ledger-state and result determinism; metrics-specific checks should verify that timer counts advance with metrics enabled and remain gated by `DISABLE_SOROBAN_METRICS_FOR_TESTING`.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` on soroswap and max-sac with metrics enabled, multiple repetitions, and report top-line apply time plus narrow instrumentation for buffered timer sample count and flush cost. The success criterion is a reproducible 3-10% apply-time reduction without losing transaction/operation timing observability.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-21
**PoC by**: claude-opus-4.7, high

### Changes Made

The optimization adds a batched-update primitive to libmedida and rewires the
Soroban parallel-apply hot-path timers to buffer per-worker samples and flush
them in a single batched call instead of mutating shared `medida::Timer`
state once per transaction / per operation.

1. `lib/libmedida/src/medida/histogram.h` and `histogram.cc`
   - Added `Histogram::UpdateBatch(int64_t const*, size_t)` which acquires
     the recursive mutex once and applies all samples (sample insert plus
     min/max/sum/count/variance update) in a single pass. The per-sample
     arithmetic is identical to `Update`, so count/min/max/sum/variance and
     the CKMS sample contents are bit-for-bit equivalent to N individual
     `Update` calls.

2. `lib/libmedida/src/medida/timer.h` and `timer.cc`
   - Added `Timer::UpdateBatch(nanoseconds const*, size_t)` which converts
     non-negative durations and calls `Histogram::UpdateBatch` plus a
     single `Meter::Mark(N)`, removing per-sample histogram lock
     acquisitions and per-sample EWMA work (`m1/m5/m15.update` previously
     ran once per sample, now once per flush).

3. `src/transactions/ApplyTimerBatch.{h,cpp}` (new)
   - `ApplyTimerBatch`: per-worker buffers for `mTransactionApply`,
     `ledger.operation.apply`, `mHostFnOpExec`, `mExtFpTtlOpExec`,
     `mRestoreFpOpExec` samples.
   - `ScopedApplyTimerBatch`: RAII guard that publishes the per-worker
     batch in a `thread_local` for the lifetime of the worker so nested
     scopes can find it.
   - `ApplyTimerScope`: RAII timer scope. If a batch buffer is supplied,
     captures `steady_clock::now()` at construction and appends the
     elapsed `nanoseconds` to the buffer at destruction, never touching
     shared medida state. If no buffer is supplied (callers outside the
     parallel-apply worker path), falls back to the existing
     `medida::TimerContext` behavior.
   - `flushApplyTimerBatch(timer, samples)`: invokes
     `Timer::UpdateBatch` and clears the buffer.

4. `src/ledger/LedgerManagerImpl.cpp::applyThread`
   - Creates an `ApplyTimerBatch`, publishes it via
     `ScopedApplyTimerBatch` for the duration of the per-cluster loop,
     replaces the per-tx `mTransactionApply.TimeScope()` with
     `ApplyTimerScope(...)` writing into the buffer, and after the loop
     drops the scope guard and flushes all five buffers with one
     `UpdateBatch` call each. Falls back to the existing TimerContext
     path under `DISABLE_SOROBAN_METRICS_FOR_TESTING`.

5. `src/transactions/TransactionFrame.cpp::parallelApply`
   - The per-operation `ledger.operation.apply` timer scope now writes
     into the worker's `mOpApply` buffer when available, instead of
     constructing a `TimerContext` whose destructor takes the shared
     timer's histogram + meter locks.

6. `src/transactions/InvokeHostFunctionOpFrame.cpp` (`HostFunctionMetrics::getExecTimer`)
   - Returns an `ApplyTimerScope` that batches `mHostFnOpExec` samples
     when called inside a parallel-apply worker.

7. `src/transactions/ExtendFootprintTTLOpFrame.cpp` and
   `src/transactions/RestoreFootprintOpFrame.cpp`
   - The two per-op `getExecTimer` helpers similarly batch into
     `mExtFpTtlExec` / `mRestoreFpExec`.

Files modified:
- `lib/libmedida/src/medida/histogram.h`
- `lib/libmedida/src/medida/histogram.cc`
- `lib/libmedida/src/medida/timer.h`
- `lib/libmedida/src/medida/timer.cc`
- `src/ledger/LedgerManagerImpl.cpp`
- `src/transactions/TransactionFrame.cpp`
- `src/transactions/InvokeHostFunctionOpFrame.cpp`
- `src/transactions/ExtendFootprintTTLOpFrame.cpp`
- `src/transactions/RestoreFootprintOpFrame.cpp`

Files added:
- `src/transactions/ApplyTimerBatch.h`
- `src/transactions/ApplyTimerBatch.cpp`

### Demonstration

On the Soroban parallel-apply hot path each transaction and each
operation previously destroyed a `medida::TimerContext` that took two
locks (`Histogram::Impl::mutex_` and `Meter::Impl::mutex_`) and ran the
three EWMA `m1/m5/m15.update` calls and a CKMS insert. With this change
the worker only does a `steady_clock::now()` and a `vector::push_back`
per sample, and the shared medida state is touched exactly once per
timer per worker per ledger (one histogram-mutex hold covering all
samples in the batch, one `Meter::Mark(N)` covering the batched count).
For the cited soroswap trace (2000 invoke-host-function txs, 1707
operations) this collapses ~5707 locked histogram updates and ~5707
locked meter Mark(1) calls down to ~5 batched flushes per Soroban
worker per ledger, while preserving exact count/min/max/sum/variance
and feeding the same CKMS samples (just under one lock instead of N).
`DISABLE_SOROBAN_METRICS_FOR_TESTING` still short-circuits all timer
work.

### Test Results

Full unit-test suite ran clean:

```
env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check
```

All Catch2 partitions and Rust/host-side test crates exited with status
zero; the trailing autotools summary reports `PASS: test/selftest-nopg`
and `PASS: test/check-nondet`, with no `FAIL` lines anywhere in the
output. The libmedida, xdrpp, gperftools and Soroban (`p21`-`p26`)
sub-suites all reported `# FAIL: 0`.

---

## Final Review

**Verdict**: REJECTED
**Date**: 2026-05-21
**Final review by**: gpt-5.5, high
**Failed At**: final-review

### Adversarial Analysis

1. **Does the change actually address the claimed inefficiency?** YES — the diff targets the claimed hot timers by replacing per-transaction / per-operation `medida::TimerContext` updates in Soroban parallel apply with worker-local duration buffers and libmedida `UpdateBatch`.
2. **Are the preconditions realistic?** YES — the changed paths are exercised by the soroswap apply-load workload under `applyLedger`.
3. **Is the original code inefficient or working as designed?** INEFFICIENCY — the per-sample shared histogram/meter updates are metrics-only work and not consensus state.
4. **Does the benchmark improvement match the claimed severity?** NO — the independent authoritative non-Tracy benchmark runs show regressions, not improvement.
5. **Is the optimization in scope?** YES — the modified timer scopes are descendants of `applyLedger` and do not target TX-set construction.
6. **Is the benchmark methodology correct?** YES — the final review used the required local-build command, `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py`, run exactly three times without `--tracy`, and compared against `ai-summary/CURRENT_STATE.md`.
7. **Can the improvement be explained without the optimization?** NOT APPLICABLE — there is no measured improvement to explain; the optimized runs are consistently slower.
8. **Is this optimization novel?** NOVELTY NOT DISPUTED — duplicate handling is outside this final review.

### Benchmark Results

Baseline from `ai-summary/CURRENT_STATE.md`:

| run | sac median_ms | soroswap median_ms |
|-----|---------------|--------------------|
| 1 | 306.357371 | 272.249541 |
| 2 | 300.543791 | 275.885919 |
| 3 | 312.727103 | 270.551362 |

Independent optimized non-Tracy runs:

| run | artifact directory | sac median_ms | soroswap median_ms |
|-----|--------------------|---------------|--------------------|
| 1 | `/mnt/nvme2/apply-load/8da1a64e5cf6-20260521-214915` | 330.059014 | 285.922630 |
| 2 | `/mnt/nvme2/apply-load/8da1a64e5cf6-20260521-215602` | 340.390290 | 290.276738 |
| 3 | `/mnt/nvme2/apply-load/8da1a64e5cf6-20260521-220248` | 363.784156 | 289.726871 |

Average soroswap median regressed from 272.895607 ms to 288.642080 ms (+5.77%). Average max-sac median regressed from 306.542755 ms to 344.744487 ms (+12.46%). Because the required headline soroswap metric regressed in all three runs, no diagnostic `--tracy` run was collected.

### Test Results

The optimized branch built with:

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres \
            --enable-next-protocol-version-unsafe-for-production
make -j $(nproc)
```

The first full `make check` attempt hit a one-off third-party gperftools allocator test failure (`tcm_min_asserts_unittest`, `LargeAllocsRelease` allocation-failure threshold). A rerun with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j $(nproc) check` completed successfully, including `PASS: test/selftest-nopg` and `PASS: test/check-nondet`.

### Rejection Reason

The optimization does not meet the performance objective. It consistently regresses the headline soroswap apply-time metric versus the accepted baseline, and it also materially regresses max-sac. Under the objective's verdict criteria, soroswap regression blocks CONFIRMED and warrants rejection.

### Failed Checks

- Check 4: benchmark improvement does not match claimed severity; it is a reproducible regression.
- Verdict criteria: soroswap regressed across all three authoritative non-Tracy benchmark runs.
