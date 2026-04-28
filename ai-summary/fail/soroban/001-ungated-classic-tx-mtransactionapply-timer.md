# H001: Ungated `mTransactionApply.TimeScope()` in classic-tx apply contends with the medida reporter thread

**Date**: 2026-04-29
**Subsystem**: ledger / metrics
**Severity**: Medium (high-end)
**Impact**: ~7-12% reduction in soroswap/sac apply time (serial classic-tx phase).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyTransaction` (the **classic** per-tx apply loop in
`applyTxLoop`/`applyTransactions`) should not pay tens of microseconds of
medida timer overhead per transaction during `closeLedger`. Other per-tx
metric scopes in the apply path are gated by
`Config::DISABLE_SOROBAN_METRICS_FOR_TESTING`:

- The Soroban parallel-apply per-tx scope at `LedgerManagerImpl.cpp:2493-2498`
  emplaces `mTransactionApply.TimeScope()` only when the gate is off.
- The classic-op per-op scope at `TransactionFrame.cpp:2528-2542`
  (and the parallel-op variant at `TransactionFrame.cpp:2414-2420`)
  emplaces `opTimer->TimeScope()` only when the gate is off.

By symmetry, the **classic per-tx** scope in `applyTransaction` should be
either gated the same way or cheap enough that it is not a measurable
fraction of apply time. In either case, the total wall-clock spent
finalizing the per-tx timer (including any blocking on the medida histogram
mutex held by the metrics reporter thread) should be small relative to the
real per-tx work (~37 µs/tx in the trace).

## Mechanism

`LedgerManagerImpl.cpp:3049` unconditionally creates a `medida::TimerContext`
on **every** classic-tx apply iteration:

```cpp
auto txTime = mApplyState.getMetrics().mTransactionApply.TimeScope();
```

This is **not** gated on `DISABLE_SOROBAN_METRICS_FOR_TESTING`, even though
the analogous parallel-apply scope a few hundred lines above (line 2494) and
the per-op scopes in `TransactionFrame::applyOperations`/`parallelApply`
all are.

The destructor of `TimerContext` (`~Impl` at
`libmedida/src/medida/timer_context.cc:77`) calls `Stop()` (line 90), which
calls `Timer::Update` (line 155), which in turn calls
`Histogram::Update` (line 115) — both of which acquire mutexes on the
underlying `ExpDecaySample` reservoir and `EWMA` accumulator. Those same
mutexes are periodically acquired by the metrics reporter thread when it
samples percentiles and rate windows.

The Tracy soroswap baseline (T=8, TX=4000, Run 3 — the accepted current
state) shows the destructor chain dominating the classic-tx apply path:

| Zone | Source | Total ns | Calls | Mean ns | Max ns | Std ns |
|------|--------|---------:|------:|--------:|-------:|-------:|
| `Stop` | `medida/timer_context.cc:90` | **462,166,824** | 37,642 | 12,277 | 17,382,671 | 302,587 |
| `~Impl` | `medida/timer_context.cc:77` | 463,251,511 | 37,531 | 12,343 | 17,382,722 | 303,035 |
| `Update` | `medida/timer.cc:155` | 460,174,096 | 37,978 | 12,116 | 17,382,557 | 301,247 |
| `Update` | `medida/histogram.cc:115` | 455,379,724 | 38,890 | 11,709 | 17,382,137 | 297,692 |
| `applyTransaction` | `LedgerManagerImpl.cpp:3046` | 1,370,539,506 | 36,909 | 37,132 | — | — |
| `applyLedger` | `LedgerManagerImpl.cpp:1484` | 4,331,724,168 | 65 | 66,641,910 | — | — |

The huge `std_ns` (~300 µs) and `max_ns` (~17 ms) for these zones — relative
to a `mean_ns` of ~12 µs — are the classic signature of mutex contention:
most calls finish in a few hundred nanoseconds (the uncontended
fast-path of `histogram::Update` is sub-µs), but periodic stalls of milliseconds
to ~17 ms occur whenever the reporter thread holds the histogram or meter
mutex while computing percentiles or rate snapshots.

The call count (37,642) matches the classic-tx per-session count
(`applyTransaction` = 36,909) plus a small amount of overhead from
`mLedgerClose` / `mTotalTxApply` scopes. Effectively **every** classic
transaction in the soroswap benchmark pays this medida destructor cost on
the apply thread's serial path.

`462 ms / 4332 ms ≈ 10.7 %` of `applyLedger` zone time is attributable to
this single ungated per-tx timer scope. Removing or gating it should yield
a Medium-to-High reduction in soroswap apply time, and the same fix would
also help any deployment that runs the metrics reporter under load.

## Trigger

Reproduce by running the soroswap apply-load benchmark on the current
baseline:

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

Inspect the Tracy trace — `Stop` / `~Impl` / `Update` zones from the medida
timer/histogram source files should account for ~10% of `applyLedger` zone
self-time. The slow tail (max ~17 ms per `Stop` call) confirms periodic
mutex contention with the metrics reporter thread.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3046-3090` — classic-tx
  `applyTransaction` body. Line 3049 unconditionally constructs
  `mTransactionApply.TimeScope()`.
- `src/ledger/LedgerManagerImpl.cpp:2484-2498` — Soroban parallel-apply
  variant: same metric, but gated by `DISABLE_SOROBAN_METRICS_FOR_TESTING`
  at line 2494.
- `src/transactions/TransactionFrame.cpp:2414-2420` and
  `src/transactions/TransactionFrame.cpp:2528-2542` — analogous per-op
  timers, both gated by the same config.
- `lib/libmedida/src/medida/timer_context.cc:90` (`Stop`),
  `lib/libmedida/src/medida/timer.cc:155` (`Timer::Update`),
  `lib/libmedida/src/medida/histogram.cc:115` (`Histogram::Update`) — the
  expensive destructor chain (mutex acquisition + reservoir/EWMA update).
- `src/util/SimpleTimer.h` — existing replacement pattern for hot apply-path
  timers (referenced by the prior `BucketListSnapshot::load` SimpleTimer
  conversion in the project memory).

## Evidence

1. The gate inconsistency is direct: parallel-apply path at line 2494 wraps
   the **same** `mTransactionApply` timer in a `DISABLE_SOROBAN_METRICS_FOR_TESTING`
   check, but the classic path at line 3049 does not. There is no comment
   explaining the asymmetry; it appears to be a missed gate.
2. The Tracy zone counts line up exactly with classic-tx apply count
   (37,642 ≈ 36,909 + ~700 ledger/total scopes), proving the time is from
   the per-tx scope.
3. The std-deviation/max profile is the hallmark of cross-thread mutex
   contention; medida's `ExpDecaySample` reservoir is well-known to lock
   for O(reservoir-size) on resamples and is shared with the periodic
   metrics reporter that publishes percentiles every reporting interval.
4. The benchmark already disables Soroban metrics
   (`DISABLE_SOROBAN_METRICS_FOR_TESTING = true` in
   `docs/apply-load-benchmark-sac.cfg`), so a proposed gate of the form
   `if (!cfg.DISABLE_SOROBAN_METRICS_FOR_TESTING)` would activate
   immediately. Even without the testing config, replacing the medida
   `Timer` with `SimpleTimer` (or a lock-free counter+EWMA) eliminates
   the contention in production while preserving observability.

## Anti-Evidence

- The classic per-tx apply timer is genuinely useful in production for
  diagnosing classic-tx slowness; outright removal is not desirable. A
  benchmark-only gate would not improve production. However, replacing
  the medida `Timer` with `SimpleTimer` (already used elsewhere on the
  apply hot path, including `BucketListSnapshot::load`) preserves the
  metric while removing the cross-thread mutex contention.
- The 17 ms max could in theory be a single OS scheduling stall rather
  than reporter contention. The PoC step should confirm the win is
  reproducible across runs (the metric reporter cadence is on the order
  of seconds, so contention should show up consistently across the
  20–30 ledgers measured per benchmark run).
- A new config gate (e.g., `DISABLE_CLASSIC_METRICS_FOR_TESTING`) would
  be required if the fix is purely a benchmark gate. The cleaner fix is
  the SimpleTimer replacement, which has precedent.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/` or `success/`
**Failed At**: reviewer

### Trace Summary

The ungated timer exists exactly where claimed: `applySequentialPhase` constructs `mTransactionApply.TimeScope()` for every transaction in a non-parallel phase. However, the optimize-soroswap benchmark builds zero classic transactions by default and places generated soroswap transactions into the protocol-23+ parallel Soroban phase, where the same `mTransactionApply` scope is already gated by `DISABLE_SOROBAN_METRICS_FOR_TESTING`. The benchmark's top-line `p50 close time` is measured around `benchmarkModelTxTpsSingleLedger` close-ledger calls, while the cited Tracy `applyTransaction` counts are consistent with setup/classic-phase ledger closes captured by Tracy rather than the measured soroswap apply loop.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1695` — `applyLedger` measures the close path and calls `applyTransactions` after fee/sequence processing.
- `src/ledger/LedgerManagerImpl.cpp:2784-2964` — `applyTransactions` dispatches `phase.isParallel()` phases to `applyParallelPhase`; only non-parallel phases call `applySequentialPhase`.
- `src/ledger/LedgerManagerImpl.cpp:2967-3032` — `applyParallelPhase` builds `TxBundle`s and calls `applySorobanStages`; it does not use the ungated `applySequentialPhase` timer.
- `src/ledger/LedgerManagerImpl.cpp:2483-2506` — parallel Soroban worker execution wraps `mTransactionApply.TimeScope()` only when `DISABLE_SOROBAN_METRICS_FOR_TESTING` is false.
- `src/ledger/LedgerManagerImpl.cpp:3034-3090` — non-parallel `applySequentialPhase` unconditionally creates `mTransactionApply.TimeScope()` for each transaction in the phase.
- `src/herder/TxSetFrame.cpp:747-821` and `src/herder/ParallelTxSetBuilder.cpp:704-800` — Soroban phases at protocol versions starting from `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION` are built as parallel stages.
- `src/util/ProtocolVersion.h:56-58` — parallel Soroban phases start at protocol 23, well before the current p26 benchmark.
- `src/simulation/ApplyLoad.cpp:2265-2313` — the apply-load benchmark records close time from the delta of either `ledger.close` or `transaction.total-apply` timer around a single benchmark ledger close.
- `src/simulation/ApplyLoad.cpp:2275-2299` and `src/main/Config.h:412-414` — benchmark ledgers reserve room for `APPLY_LOAD_CLASSIC_TXS_PER_LEDGER`, but the default is 0 and `run_apply_load_matrix.py` does not override it.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap benchmark transactions are Soroban invoke-host-function transactions generated for the Soroban phase, not classic transactions.
- `scripts/run_apply_load_matrix.py:74-84` and `scripts/run_apply_load_matrix.py:417-425` — the soroswap scenario overrides model tx, tx count, thread count, write timing, Soroban metric disabling, and ledger count, but not classic tx count.
- `docs/apply-load-benchmark-sac.cfg:14-18` — the benchmark disables Soroban metrics, which already suppresses the parallel Soroban transaction timer.
- `lib/libmedida` submodule at `b2caac89d54c9ec2b6be7fa7c020aa1b0859206b`, `src/medida/timer_context.cc`, `timer.cc`, `histogram.cc`, and `meter.cc` — `TimerContext::Impl::~Impl` calls `Stop`, `Timer::Update` updates a histogram and meter, and those implementations take internal locks; the per-call cost is real when this timer is exercised.

### Why It Failed

The inefficiency is real but not on the objective's measured soroswap hot path. In current apply-load matrix runs, `APPLY_LOAD_CLASSIC_TXS_PER_LEDGER` remains 0, and soroswap invoke transactions enter the parallel Soroban phase. The target benchmark therefore does not execute `applySequentialPhase` once per soroswap transaction; it executes the already-gated parallel transaction timer instead. Any `applyTransaction`/medida timer cost seen in a Tracy capture is from setup ledgers or other classic/non-parallel closes captured in the trace, not from the top-line `p50 close time` samples used by `scripts/run_apply_load_matrix.py`. As a result, gating or replacing this classic sequential timer would not deliver the required 3% Medium reduction in measured soroswap apply time.

### Lesson Learned

For apply-load performance hypotheses, distinguish Tracy zones captured during setup from the benchmark ledger-close samples that feed `p50 close time`. A hot-looking classic `applySequentialPhase` zone is not automatically in scope for optimize-soroswap when the measured workload has zero classic transactions and uses the parallel Soroban phase.
