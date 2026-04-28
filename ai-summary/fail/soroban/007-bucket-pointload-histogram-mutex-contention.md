# H007: `BucketListSnapshot::load` per-call point-timer `Histogram::Update` mutex is contended across NUM_CLUSTERS worker threads inside parallel Soroban apply

**Date**: 2026-04-28
**Subsystem**: bucket / parallel-apply
**Severity**: Medium
**Impact**: Apply-time reduction; soroswap (high parallel BucketList read fan-out) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Per-LedgerEntryType point-load latency timers in
`SearchableBucketListSnapshot::load` are diagnostic instrumentation. They
should not become a serialization point for parallel Soroban apply. With
`NUM_CLUSTERS = 8` worker threads concurrently looking up classic footprint
entries (ACCOUNT, TRUSTLINE) from the LCL BucketList snapshot, each
worker's `load(k)` should pay only the (essentially uncontended) cost of
its own bucket-lookup work — sub-microsecond when the entry is found in
an in-memory bucket. The single-process aggregated histogram timing for
"avg point load by entry type" should be derived from per-thread or
batched updates, not from a serialized recursive-mutex acquisition that
every worker thread must take on every successful (non-bloom-miss)
`load` call against the *same* per-key-type timer.

## Mechanism

`SearchableBucketListSnapshot<BucketT>::load`
(`src/bucket/BucketListSnapshot.cpp:313-340`) starts a `TimerContext` on a
shared `medida::Timer` taken from `mPointTimers[k.type()]` (one timer
*per* LedgerEntryType, shared across all threads holding any
`SearchableBucketListSnapshot` clone — `mPointTimers` is copied by value
in the copy ctor at line 92 but each entry is the same `medida::Timer&`
ref). Inside `applyLedger`, the parallel-apply path
(`InvokeHostFunctionOpFrame::addReads` ->
`ParallelLedgerAccessHelper::getLedgerEntryOpt` ->
`ThreadParallelApplyLedgerState::getLiveEntryOpt` ->
`mLCLSnapshot.loadLiveEntry`) issues `load(k)` calls on the LCL snapshot
from every worker thread for every classic footprint key not preloaded
into the thread map. On `TimerContext` destruction the underlying
`Histogram::Update` (`lib/libmedida/src/medida/histogram.cc:115`) takes
a `std::recursive_mutex` (`mutex_` at histogram.cc:50) — turning the
update into a global-per-LedgerEntryType serialization point.

Tracy soroswap baseline (csvexport `-e`):
- `Update,libmedida/src/medida/histogram.cc,115` — **978.5 ms self-time
  inside `applyLedger` over 75,973 calls**, mean ≈ 13 µs per call. An
  uncontended histogram `Update` (CKMS reservoir + meter mark + recursive
  mutex) is sub-µs; a 13 µs mean on a hot worker-thread call site is the
  signature of cross-thread contention on the histogram's recursive
  mutex.
- `load,bucket/BucketListSnapshot.cpp,317` — 290.4 ms self / 669,582
  calls; the actual lookup work that the timer is "instrumenting" is
  ≈ 433 ns mean per call. The Update-side cost (13 µs) is ~30× the
  lookup-side cost the timer claims to measure.
- `scan,bucket/InMemoryIndex.cpp,67` — 3.14 s self / 1.45 M calls. This
  is the in-memory hash-set probe inside each `load` and is what the
  point timer is supposedly measuring; per-thread it costs ~2 µs but
  the *timer wrapper* adds another ~13 µs of cross-thread serialization
  on top.

For the soroswap workload (parallel apply with worker count =
`NUM_CLUSTERS`, soroswap config), wall-clock saved by removing the
mutex serialization should be a few ms per ledger (≈ 978 ms total
contention spread across 65 ledgers × 8-way parallelism, mostly
recoverable when contention is the dominant component of the 13 µs
mean), placing this firmly in the Medium band (3–10% of soroswap
median apply time of 620 ms — i.e. the per-ledger wall-clock saving
needs to be on the order of 18–60 ms; it is plausibly there because
the contention is wall-clock-serialized across worker threads, not
amortizable like uncontended CPU work would be). The
`apply-load-benchmark-sac.cfg` (`docs/apply-load-benchmark-sac.cfg:14-18`)
already calls out histograms in the apply path as known performance
hazards and disables `DISABLE_SOROBAN_METRICS_FOR_TESTING`, but that
gate covers the per-tx Soroban metric publish in `~HostFunctionMetrics`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:175-230`) — it does
*not* gate the bucket point timer in `BucketListSnapshot::load`.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` for `soroswap, TX=4000,
T=8` against the current baseline
(`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`).
csvexport `-e` shows `Update,libmedida/src/medida/histogram.cc,115` at
≈ 978 ms self-time inside `applyLedger`. A PoC should remove the per-call
`mPointTimers[k.type()].TimeScope()` / `Reset()` from
`SearchableBucketListSnapshot::load` (or move it behind a config flag,
e.g. extend `DISABLE_SOROBAN_METRICS_FOR_TESTING` semantics or add a
`DISABLE_BUCKET_POINT_TIMERS_FOR_TESTING` flag, or replace with a
per-thread accumulator that publishes to the global histogram once per
batch / once per ledger), then re-run the soroswap benchmark and
compare median apply time against the 620.996 ms baseline over multiple
runs.

## Target Code

- `src/bucket/BucketListSnapshot.cpp:313-340` —
  `SearchableBucketListSnapshot<BucketT>::load` constructs `TimerContext`
  on `mPointTimers[k.type()]` for every load call and resets / publishes
  on dtor; this is the per-load contention site.
- `src/bucket/BucketListSnapshot.cpp:60-95` — `mPointTimers` is one
  `medida::Timer&` per `LedgerEntryType`; copies of the snapshot share
  the *same* underlying `medida::Timer` instances, so every worker
  thread holding any snapshot clone serializes on the same set of
  histograms.
- `src/bucket/BucketListSnapshot.h:101` — `mPointTimers` storage
  declaration.
- `lib/libmedida/src/medida/histogram.cc:114-117,50,161-238` — `Update`
  takes `std::recursive_mutex mutex_` and updates the CKMS sample.
- `lib/libmedida/src/medida/timer.cc:273-277` — `Timer::Impl::Update`
  forwards to `histogram_.Update` and `meter_.Mark` under the same
  histogram lock.
- `src/transactions/ParallelApplyUtils.cpp:1085` (and surrounding) —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt` is one of the
  worker-thread call paths that ends up in `BucketListSnapshot::load`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:388-535` — `addReads`
  drives the per-footprint-key load calls during parallel Soroban apply.
- `docs/apply-load-benchmark-sac.cfg:14-18` — comment confirms histogram
  apply-path cost is a known issue worth addressing.

## Evidence

- Tracy baseline shows 978.5 ms self-time for `Histogram::Update` inside
  `applyLedger` windows, with a mean of 13 µs per call across
  ~76 k calls — ~30× the underlying `BucketListSnapshot::load` mean of
  433 ns and a ~6× ratio over the underlying `InMemoryIndex::scan`
  mean of ~2.2 µs that the timer is supposedly measuring.
- All `mPointTimers` entries are shared `medida::Timer&` references
  across snapshot copies (BucketListSnapshot.cpp:80,92,110), so every
  worker holding a clone of the LCL snapshot during parallel apply
  contends on the same mutex per LedgerEntryType.
- `Histogram::Update` is unambiguously serialized on a `recursive_mutex`
  (histogram.cc:50, 161-238).
- Existing config comment
  (`docs/apply-load-benchmark-sac.cfg:14-18`) explicitly identifies
  histogram contention as a real apply-path performance problem that
  has been deferred via the "disable soroban metrics" workaround for
  benchmarking — confirming this class of bottleneck is real, just
  not yet wired into the bucket point timer.

## Anti-Evidence

- `DISABLE_SOROBAN_METRICS_FOR_TESTING = true` is already set in the
  benchmark config, but the bucket point timers in
  `SearchableBucketListSnapshot::load` are *not* gated by it (they live
  in the bucket subsystem, not the Soroban-tx-emit path), so the
  observed 978 ms is in-scope for benchmark optimization and not a
  testing artifact.
- The Tracy-zone overhead itself contributes to the measured
  `Update` self-time, but Tracy zones are typically tens to a few
  hundred ns; they cannot account for a 13 µs mean. Even if Tracy
  contributes ~500 ns/call, 76 k × 500 ns ≈ 38 ms — leaving ~940 ms of
  the 978 ms attributable to the histogram lock + CKMS update.
- Removing the timer entirely loses production observability of point
  load latency by entry type. A safe PoC should make the change
  conditional (config gate or a per-thread accumulator that
  periodically publishes to the global histogram) so production-grade
  observability is retained while the hot-path contention is
  eliminated.
- The fix is within the bucket subsystem (and optionally a tiny
  config addition) — not inside soroban-env-host or the audited
  Soroban host code.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record for bucket point-load timer contention
**Failed At**: reviewer

### Trace Summary

The parallel Soroban apply path does reach `SearchableBucketListSnapshot::load` from worker threads for classic footprint entries: `InvokeHostFunctionOpFrame::doParallelApply` constructs `InvokeHostFunctionParallelApplyHelper`, `addReads` calls `ParallelLedgerAccessHelper::getLedgerEntryOpt`, that reads through `TxParallelApplyLedgerState` and `ThreadParallelApplyLedgerState`, and non-Soroban keys fall back to `mLCLSnapshot.loadLiveEntry`. However, the specific timer implementation claimed by the hypothesis is not present in this checkout. Point-load metrics in `SearchableBucketListSnapshot::load` use `SimpleTimer`, not `medida::Timer`, and the repository does not contain the claimed `lib/libmedida/src/medida/histogram.cc` / `timer.cc` code path for these point loads.

### Code Paths Examined

- `src/bucket/BucketListSnapshot.cpp:60-95` — constructor registers point-load metrics with `metrics.NewSimpleTimer(...)`, and snapshot copy/assignment copies references to those `SimpleTimer` objects.
- `src/bucket/BucketListSnapshot.h:96-101` — `mPointTimers` is `UnorderedMap<LedgerEntryType, std::reference_wrapper<SimpleTimer>>`; the header comment explicitly says point loads use `SimpleTimer` because medida timers are too expensive.
- `src/bucket/BucketListSnapshot.cpp:313-345` — `load` does create a timer scope per lookup and resets it on bloom miss, but the scope is a `SimpleTimerContext`, not a `medida::TimerContext` backed by a histogram.
- `src/util/SimpleTimer.h:26-70` and `src/util/SimpleTimer.cpp:40-56` — `SimpleTimer::Update` increments sum/count counters and updates a max value under a plain `std::mutex`; it does not own a CKMS histogram and does not call `Histogram::Update`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535,1270-1280,1358-1377` — parallel invoke-host-function apply uses `InvokeHostFunctionParallelApplyHelper`; `addReads` is the per-footprint load loop.
- `src/transactions/ParallelApplyUtils.cpp:337-342,1084-1120,1294-1313` — `ParallelLedgerAccessHelper::getLedgerEntryOpt` reads via tx/thread state; non-in-memory Soroban types fall through to `mLCLSnapshot.loadLiveEntry`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban stage workers are launched with per-cluster `ThreadParallelApplyLedgerState`, so the load path can execute from multiple worker threads.
- `docs/apply-load-benchmark-sac.cfg:14-18` — the benchmark disables Soroban metrics due to histogram overhead, but that comment does not establish that bucket point loads currently use libmedida histograms.

### Why It Failed

The proposed bottleneck does not exist as stated. The current point-load timer path has already been converted away from `medida::Timer`/histogram percentiles to `SimpleTimer`, so `SearchableBucketListSnapshot::load` cannot be spending time in `Histogram::Update` or contending on the claimed `std::recursive_mutex`. There is still a shared per-entry-type `SimpleTimer` update on every point load, and it includes a small `std::mutex` around max tracking plus counter updates, but that is a different mechanism and lacks the hypothesis's CKMS-histogram cost evidence. Without measured `SimpleTimer::Update` self-time inside `applyLedger`, the remaining timer overhead cannot be projected to clear the objective's 3% Medium threshold.

### Lesson Learned

Before promoting bucket-metric hypotheses, verify the concrete metric type in the current checkout. Historical or generic libmedida histogram evidence does not apply to bucket point loads now that `mPointTimers` stores `SimpleTimer&`; any future version should target `SimpleTimer::Update` directly, quantify its apply-window cost, and compare that cost against the Medium threshold before proposing a config gate or per-thread accumulator.
