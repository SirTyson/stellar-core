# H033: medida `Histogram::Update` recursive_mutex contention across parallel apply workers

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Low
**Impact**: parallel-worker mutex contention on shared application metrics histograms during apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Per-transaction timer/histogram updates that fire from inside the
parallel Soroban apply workers should be lock-free or per-thread to
avoid serializing concurrent workers. `medida::Histogram::Impl::Update`
takes a `std::recursive_mutex` for every call (`lib/libmedida/src/medida/histogram.cc:160-217`),
so any histogram updated from multiple parallel apply workers becomes
a serialization point: the workers' wall-clock time becomes the sum,
not the max, of their update overhead. For workloads that update the
same histogram on every Soroban tx in a stage, this can cancel a
significant fraction of the parallelism speedup.

## Mechanism

`Histogram::Update` in libmedida acquires
`std::lock_guard<std::recursive_mutex>` on every sample insertion,
then mutates `min_`, `max_`, `sum_`, `count_`, `variance_m_`,
`variance_s_`, and the configured `Sample` strategy. If multiple
parallel apply workers (one per `Cluster`) call `Update` on the same
shared `Histogram` (e.g., a per-tx apply-time timer or per-op count)
during the same stage, they serialize on this mutex and lose the
parallelism gains of `applySorobanStageClustersInParallel`.

The Tracy trace shows
`Update,libmedida/src/medida/histogram.cc,115` consuming
**1.54 % of Tracy time over 21,060 calls (mean 73 µs/call, max 9.96 ms)**.
The 9.96 ms max and 73 µs mean (vs an expected sub-µs cost for
an uncontended sample insertion) are characteristic of mutex
contention.

## Trigger

Run the soroswap apply-load benchmark with the production metric
configuration (mTransactionApply timer, ledger histograms, and any
other per-tx histogram updates left enabled). If `Update` calls
fire from inside `applyThread` (`src/ledger/LedgerManagerImpl.cpp:2484`),
multiple workers will contend on the same recursive_mutex.

## Target Code

- `lib/libmedida/src/medida/histogram.cc:114-117` — `Histogram::Update`
  public entry point.
- `lib/libmedida/src/medida/histogram.cc:160-217` — `Histogram::Impl`
  mutex-protected mutation of aggregate counters.
- `src/ledger/LedgerManagerImpl.cpp:2484-2520` — `applyThread`, the
  per-cluster apply loop where `mTransactionApply.TimeScope()` would
  fire if `DISABLE_SOROBAN_METRICS_FOR_TESTING` were not set.
- `src/ledger/LedgerManagerImpl.cpp:2493-2498` — gating of
  `mTransactionApply.TimeScope()` behind
  `DISABLE_SOROBAN_METRICS_FOR_TESTING`.

## Evidence

The Tracy trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`)
shows `Update` with mean 73 µs and max 9.96 ms. These figures are
consistent with intermittent mutex contention rather than uncontended
sample insertion (which is typically < 1 µs).

## Anti-Evidence

The benchmark explicitly sets
`DISABLE_SOROBAN_METRICS_FOR_TESTING = true` (per the technical
record), and inspection of `applyThread` at
`src/ledger/LedgerManagerImpl.cpp:2493-2498` confirms the
`mTransactionApply.TimeScope()` is gated behind that flag, so the
hottest per-tx histogram update inside parallel workers is in fact
NOT firing in the soroswap benchmark. Across 21,060 `Update` calls
spread over 71 ledgers, only ~297 calls/ledger remain — orders of
magnitude lower than the 2000 txs/ledger workload, indicating these
updates fire from outside the parallel apply loop (e.g.,
ledger-level aggregates updated by the main thread). The previously
investigated `BucketListSnapshot::load` per-call timer was already
converted to `SimpleTimer` (per fail summary
`007-bucket-pointload-histogram-mutex-contention.md`), so the most
plausible remaining contention point is also already gone.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in retained Soroban fail/success records (fail #007 covered a different histogram path that was already fixed)

### Why It Failed

The proposed contention point is already mitigated:
`DISABLE_SOROBAN_METRICS_FOR_TESTING` removes the per-tx timer
update from inside the `applyThread` worker loop, so the residual
`Update` calls run from outside the parallel section and do not
serialize parallel workers. The Tracy `Update` call count
(21,060 calls / 71 ledgers ≈ 297/ledger) is incompatible with
per-tx contention from a 2000-tx-per-ledger workload, confirming
these updates do not fire from inside parallel apply.

The 73 µs mean and 9.96 ms max are explained by Tracy zone overhead
plus occasional sampling-strategy work (CKMS / SlidingWindow
sample insertion) on background threads, not by contention from
inside the apply critical path.

### Lesson Learned

Before proposing a mutex-contention fix for any libmedida
histogram, verify the call site is actually inside the parallel
apply worker loop and not gated behind
`DISABLE_SOROBAN_METRICS_FOR_TESTING` or already moved to a
`SimpleTimer`. The call-count-per-ledger ratio is a fast sanity
check: if it doesn't roughly match the expected per-tx fan-out,
the calls are not on the parallel apply hot path. Tracy `Update`
mean times also include zone-enter/exit overhead, which can
mimic light contention even when the mutex is uncontended.
