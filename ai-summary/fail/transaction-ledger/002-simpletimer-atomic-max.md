# H002: Replace SimpleTimer mutex with atomic CAS for max tracking

**Date**: 2026-04-28
**Subsystem**: transaction-ledger (util / bucket)
**Severity**: Medium
**Impact**: Eliminate cross-thread lock contention on hot point-load timers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A point-load timing helper called from every Soroban worker thread on
every BucketList read should not require any cross-thread synchronization
beyond what is necessary to update the underlying counters. `medida::Counter::inc`
is already atomic (uses `std::atomic`), so `Update` should require only:
(a) an atomic add to `mSum`, (b) an atomic add to `mSampleCount`, and
(c) an atomic max update to `mMax`. None of these need a `std::mutex`.

## Mechanism

`SimpleTimer::Update` (src/util/SimpleTimer.cpp:40-50) takes
`std::lock_guard<std::mutex> lock{mLock}` purely to update `mMax` via
`std::max`. That mutex is shared across every thread that records a
timing for the same timer. The class comment
(SimpleTimer.h:47-51) explicitly notes the mutex exceeds Tracy's 64-thread
per-lock tracking limit — i.e. it is known to be heavily contended in
parallel apply.

`BucketListSnapshot` registers one `SimpleTimer` per `LedgerEntryType`
(BucketListSnapshot.h:99-100, BucketListSnapshot.cpp:75-90), and
`SearchableBucketListSnapshotBase::loadKeys` / `load`
(BucketListSnapshot.cpp:313-346) opens a `TimeScope()` per individual
load. During parallel Soroban apply, all 8 worker threads pound the same
per-type `SimpleTimer` for `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL`
loads triggered by host-fn storage gets and footprint reads.

Replacing `mLock` + `std::max` with an `std::atomic<int64_t> mMax` and a
single CAS loop:

```cpp
int64_t prev = mMax.load(std::memory_order_relaxed);
while (converted > prev &&
       !mMax.compare_exchange_weak(prev, converted,
                                   std::memory_order_relaxed)) {}
```

eliminates the lock entirely. `syncMax()` becomes
`mMax.exchange(0, std::memory_order_relaxed)`. The Tracy-tracking comment
becomes obsolete (no lock to track). Deviation from expected: the current
code introduces a serialization point that is invisible in single-threaded
runs but compounds linearly with worker-thread count during the parallel
apply phase, where these timers are the most-touched cross-thread
synchronization point on the BucketList read path.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap T=8 TX=4000 before and
after the change. The wall-clock improvement should grow with thread
count: rerun at T=4 and T=8 to confirm contention scales with workers.
For a controlled microbench, hammer `SimpleTimer::Update` from N threads
in a loop and measure per-call latency vs the atomic version.

## Target Code

- `src/util/SimpleTimer.h:37-71` — class fields (`mMax`, `mLock`).
- `src/util/SimpleTimer.cpp:26-50` — `syncMax()` and `Update()` lock paths
  to convert to atomic CAS.
- `src/bucket/BucketListSnapshot.cpp:313-346` — primary hot caller
  (`load`, called per footprint key per worker).
- `src/bucket/BucketListSnapshot.cpp:75-90` — per-type timer registration
  showing one shared `SimpleTimer` per `LedgerEntryType`.

## Evidence

- Trace `BucketListSnapshot::load`: 670,130 calls, 277 ms self-time,
  std_ns 14,802 vs mean 413 ns — a 35× standard-deviation/mean ratio
  consistent with lock contention spikes on a hot critical section.
- Class comment at `SimpleTimer.h:47-51` documents that the lock is
  cross-thread-contended enough to crash Tracy's lock-tracker on long
  runs (>64 distinct waiters).
- All three counters (`mSum`, `mSampleCount`, `mMaxSampleValue`) are
  already atomic via medida; the lock guards only `mMax` (a single
  scalar), making the conversion trivial and risk-free.

## Anti-Evidence

- The headline trace shows `BucketListSnapshot::load` mean self-time is
  small in absolute terms (413 ns); the CAS-vs-lock difference per call
  is on the order of 50–200 ns uncontended, with contention adding
  variable µs-scale waits. Worst-case savings could land in the 1–3%
  range of the 596 ms apply baseline (Low/Medium boundary).
- If contention is mostly absorbed by Linux futex fast-path
  (uncontested mutex ≈ atomic CAS in practice), the atomic version may
  show parity rather than a clean win. Benchmark must arbitrate.
- The diff is small enough that even a Low result is worth taking, but
  this hypothesis is being filed as Medium on the theory that the
  documented "exceeds 64-thread tracking" comment indicates the lock IS
  the binding constraint during parallel Soroban apply phases with heavy
  storage reads (soroswap pool gets/sets).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record covers the `SimpleTimer` atomic-max mechanism specifically; nearby metric failures are residual medida histogram gates, not BucketList point-load `SimpleTimer`.
**Failed At**: reviewer

### Trace Summary

The `SimpleTimer` mutex exists and `SearchableBucketListSnapshot::load` does take a per-type point-load `TimeScope`, so the local inefficiency is real for point lookups that reach the BucketList snapshot. However, the hypothesized hot path is wrong: parallel Soroban apply does not pound the BucketList point timers for `CONTRACT_DATA`, `CONTRACT_CODE`, or `TTL` host storage reads. Those types are explicitly routed to `InMemorySorobanState` in `ThreadParallelApplyLedgerState::getLiveEntryOpt`, leaving BucketList point loads mainly for non-in-memory classic keys and snapshot comparison paths. With the claimed dominant Soroban storage-read path removed, the remaining lock removal is a narrow metrics micro-optimization below the objective's Medium threshold.

### Code Paths Examined

- `src/util/SimpleTimer.h:37-51` — `mMax` is guarded by `mLock`, and the comment confirms `SimpleTimer::Update` can be called from many threads.
- `src/util/SimpleTimer.cpp:26-50` — `syncMax()` and `Update()` both lock `mLock`; `Update()` only uses it to update `mMax` after incrementing the sum/count counters.
- `src/util/MetricsRegistry.cpp:10-27` — `NewSimpleTimer` interns timers in a registry map, so each `{domain,type,name}` timer is shared, and `syncSimpleTimerStats()` calls each timer's `syncMax()`.
- `src/bucket/BucketListSnapshot.cpp:74-80` — `SearchableBucketListSnapshot` registers one shared `SimpleTimer` per `LedgerEntryType`.
- `src/bucket/BucketListSnapshot.cpp:313-345` — `SearchableBucketListSnapshot::load` opens a point-load `TimeScope()` and updates the timer on scope exit after searching buckets.
- `src/ledger/LedgerStateSnapshot.cpp:224-228,296-298` — `BucketSnapshotState::load` and `LedgerSnapshot::load` forward snapshot loads to `SearchableLiveBucketListSnapshot::load`.
- `src/transactions/ParallelApplyUtils.h:74-80,190-197` — the parallel apply state comments state that `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` are queried from `InMemorySorobanState`, not `mLiveSnapshot`.
- `src/transactions/ParallelApplyUtils.cpp:1084-1118` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` implements that routing: in-memory Soroban types call `mInMemorySorobanState.get(key)`, while only other keys call `mLCLSnapshot.loadLiveEntry(key)`.
- `src/transactions/ParallelApplyUtils.cpp:134-148,151-207,525-583` — read-only pre-parallel apply can use `LedgerSnapshot` and therefore BucketList point loads, but this is a pre-apply/snapshot-comparison path, not the per-host-function `CONTRACT_DATA`/`CONTRACT_CODE`/`TTL` storage-get path claimed by the hypothesis.
- `src/ledger/InMemorySorobanState.cpp:207-236,413-445` — in-memory lookup paths return `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` entries without touching `SearchableBucketListSnapshot::load` or its point timer.

### Why It Failed

The central hot-path claim is false. Soroswap's high-frequency host-function storage reads of `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` do not contend on the BucketList point-load `SimpleTimer`; they are served from `InMemorySorobanState`. The remaining BucketList point loads for classic keys and snapshot comparisons may still pay the `SimpleTimer::Update` mutex, but the hypothesis's own trace bounds `BucketListSnapshot::load` self-time at 277 ms total with a 413 ns mean, and only a fraction of that self-time can be the max-tracking mutex. After excluding the dominant Soroban storage-read path, replacing the mutex with an atomic max cannot plausibly produce the required 3-10% apply-time reduction for this objective.

### Lesson Learned

Do not infer BucketListDB point-load hotness for Soroban entries from `LedgerSnapshot::load` alone. In parallel apply, `ThreadParallelApplyLedgerState` intentionally bypasses the live BucketList snapshot for `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` by using `InMemorySorobanState`; BucketList point-load timers mostly cover non-in-memory key types and ancillary snapshot reads.
