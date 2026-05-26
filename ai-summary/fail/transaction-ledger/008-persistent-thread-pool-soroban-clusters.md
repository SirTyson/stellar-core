# H008: Replace std::async-per-cluster with persistent worker thread pool

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Low (projected)
**Impact**: parallel apply launch overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2531–2575`) launches one worker per cluster
via `std::async(std::launch::async, &LedgerManagerImpl::applyThread, ...)` on
every Soroban stage of every ledger. For a steady-state apply-load run
(70 ledgers × 1 stage × `NUM_CLUSTERS = 8` clusters = 560 launches), each call
constructs and joins an OS thread (libstdc++'s `std::async(launch::async)`
implementation creates a fresh `std::thread` per call — there is no built-in
pool). Even on Linux with `pthread_create` measured at ~10–30 µs per spawn,
560 spawns/join pairs sum to ~6–17 ms over the trace, and the per-ledger
critical path absorbs the spawn cost serially before the workers can start
applying any tx work.

A persistent thread pool with `NUM_CLUSTERS` long-lived worker threads,
each pulling cluster work from a per-stage handoff queue, would eliminate
the per-ledger spawn/join cost entirely. Expected behavior: cluster work
dispatched to an already-running worker in O(condvar-signal) time rather
than O(pthread_create) time.

## Mechanism

`std::async(std::launch::async, ...)` in libstdc++ allocates and starts a
fresh `std::thread` on each invocation and the returned `std::future`'s
destructor joins it. There is no pool reuse. For our pattern of "launch 8
workers, wait for all, do a tiny serial fold, launch 8 more" repeated 70+
times per benchmark, every launch round pays full thread-creation cost.

A pool design owned by `LedgerManagerImpl` (sized at `NUM_CLUSTERS`) would
park workers on a condition variable between stages, allowing the apply
thread to wake them via `notify_all` and join them via a barrier.
Per-cluster wall time saved is roughly `pthread_create + pthread_join`
serialization on the apply thread; estimate ~20 µs × 8 clusters /
serial-launch loop = ~160 µs/ledger if launches were fully serial, but
because libstdc++ launches each thread immediately and the workers start
running while subsequent threads are still being spawned, the apply-thread
critical-path cost is essentially the time to call `pthread_create` 8 times
serially before the first `future.get()` blocks. That is ~80–240 µs/ledger.

## Trigger

Run the soroswap apply-load benchmark on the current `soroswap-perf`
baseline. Observe Tracy `applySorobanStageClustersInParallel` self-time
includes the synchronous spawn loop before any cluster work executes.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2531–2575` —
  `applySorobanStageClustersInParallel`: replace `std::async` loop with
  pool dispatch.
- `src/ledger/LedgerManagerImpl.h` — add `mClusterWorkerPool` member.
- `src/ledger/LedgerManagerImpl.cpp` constructor — initialize pool at
  apply-thread startup, tear down at shutdown.

## Evidence

- libstdc++ `std::async(launch::async)` does NOT pool threads
  (confirmed via libstdc++ source: each call creates a fresh
  `_State_baseV2::_M_run_deferred_or_async_thread` allocating a
  `std::thread`).
- 70 ledgers × 8 clusters/ledger = 560 thread creations per benchmark run.
- The `applyThread` body (`LedgerManagerImpl.cpp:2484–2521`) is short and
  the per-cluster launch+join cost is amortized over only ~250 txs/cluster
  on soroswap, so spawn overhead is a non-trivial fraction of per-cluster
  setup time.

## Anti-Evidence

- On modern Linux glibc, `pthread_create` is ~10 µs typical (cached stack,
  no preallocated TLS); the apply-thread critical-path cost of 8 serial
  spawns is ~80 µs/ledger, not 240 µs.
- Pool workers parked on a condvar still cost ~5 µs each to wake
  (`futex_wake` + scheduler dispatch); the saving relative to spawn is
  ~5–15 µs/cluster, not the full spawn cost.
- Pool design must integrate with `LedgerEntryScope` thread-affinity
  asserts in `ParallelApplyUtils.cpp:914,929` (currently the asserts pass
  because `std::async` threads are typed via `app.threadIsType(APPLY)` —
  pool threads would need the same `ThreadType` registration).
- The `applySorobanStageClustersInParallel` Tracy zone self-time
  (2.66 s aggregate / 71 ledgers / 8 = ~4.7 ms/cluster wall) is dominated
  by `future.get()` blocking on the slowest cluster's worker (per fail
  #006 / Meta-Pattern 6), NOT by spawn overhead. The slowest-cluster wait
  is a floor that pool reuse cannot lower.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail #054 (persistent thread-state
pool — that one targeted per-cluster ledger-state ctor allocation, not
the thread object itself).

### Why It Failed

Direct sizing of the saving:

- Optimistic: 8 spawns × 25 µs serial-launch cost = 200 µs/ledger.
- Optimistic relative to 207 ms soroswap median = 0.097%.

Even doubling the pthread_create estimate to a pessimistic 50 µs per
spawn still caps the saving at ~0.19% of apply time — an order of
magnitude below the 1% Low floor and two below the 3% Medium floor.

The real cost of `applySorobanStageClustersInParallel` is the
slowest-cluster wait at `future.get()` (per fail #006 and Meta-Pattern
6), which is bounded by worker execution time, not by `std::thread`
creation. A persistent pool does not change `future.get()` wait time
because the workers spend ~99% of their wall on `parallelApply`
host execution, not on startup.

Furthermore, the pool would have to maintain `LedgerEntryScope`
thread-affinity safety (each pool worker is reused across ledgers and
across global/thread/tx scopes); the existing per-call `std::async`
threads die between calls and naturally clear scope state. Adding pool
support to the scope discipline (`ParallelApplyUtils.cpp:914,929`)
is a non-trivial correctness change for a sub-0.2% saving.

### Lesson Learned

`std::async(launch::async)` not being pooled is a real cost but it is
fundamentally bounded by `pthread_create` cost (~10–50 µs), and for any
benchmark whose per-launch worker body is in the millisecond range the
launch overhead is sub-Low. For `applySorobanStageClustersInParallel`
specifically, the per-cluster worker body is multi-millisecond and the
spawn cost is sub-1% of cluster wall. Future thread-pool hypotheses for
the parallel apply path should target paths that launch hundreds or
thousands of short-lived workers per ledger, not the 8/ledger
cluster-launch pattern.
