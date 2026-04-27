# H002: `applySorobanStageClustersInParallel` serializes per-cluster `ThreadParallelApplyLedgerState` setup on the stage critical path

**Date**: 2026-04-27
**Subsystem**: ledger / parallel-apply
**Severity**: Medium
**Impact**: parallel-apply stage critical-path serialization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a Soroban apply stage with `N` clusters is dispatched on `T` worker
threads (with `N <= T = NUM_CLUSTERS`), the per-cluster work — both the
`ThreadParallelApplyLedgerState` construction and the actual transaction
application inside `applyThread` — should run in parallel across the
worker threads. The main apply thread's wall-clock for
`applySorobanStageClustersInParallel` should be approximately
`max_i(setup_i + work_i)` where each `setup_i + work_i` is the total
per-cluster cost on its own thread, yielding ~`T`× speed-up over a
sequential apply for balanced clusters. In particular, the per-cluster
setup work (cluster-footprint walk, hash-map reservation, fetching
entries from the global state map, copying restored-entries info) should
run on the worker thread, not on the main thread before `std::async`
launch.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2530-2575`) currently builds each
`ThreadParallelApplyLedgerState` synchronously **before** spawning the
worker:

```cpp
for (size_t i = 0; i < stage.numClusters(); ++i) {
    auto const& cluster = stage.getCluster(i);
    auto threadStatePtr = std::make_unique<ThreadParallelApplyLedgerState>(
        app, globalState, cluster, i);          // <-- runs on main thread
    threadFutures.emplace_back(std::async(
        std::launch::async, &LedgerManagerImpl::applyThread, this,
        std::ref(app), std::move(threadStatePtr), …));
}
```

The `ThreadParallelApplyLedgerState` constructor
(`src/transactions/ParallelApplyUtils.cpp:988-1001`) calls
`collectClusterFootprintEntriesFromGlobal` (lines 924-986), which:

1. Iterates the entire cluster's footprints to estimate
   `mThreadEntryMap` capacity and `reserve()`s it.
2. Walks every footprint key (RW + RO) of every TX in the cluster,
   probes `globalEntryMap` (a hash map), and copies matching entries
   into `mThreadEntryMap`. Each Soroban key also generates a TTL-key
   probe (line 980-981).
3. Calls `mPreviouslyRestoredEntries.addRestoresFrom(global.getRestoredEntries())`
   which copies the global restored-entries map.

For a stage with 8 clusters of moderately-sized footprints, this work is
a meaningful chunk of per-stage setup that runs *strictly serially* on
the main thread before any worker can start. Because `applyThread` only
begins after its `std::async` call returns from the main thread's
construction step, the slowest cluster's setup blocks every later
cluster from starting at all.

The Tracy baseline shows:

- `applySorobanStageClustersInParallel`
  (`ledger/LedgerManagerImpl.cpp:2537`) self-time = **1.68 s** across
  37 calls — by far the largest "wait/serial" self-time bucket on the
  apply path. (Self-time here counts both `std::async`/`future.get()`
  blocking *and* the inline construction loop.)
- `applySorobanStages` total = 1.79 s; `applySorobanStageClustersInParallel`
  total = 1.70 s. The gap between aggregate `parallelApply` per-tx time
  (4.94 s summed across all worker threads) and wall-clock
  `applySorobanStageClustersInParallel` (1.70 s) implies effective
  thread utilization of only ~36 % even though the config exposes 8
  worker slots. Some of that gap is fundamental (load imbalance between
  clusters), but the serialized setup loop is a direct, removable
  contributor.

Moving construction inside `applyThread` (i.e., pass `globalState`,
`cluster`, and `clusterIdx` into the future and have the worker thread
call the `ThreadParallelApplyLedgerState` ctor) keeps determinism
(constructor is pure w.r.t. inputs that are already const) and lets
setup overlap across clusters.

## Trigger

Run `scripts/run_apply_load_matrix.py` against the `soroswap` scenario
(`TX=4000, T=8`). Soroswap stages have 8 clusters by design (one pair
per dependent cluster — see ApplyLoad memory). Per-cluster setup walks
swap-tx footprints (each tx has multiple RW + RO contract-data + TTL
keys), so the serial construction loop is meaningful in absolute time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2575`
  (`applySorobanStageClustersInParallel`) — restructure to do
  construction inside the `std::async` lambda. Pass `globalState`,
  `cluster`, `clusterIdx`, and `app` by reference / value into the
  worker; the worker constructs its `ThreadParallelApplyLedgerState`
  and then runs the cluster.
- `src/transactions/ParallelApplyUtils.cpp:924-1001`
  (`collectClusterFootprintEntriesFromGlobal` and the
  `ThreadParallelApplyLedgerState` ctor) — verify inputs (global state,
  app connector) are safe to read from worker threads. They are
  already accessed read-only here (the global state map is not mutated
  during the parallel phase; mutation happens in
  `commitChangesFromThreads` after the join).
- `src/ledger/LedgerEntryScope.h` — confirm the `LedgerEntryScope`
  construction (currently invoked in the ctor with
  `ScopeIdT(clusterIdx, global.mScopeID.mLedger)`) is thread-safe to
  perform on the worker; if not, reorder so the scope-id assignment
  stays on the main thread but the heavy footprint walk moves to the
  worker.

## Evidence

- Tracy soroswap trace
  (`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`):
    * `applySorobanStageClustersInParallel` self = 1.68 s / 37 calls
      = ~45 ms wall per stage on the main thread.
    * `parallelApply` (per-tx total summed across worker threads) =
      4.94 s; wall-clock `applySorobanStages` = 1.79 s → effective
      thread utilization ≈ 35 %.
    * `applySorobanStage` total = 1.72 s; `applySorobanStages` total
      = 1.79 s; the ~70 ms gap is per-stage setup before clustering.
- Code inspection confirms the construction loop runs strictly
  serially on the main thread before any worker is launched.
- Pre-existing knowledge in repo memory: "applySorobanStageClustersInParallel
  constructs each ThreadParallelApplyLedgerState before std::async
  launch, so per-cluster state setup stays on the stage critical path"
  — this hypothesis quantifies and proposes a fix.

## Anti-Evidence

- `LedgerEntryScope`'s clusterIdx assignment may have lifecycle
  invariants that require construction on a specific thread; if so, the
  scope object can be created on the main thread but the
  `collectClusterFootprintEntriesFromGlobal` heavy-lifting moved
  separately into the worker via a two-phase init.
- Some of the 1.68 s self-time is genuine `future.get()` wait at
  `threadFutures` join, not setup work — that portion is fundamental
  load-imbalance and not addressable here. We would need a finer-grained
  Tracy zone around the construction loop to split the two contributions
  exactly. Even so, every ms of construction shifted into the workers
  removes work from the critical path of the slowest cluster (it
  shortens the per-cluster setup_i, and only the slowest matters).
- For stages with very few clusters (e.g., 1–2), the win is small.
  Soroswap is configured for 8 clusters per stage, so the leverage is
  maximal there; max-sac may see a smaller benefit.
