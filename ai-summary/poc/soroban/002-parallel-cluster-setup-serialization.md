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

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The apply path reaches this code from `applyTransactions` into `applyParallelPhase`, which builds `ApplyStage`/`Cluster` bundles and calls `applySorobanStages`. `applySorobanStages` creates one `GlobalParallelApplyLedgerState`, then for each stage calls `applySorobanStage`, which times `applySorobanStageClustersInParallel` as the `sorobanParallelApplyMs` phase. In the current implementation, every `ThreadParallelApplyLedgerState` is constructed on the apply thread before its corresponding `std::async` launch, and that constructor walks the whole cluster footprint, probes/copies from the global map, copies restored-entry state, clones the module cache, and copies the apply snapshot. Soroswap's benchmark setup creates exactly `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` pairs and round-robins swaps across them, while the benchmark asserts one stage with the configured max-cluster count, so this serialized per-cluster setup is on the measured closeLedger hot path for the target `TX=4000,T=8` scenario.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2964` — `applyTransactions` loads Soroban config, dispatches parallel phases, records apply-stage metrics, and returns the measured transaction-apply result.
- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` converts tx-set stages into `ApplyStage`/`Cluster` objects and then calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState` once, applies each stage, commits global changes to the `LedgerTxn`, and records subphase timing.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` wraps `applySorobanStageClustersInParallel`, invariant checks, thread-state merge, and thread-state destruction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` deactivates the global scope, then constructs each `ThreadParallelApplyLedgerState` synchronously before launching `applyThread` with `std::async`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` only performs per-transaction apply work after receiving an already-constructed thread state.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — `ThreadParallelApplyLedgerState` construction copies global restored entries and calls `collectClusterFootprintEntriesFromGlobal`, which reserves by scanning every tx footprint, walks RW and RO keys, derives TTL keys for Soroban entries, probes `globalEntryMap`, and copies matching scoped entries.
- `src/transactions/ParallelApplyUtils.cpp:371-384` — comments document the intended model: thread state must copy what it needs before worker execution because global maps/snapshots are not used mutably by thread objects.
- `src/transactions/ParallelApplyUtils.cpp:893-922` — global state is not merged from threads until after all futures complete and thread states are returned.
- `src/ledger/LedgerEntryScope.cpp:448-520` — scope adoption from global to thread checks that the source scope is inactive and then copies the entry; `DeactivateScopeGuard` in `applySorobanStageClustersInParallel` already establishes this before construction.
- `src/ledger/LedgerEntryScope.cpp:526-535` — `DeactivateScopeGuard` deactivates on construction and reactivates on destruction, matching the lifetime needed while worker constructors adopt from the global scope.
- `src/main/AppConnector.h:50-64` and `src/main/AppConnector.cpp:127-130` — `getModuleCache` is listed with thread-safe methods and forwards to `LedgerManager::getModuleCache`.
- `src/ledger/LedgerManagerImpl.cpp:954-961` and `src/rust/src/soroban_proto_any.rs:761-770` — `getModuleCache` shallow-clones the Soroban module cache; the Rust side describes the underlying reusable module cache as thread-safe and intended for C++-launched threads.
- `src/ledger/LedgerStateSnapshot.h:122-125` and `src/transactions/ParallelApplyUtils.cpp:526-583` — `LedgerStateSnapshot` is copyable with fresh file caches, and read-only pre-parallel apply already copies/uses the same apply snapshot from multiple worker threads.
- `src/simulation/ApplyLoad.cpp:2261-2334` — benchmark timing measures closeLedger/apply time, resolves bucket futures before measurement, and asserts one stage with the configured max dependent clusters.
- `src/simulation/ApplyLoad.cpp:2652-2682` and `src/simulation/ApplyLoad.cpp:3382-3507` — soroswap setup creates one pair per dependent cluster and swap generation round-robins transactions across those pairs with 5 RO and 5 RW footprint entries per swap.
- `scripts/run_apply_load_matrix.py:74-125` and `scripts/run_apply_load_matrix.py:417-425` — the active soroswap matrix scenario uses `TX=4000,T=8`, and the script maps `thread_count` to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.

### Findings

The inefficiency exists: the constructor work is not merely bookkeeping, because it performs two full cluster-footprint walks for reservation and collection, constructs `ParallelApplyLedgerKey` wrappers, computes TTL keys for Soroban entries, performs unordered-map lookups in the global entry map, copies scoped ledger entries into the thread map, copies restored-entry tracking, shallow-clones the module cache, and copies the apply snapshot. This all happens in a strict loop on the apply thread before each future launch, so with 8 clusters the launch schedule is serialized by the sum of all cluster setup times rather than allowing setup to overlap.

The path is hot for the objective: `benchmarkModelTxTpsSingleLedger` measures `closeLedger`, the soroswap scenario is active in `run_apply_load_matrix.py` with 4000 transactions and 8 clusters, and the benchmark asserts that the produced tx set has one stage with exactly the configured cluster count. Each soroswap swap has a moderately large footprint (5 RO entries and 5 RW entries, most Soroban entries having TTL probes), and the transaction generator round-robins across the cluster-specific pairs, so the constructor loop scales with the target workload rather than being one-time setup outside the measured window.

The proposed fix is correctness-preserving in shape. `GlobalParallelApplyLedgerState` is fully built before stage execution, is deliberately deactivated while thread state adopts entries, and is not mutated until `commitChangesFromThreads` runs after all futures have joined. The global entry map and restored-entry map can therefore be read concurrently as immutable state, `LedgerStateSnapshot` is designed for thread-safe copied snapshots, and `getModuleCache`/Rust shallow clone are documented as thread-safe for C++-launched threads. The implementation should still avoid capturing a loop-local `cluster` reference accidentally; capture either the cluster reference from `stage.getCluster(i)` with a stable lifetime tied to `stage`, or capture the cluster index and resolve it inside the worker.

The projected impact plausibly meets the objective's Medium floor but should be benchmark-gated. The full 1.68s Tracy self-time is an upper bound because it includes real `future.get()` wait and load imbalance, but the serialized constructor work is directly removable from the apply-thread launch critical path. For the target 8-cluster soroswap case, moving setup from `sum(setup_i) + max(work_i)` toward `max(setup_i + work_i)` can recover up to about seven-eighths of the setup component when clusters are balanced, which is a credible 3-10% apply-time improvement if the constructor accounts for only a modest fraction of the observed per-stage self time.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.h` and `src/ledger/LedgerManagerImpl.cpp` signatures for `applyThread` / `applySorobanStageClustersInParallel`; `src/transactions/ParallelApplyUtils.cpp` only if a helper/lambda boundary is clearer than changing `applyThread` directly.
- **Change description**: Launch each worker before constructing its `ThreadParallelApplyLedgerState`. The worker should construct `std::make_unique<ThreadParallelApplyLedgerState>(app, globalState, cluster, clusterIdx)` inside the async callable and then execute the existing per-transaction loop, returning the completed state. Keep `DeactivateScopeGuard globalStateDeactivateGuard(globalState)` alive across all worker construction and execution.
- **Correctness check**: Preserve global-state deactivation during thread-state adoption, preserve deterministic cluster order when collecting returned `threadStates` and when `commitChangesFromThreads` iterates them, and ensure no async lambda captures the loop variable `i` or `cluster` by dangling reference.
- **Benchmark focus**: Compare `scripts/run_apply_load_matrix.py` for the active `soroswap,TX=4000,T=8` scenario over repeated runs. The expected improvement should show up in top-line close/apply time and in the phase table's `soroban_parallel` / `parallel_total` rows; adding a temporary Tracy zone around thread-state construction can split constructor time from `future.get()` wait if the result is ambiguous.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-27
**PoC by**: gpt-5.5, high

### Changes Made

- `src/ledger/LedgerManagerImpl.h:372-377` and `src/ledger/LedgerManagerImpl.cpp:2483-2553`: changed `applyThread` to receive `GlobalParallelApplyLedgerState`, `Cluster`, and `clusterIdx`, construct its own `ThreadParallelApplyLedgerState` on the async worker, and launch futures without doing per-cluster thread-state construction on the apply thread.
- `src/transactions/ParallelApplyUtils.h:114-116` and `src/transactions/ParallelApplyUtils.cpp:924-996`: removed the now-invalid main/apply-thread registration assertion from `collectClusterFootprintEntriesFromGlobal`, since the helper is private to thread-state construction and now intentionally runs on unregistered `std::async` worker threads while reading immutable global state.

### Demonstration

The launch loop in `applySorobanStageClustersInParallel` now starts each async worker immediately and passes only stable references plus the cluster index into the future. Each worker overlaps `ThreadParallelApplyLedgerState` construction, including restored-entry copying, module-cache shallow clone, cluster footprint reservation, global-entry lookups, TTL-key derivation, and global-to-thread scoped-entry adoption, with the other clusters instead of serializing that setup on the apply thread. `DeactivateScopeGuard globalStateDeactivateGuard(globalState)` remains alive across worker construction and execution, and futures are collected in launch order, preserving deterministic merge order.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30`. Ran the full suite with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check`; it completed with exit code 0. The final summaries included `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and Rust unit-test summaries with zero failures, including `test result: ok. 750 passed; 0 failed; 2 ignored; 0 measured; 1 filtered out`.
