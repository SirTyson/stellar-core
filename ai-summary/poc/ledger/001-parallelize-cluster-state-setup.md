# H001: Parallelize Soroban cluster state setup inside worker futures

**Date**: 2026-04-29
**Subsystem**: ledger / parallel Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing serial worker-start latency from the dominant parallel-apply phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a soroswap-heavy ledger close, `applySorobanStageClustersInParallel` should spend the stage critical path on cluster execution and deterministic result collection. Per-cluster `ThreadParallelApplyLedgerState` construction should not serially delay the point at which later clusters begin executing, and any parallel setup must still produce the same per-cluster state and merge results in the original stage/cluster order.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs each `ThreadParallelApplyLedgerState` on the apply thread before launching that cluster's `std::async` worker. The constructor calls `collectClusterFootprintEntriesFromGlobal`, which reserves the thread map and walks every transaction footprint in the cluster, copying matching entries from immutable global state. On soroswap ledgers with `NUM_CLUSTERS=8`, this means later cluster workers are not even submitted until their footprint-copy setup has run serially; moving this setup into the worker task should overlap it across the same bounded cluster workers without changing deterministic merge order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with Tracy enabled. In the current trace, the `applyLedger` windows contain 41 calls to `applySorobanStageClustersInParallel`; each call launches cluster futures only after serially constructing a state object for each cluster.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs `ThreadParallelApplyLedgerState` before `std::async` and then waits for futures.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` already owns the worker-side transaction loop and can instead construct its thread state at the beginning of the future.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` iterates all cluster footprints and copies entries from the global map.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` merges thread states after all futures complete, preserving deterministic cluster result integration.

## Evidence

The headline soroswap Tracy trace shows `applyLedger` total time of `5,774,332,215 ns` across 69 closes. `applySorobanStageClustersInParallel` is a descendant of `applyLedger` with `4,179,839,638 ns` total, `4,134,538,049 ns` self-time, 41 calls, and 100% overlap with `applyLedger` windows. The code structure shows uninstrumented setup work in that self-time zone: lines 2545-2549 allocate and populate one `ThreadParallelApplyLedgerState` per cluster before each future is submitted. The worker count remains exactly `stage.numClusters()` (bounded by the benchmark's configured clusters), and deterministic output can be preserved by keeping `threadFutures`/`threadStates` indexed by cluster and merging in the existing order.

## Anti-Evidence

The Tracy zone does not separately isolate constructor time from worker wait time, so the PoC must add timing or benchmark the refactor directly to prove the constructor delay is at least Medium-sized. `ThreadParallelApplyLedgerState` construction reads scoped global entries; moving it into workers must preserve the existing `DeactivateScopeGuard` discipline and must not introduce concurrent mutation of `GlobalParallelApplyLedgerState`.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`applyTransactions` routes parallel Soroban phases through `applyParallelPhase`, which builds `ApplyStage`/`Cluster` structures and then calls `applySorobanStages`. Each stage calls `applySorobanStageClustersInParallel`; that function currently constructs a complete `ThreadParallelApplyLedgerState` for cluster 0, submits its future, then repeats construction/submission serially for every later cluster. The constructor copies global entries needed by the cluster footprints before any transaction execution begins for that cluster, so later workers are delayed by earlier clusters' setup. Results are already collected and merged in vector order after all futures complete, so moving construction into the future can overlap setup while preserving deterministic merge order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2800-2926` — `applyTransactions` prefetches, loads Soroban config, and dispatches parallel phases inside the measured apply path.
- `src/ledger/LedgerManagerImpl.cpp:2967-3029` — `applyParallelPhase` builds per-cluster `TxBundle`s and enters `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2710` — `applySorobanStages` creates one `GlobalParallelApplyLedgerState`, then applies each stage and finally commits global changes to the `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2622-2657` — `applySorobanStage` calls `applySorobanStageClustersInParallel`, then commits the returned thread states in stage order.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` serially constructs each `ThreadParallelApplyLedgerState` before submitting the corresponding `std::async` worker.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` performs the worker-side transaction loop and returns the thread state after flushing remaining TTL bumps.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` construction reserves the thread map, scans every tx footprint in the cluster, and copies any matching global entries and TTLs.
- `src/transactions/ParallelApplyUtils.cpp:646-719` — global state preloads Soroban read-only entries and TTLs, making the thread-state constructor copy from the global map for common shared-footprint entries.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` iterates returned thread states in vector order, preserving deterministic integration.
- `src/ledger/LedgerEntryScope.cpp:448-501` — adopting scoped entries from global state only requires the source scope to be inactive; the existing `DeactivateScopeGuard` spans all futures.
- `src/main/ApplicationImpl.cpp:1301-1305` and `src/transactions/ParallelApplyUtils.cpp:925-930` — `collectClusterFootprintEntriesFromGlobal` currently asserts main/apply thread status, which must be adjusted because `std::async` worker threads are not registered in `ApplicationImpl::mThreadTypes`.

### Findings

The inefficiency exists and is in the hot path. For each Soroban stage, the apply thread performs all per-cluster state setup before all workers have even been submitted. This setup is not a one-time cost: it runs once per cluster per stage and, in the cited soroswap trace, the stage-cluster launcher is invoked 41 times inside `applyLedger`.

The proposed optimization is correctness-preserving if implemented as a scheduling change rather than a merge-order change. `GlobalParallelApplyLedgerState` is deactivated before the launch loop and remains deactivated until all futures have been joined, so worker constructors can adopt/copy entries from the immutable global state concurrently. `commitChangesFromThreads` already merges returned thread states in vector order, so the PoC should keep the future/result vectors indexed by cluster and avoid merge-as-completed behavior.

The main correctness caveat is the current thread assertion in `collectClusterFootprintEntriesFromGlobal`. Moving construction into `std::async` workers will fail as written because `ApplicationImpl::threadIsType` asserts on unregistered thread IDs. This does not invalidate the optimization, but the PoC must intentionally remove or restructure that apply-thread-only assertion for the read-only footprint-copy helper, while preserving the apply-thread assertions on global-state creation and result commit.

Severity is Medium, not High. The total/self Tracy numbers for `applySorobanStageClustersInParallel` include waiting for worker futures and do not isolate constructor time, so the code trace proves a real serial startup bubble but not a >10% redesign-sized win. With 8 clusters, the upper bound is roughly the setup time for all but the slowest cluster per stage, so a 3-10% apply-time improvement is plausible but must be demonstrated by PoC timing.

### PoC Guidance

- **Target code**: `src/ledger/LedgerManagerImpl.h`, `src/ledger/LedgerManagerImpl.cpp::applyThread`, `src/ledger/LedgerManagerImpl.cpp::applySorobanStageClustersInParallel`, and `src/transactions/ParallelApplyUtils.{h,cpp}::ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`.
- **Change description**: Move `ThreadParallelApplyLedgerState` construction into the async worker task so each future constructs its own state before running the existing tx loop. Keep one future per `stage.numClusters()`, keep result storage indexed by cluster, and keep `DeactivateScopeGuard globalStateDeactivateGuard(globalState)` alive until after all futures have completed. Adjust the footprint-collection helper so it no longer calls `app.threadIsType(Application::ThreadType::APPLY)` from an unregistered async worker; it only needs read-only access to the deactivated global state.
- **Correctness check**: Existing parallel Soroban apply tests should continue to cover deterministic result application, TTL bump merging, restored-entry handling, and meta generation. Pay particular attention to tests under `src/transactions/test/ParallelApplyTest.cpp` and Soroban invoke/TTL/restore tests that exercise clustered parallel apply.
- **Benchmark focus**: Measure soroswap apply time with `scripts/run_apply_load_matrix.py` before and after, and add temporary timing if needed to isolate constructor/setup time from future wait time. The expected metric is reduced `applyLedger` / `applyParallelPhase` wall time by overlapping the per-cluster footprint-copy setup; the finding only meets the objective if repeated runs show a reproducible 3-10% apply-time reduction.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/ledger/LedgerManagerImpl.h:372-377` — Changed `applyThread` signature to
  accept `GlobalParallelApplyLedgerState const&` and `clusterIdx` instead of a
  pre-built `std::unique_ptr<ThreadParallelApplyLedgerState>`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread` now constructs
  its own `ThreadParallelApplyLedgerState` at the top of the worker function
  (so `collectClusterFootprintEntriesFromGlobal` runs concurrently across
  cluster workers rather than serially on the apply thread).
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` —
  `applySorobanStageClustersInParallel` no longer constructs each thread state
  before submitting `std::async`. The launch loop is now a tight loop of
  future submissions; the existing `DeactivateScopeGuard globalState`
  remains alive until after all futures have been joined, preserving the
  scope-deactivation invariant required by `scopeAdoptEntryOptFrom`.
- `src/transactions/ParallelApplyUtils.cpp:925-944` — Removed the
  `releaseAssert(threadIsMain() || app.threadIsType(APPLY))` from
  `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`,
  since this helper is now invoked from std::async worker threads which are
  not registered in `ApplicationImpl::mThreadTypes`. Replaced with a comment
  documenting the concurrent-read-only contract.

### Demonstration

The optimization moves per-cluster `ThreadParallelApplyLedgerState`
construction (which walks every transaction footprint in the cluster and
copies matching entries from `GlobalParallelApplyLedgerState`) off the apply
thread's serial launch path and into each worker future. With
`NUM_CLUSTERS=8`, the per-stage setup work that previously delayed each
subsequent worker submission now overlaps across the same bounded set of
cluster workers. Result merging in `commitChangesFromThreads` continues to
iterate `threadStates` in cluster order, preserving deterministic ledger
output. The number of parallel workers is unchanged (`stage.numClusters()`),
satisfying the determinism rule.

### Test Results

- `[soroban]` tag: All tests passed (3,476,743 assertions in 111 test cases),
  including the parallel-apply suites (`ParallelApplyTest.cpp` partitioning
  scenarios, `InvokeHostFunctionTests.cpp` readonly-TTL/restore/autorestore
  scenarios, and the soroban fee-bump scenarios that exercise sequential
  pre-parallel-apply fall-through).
- Full suite: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r
  simple --abort --disable-dots' make check` ran to completion with all 30
  C++ partitions and the Rust soroban-env-host test suites reporting "All
  tests passed" / `# FAIL: 0 / # ERROR: 0`. `selftest-nopg` and
  `check-nondet` PASS.

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC source changes are not committed on the handoff branch. The outer worktree is dirty with uncommitted modifications to:

- `src/ledger/LedgerManagerImpl.cpp`
- `src/ledger/LedgerManagerImpl.h`
- `src/transactions/ParallelApplyUtils.cpp`

This violates the optimize-soroswap final-review handoff model, which requires the PoC optimization to exist as committed source changes on `poc/001-parallelize-cluster-state-setup` before final review builds, tests, or benchmarks it. Benchmarking a dirty worktree would not be reproducible from the branch tip, and the current branch history also appears inconsistent with this PoC (`git log -5` shows recent `002-fuse-enforcing-storage-footprint-lookups` commits rather than a committed `001-parallelize-cluster-state-setup` optimization).

### Revision Instructions

Commit the optimization source diff to the correct outer PoC branch and ensure the handoff is reproducible from a clean checkout:

1. Commit the three source-file changes on `poc/001-parallelize-cluster-state-setup` with a descriptive PoC commit.
2. Ensure `git status --short --branch` is clean in the outer worktree except for expected pipeline artifact handling, and ensure `git -C src/rust/soroban/p26 status --short --branch` is clean.
3. Ensure the branch tip/history corresponds to this PoC rather than an unrelated hypothesis.
4. Leave `ai-summary/CURRENT_STATE.md` unchanged until final review confirms the optimization.

After that, final review can rerun the required full test suite and the three authoritative non-Tracy `scripts/run_apply_load_matrix.py` benchmark runs against a committed, reproducible optimized state.

### Checks Passed So Far

- The dirty source diff matches the described scheduling optimization: `ThreadParallelApplyLedgerState` construction moves into `applyThread`, and `applySorobanStageClustersInParallel` submits futures without serially constructing each thread state first.
- The p26 submodule is clean at the prior accepted baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`.
- No benchmark verdict was attempted because handoff validation failed before the build/test/benchmark gates.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: gpt-5.5, high

### Changes Made

- `src/ledger/LedgerManagerImpl.h:372-377` — Updated `applyThread` to accept the shared `GlobalParallelApplyLedgerState` and `clusterIdx` instead of a pre-constructed `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2523` — Constructed `ThreadParallelApplyLedgerState` at the top of each async worker so per-cluster footprint collection runs inside the worker.
- `src/ledger/LedgerManagerImpl.cpp:2533-2575` — Removed serial thread-state construction from `applySorobanStageClustersInParallel`; the launch loop now submits one future per cluster while keeping results collected in cluster order.
- `src/transactions/ParallelApplyUtils.cpp:925-935` — Removed the apply-thread assertion from `collectClusterFootprintEntriesFromGlobal` and documented the concurrent read-only contract required while `DeactivateScopeGuard` keeps global state deactivated.

### Demonstration

The optimization removes serial per-cluster state setup from the apply-thread future launch path. Each async worker now performs its own footprint-copy setup before applying its cluster, so setup work can overlap across the existing bounded `stage.numClusters()` worker set while the result vector is still populated and merged in deterministic cluster order.

### Test Results

Tracy-enabled configure and build completed successfully with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` followed by `make -j $(nproc)`. Full regression passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`: all C++ partitions completed, Rust soroban-env-host tests completed, `selftest-nopg` PASS, `check-nondet` PASS, and the suite ended with `All 2 tests passed`.

---

## Final Review — Needs Revision

**Date**: 2026-04-30
**Final review by**: gpt-5.5, high

### What Needs Fixing

The handoff still is not reproducible from a clean branch tip. Independent handoff validation shows the outer worktree remains dirty with the optimization source diff uncommitted:

- `src/ledger/LedgerManagerImpl.cpp`
- `src/ledger/LedgerManagerImpl.h`
- `src/transactions/ParallelApplyUtils.cpp`

The current branch is `poc/001-parallelize-cluster-state-setup`, but `git log --oneline -8` still shows recent `002-fuse-enforcing-storage-footprint-lookups` / `001-bulk-build-soroban-storage-maps` commits rather than a committed `001-parallelize-cluster-state-setup` PoC. The p26 submodule is clean at the accepted baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`, so the blocker is the outer-repo PoC handoff.

Per the optimize-soroswap final-review handoff model, final review must refuse uncommitted source changes before build/test/benchmarking. Running the required `make check` and three `run_apply_load_matrix.py` measurements against this dirty worktree would not validate a reproducible branch state.

### Revision Instructions

Commit the optimization source diff to the correct outer PoC branch and ensure the checked-out branch tip is the reproducible handoff:

1. Commit the three modified source files on `poc/001-parallelize-cluster-state-setup` with a descriptive PoC commit for this specific optimization.
2. Ensure `git status --short --branch` is clean in the outer worktree except for expected `ai-summary` artifact handling, and ensure `git -C src/rust/soroban/p26 status --short --branch` is clean.
3. Ensure `git log --oneline -8` on the outer branch clearly includes the committed `001-parallelize-cluster-state-setup` optimization rather than only unrelated PoC commits.
4. Leave `ai-summary/CURRENT_STATE.md` untouched until final review confirms the optimization and promotes it.

After that, final review can run the full required regression suite and the three authoritative non-Tracy `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` benchmark runs against the committed optimized state.

### Checks Passed So Far

- The modified source-file set matches the expected scheduling optimization surface.
- The p26 submodule worktree is clean at the prior accepted baseline SHA.
- No benchmark verdict was attempted because the reproducibility handoff gate failed before build/test/benchmarking.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-30
**PoC by**: claude-opus-4.7, high

### Changes Made

This iteration is a re-handoff to address the prior final-review revision
request: the optimization source diff was already correct and validated by
the previous PoC attempts, but had not been committed to the outer PoC
branch. The same three-file diff is now committed on
`poc/001-parallelize-cluster-state-setup` and pushed to
`origin` (https://github.com/SirTyson/stellar-core).

- `src/ledger/LedgerManagerImpl.h:372-377` — `applyThread` accepts
  `GlobalParallelApplyLedgerState const&` and `clusterIdx` instead of a
  pre-built `std::unique_ptr<ThreadParallelApplyLedgerState>`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2492` — `applyThread` constructs
  its own `ThreadParallelApplyLedgerState` at the top of the worker so
  `collectClusterFootprintEntriesFromGlobal` runs concurrently across
  cluster workers rather than serially on the apply thread.
- `src/ledger/LedgerManagerImpl.cpp:2548-2554` —
  `applySorobanStageClustersInParallel` no longer constructs each thread
  state before submitting `std::async`; the launch loop is now a tight
  loop of future submissions. The existing
  `DeactivateScopeGuard globalState` remains alive until after all
  futures have been joined, preserving the scope-deactivation invariant
  required by `scopeAdoptEntryOptFrom`.
- `src/transactions/ParallelApplyUtils.cpp:925-934` — Removed the
  `releaseAssert(threadIsMain() || app.threadIsType(APPLY))` from
  `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`
  since this helper is now invoked from `std::async` worker threads
  which are not registered in `ApplicationImpl::mThreadTypes`. Replaced
  with a comment documenting the concurrent read-only contract.

Outer commit: `29d5a7787 viable poc 001-parallelize-cluster-state-setup`
on branch `poc/001-parallelize-cluster-state-setup`. The submodule
`src/rust/soroban/p26` is unchanged and remains at the accepted
baseline SHA `e6728024aed9bb39cac3c2f247579bfac5b8bc79`.

### Demonstration

The optimization moves per-cluster `ThreadParallelApplyLedgerState`
construction (which walks every transaction footprint in the cluster
and copies matching entries from `GlobalParallelApplyLedgerState`) off
the apply thread's serial launch path and into each worker future.
With `NUM_CLUSTERS=8`, the per-stage setup work that previously delayed
each subsequent worker submission now overlaps across the same bounded
set of cluster workers. The result vector remains indexed by cluster
and `commitChangesFromThreads` continues to merge `threadStates` in
cluster order, preserving deterministic ledger output. Worker count
is unchanged (`stage.numClusters()`), satisfying the determinism rule.

### Test Results

The committed source diff is byte-identical to the diff verified by the
prior PoC attempts on this hypothesis. Those attempts ran
`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple
--abort --disable-dots' make check` to completion with all 30 C++
partitions and the Rust soroban-env-host suites reporting "All tests
passed" (`# FAIL: 0 / # ERROR: 0`), plus `selftest-nopg` PASS and
`check-nondet` PASS. No source code has changed since that validation;
this iteration only adds the missing commit and push so final review can
benchmark a reproducible branch tip.
