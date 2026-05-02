# H002: Persistent bounded Soroban apply-worker executor instead of per-stage `std::async`

**Date**: 2026-05-02
**Subsystem**: soroban / ledger parallel apply
**Severity**: Medium
**Impact**: Apply-time tail reduction in `applySorobanStageClustersInParallel` for soroswap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban stages should still execute at most `NUM_CLUSTERS` clusters concurrently, preserve deterministic per-stage cluster ordering, merge thread results in the same order, and produce identical transaction results, ledger changes, metadata, diagnostics, and PRNG sub-seeds. The apply path should not create cold unmanaged `std::async` workers for every stage if a bounded executor can run the same cluster jobs on stable apply-worker threads and return results in cluster-index order.

## Mechanism

`LedgerManagerImpl::applySorobanStageClustersInParallel` currently constructs a thread state for each cluster and immediately launches `std::async(std::launch::async, &LedgerManagerImpl::applyThread, ...)`, then waits on the futures in vector order. This leaves thread creation, scheduler placement, per-thread allocator/TLS cold start, and worker teardown on the critical path of each stage. A persistent executor with exactly `stage.numClusters()`/`NUM_CLUSTERS` deterministic job slots can keep registered apply workers alive across ledgers, preserve result ordering by writing each returned `ThreadParallelApplyLedgerState` into its cluster index, and reduce long-tail wall time without increasing parallelism or changing merge order.

## Trigger

Run the soroswap apply-load benchmark (`TX=2000, T=8`) and inspect the Tracy trace from `ai-summary/CURRENT_STATE.md`. Stages with multiple Soroban clusters enter `applySorobanStageClustersInParallel`, launch one async worker per cluster, and block until the slowest worker completes before committing thread changes.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the cluster job body that can be run unchanged by a persistent bounded executor.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` currently owns per-stage future creation, `std::async` launch, ordered `future.get()`, and result collection.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` construction remains per-cluster and deterministic; the executor must not share mutable ledger state across jobs.
- `src/transactions/ParallelApplyUtils.cpp:908-921` — `commitChangesFromThreads` already consumes `threadStates` in stage order, so the executor result array can preserve the existing deterministic merge order.
- `src/main/ApplicationImpl.cpp:172-205` — current long-lived application worker/apply threads are registered; a persistent Soroban executor should either register its worker threads consistently or avoid thread-type assertions in code paths not owned by those workers.

## Evidence

The current trace confirms that the target wrapper is wholly inside the apply window: `applySorobanStageClustersInParallel` has 42/42 events inside `applyLedger`, totaling 3,467,944,842 ns, with a max event of 590,367,166 ns and very high variance. Source inspection shows the function launches a new async task for every cluster at `LedgerManagerImpl.cpp:2545-2553` and then synchronously waits for every future at `2556-2572`. The proposed executor does not rely on unsafe extra parallelism: it uses the same cluster count, same `applyThread` body, same PRNG sub-seed derivation by `txBundle.getTxNum()`, and same ordered merge, so determinism is maintained.

This is distinct from the repeatedly rejected "parallelize thread-state setup" path. Those attempts moved `ThreadParallelApplyLedgerState` construction and footprint walks into workers and regressed due to memory/cache pressure. This hypothesis keeps the per-cluster state semantics intact and targets per-stage worker lifecycle and scheduling overhead around the existing worker body.

## Anti-Evidence

Most of `applySorobanStageClustersInParallel` wall time is real worker execution behind `future.get()`, not launch overhead, so a PoC must isolate thread lifecycle/scheduling cost with narrow timing before claiming the whole 3.47 s wrapper. There is also a related transaction-ledger failure where a worker-pool handoff had no committed implementation; this hypothesis must be judged only if the source actually contains a reproducible executor change. If the platform's `std::async` implementation already reuses threads or if worker lifetime overhead is below a few milliseconds per representative ledger, the optimization will fall below the objective's Medium threshold.
