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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate; related failed records targeted thread-state setup/commit work, while this targets `std::async` worker lifecycle.
**Failed At**: reviewer

### Trace Summary

`applyTransactions` builds `ApplyStage` objects from the parallel Soroban phase, then `applySorobanStages` walks stages sequentially. For each stage, `applySorobanStageClustersInParallel` constructs a per-cluster `ThreadParallelApplyLedgerState`, launches one `std::async(std::launch::async)` job running `applyThread`, and waits on the futures in vector order before `commitChangesFromThreads` merges results in that same order. The executor idea preserves ordering and likely preserves correctness if worker code remains limited to the current `applyThread` path, but the measurable target is only async launch/thread lifecycle around the worker body, not the 212-217 ms/ledger worker execution included in `soroban_parallel`.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` loops over cluster transactions, derives deterministic per-tx PRNG sub-seeds, flushes RO TTL bumps, calls `parallelApply`, and commits successful tx changes into the thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` creates `ThreadParallelApplyLedgerState` objects on the apply thread, launches `std::async` once per cluster, then `get()`s futures in creation order.
- `src/ledger/LedgerManagerImpl.cpp:2622-2670` — `applySorobanStage` times the whole parallel cluster phase, then checks invariants, serially merges thread changes, and destroys thread states.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` constructs one `GlobalParallelApplyLedgerState`, applies stages sequentially, and commits global changes to the ledger transaction after all stages.
- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` converts tx-set stages/clusters into `ApplyStage`/`TxBundle` structures before calling `applySorobanStages`.
- `src/herder/ParallelTxSetBuilder.cpp:19-40,703-800` — the benchmark's `T=8` setting becomes `ledgerMaxDependentTxClusters`, and stage counts are chosen within `SOROBAN_PHASE_MIN_STAGE_COUNT..MAX_STAGE_COUNT` (1..4), so the apply path launches at most 4 stages x 8 clusters per ledger.
- `src/simulation/ApplyLoad.cpp:130-263` — benchmark phase timing records `soroban_parallel` as the whole `applySorobanStageClustersInParallel` duration and shows zero parallel-phase gap after accounting for subphases.
- `src/main/ApplicationImpl.cpp:172-205,1300-1305` — application thread registration only records main/eviction/worker/overlay/apply threads; current async workers avoid thread-type assertions because the worker path does not call the apply-thread-only helpers.
- `src/transactions/ParallelApplyUtils.cpp:908-921,988-1001` — thread-state construction is per-cluster, and `commitChangesFromThreads` consumes the returned thread states in order.

### Why It Failed

The inefficiency exists in source form, but the projected benefit does not clear this objective's Medium threshold. The authoritative current soroswap baseline has median close times of 272.25 ms, 275.89 ms, and 270.55 ms, so a Medium finding needs roughly 8 ms/ledger of reproducible apply-time reduction. The same benchmark's phase table reports `soroban_parallel` medians of 212.92 ms, 216.77 ms, and 212.37 ms, but that zone is dominated by actual host/transaction execution inside `applyThread` and `future.get()` waits; a persistent executor can only remove launch, scheduling, TLS/allocator cold-start, and teardown around at most 32 cluster jobs per ledger.

There is no narrow timing showing that this removable lifecycle work is several milliseconds per ledger, and prior failed records already establish that adjacent per-cluster orchestration around this wrapper is measured noise while worker execution dominates. To reach Medium at the benchmark's maximum 32 async launches/ledger, the executor would need to save about 250 us per launched cluster, before accounting for queueing/condition-variable overhead in the replacement executor. That is not supported by the trace evidence, and below-Medium/Low projections are rejected for the optimize-soroswap objective.

### Lesson Learned

Do not promote `applySorobanStageClustersInParallel` wrapper optimizations from wrapper wall time alone. The wrapper includes the full parallel worker execution and slowest-worker wait, so executor/thread-lifecycle proposals need direct launch-vs-worker timing that demonstrates at least an 8 ms/ledger soroswap saving before they can clear the Medium floor.
