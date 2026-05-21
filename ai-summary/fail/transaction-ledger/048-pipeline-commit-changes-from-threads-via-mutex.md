# H048: Fold `commitChangesFromThreads` into worker threads via mutexed incremental merge

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / parallel apply stage commit
**Severity**: Low
**Impact**: Sub-noise — projected ≤ 0.4 ms/ledger critical-path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all cluster worker threads in `applySorobanStageClustersInParallel`
complete, `LedgerManagerImpl::applySorobanStage` calls
`GlobalParallelApplyLedgerState::commitChangesFromThreads`
(`src/ledger/LedgerManagerImpl.cpp:2656`) on the apply thread to fold each
`ThreadParallelApplyLedgerState`'s entry map and restored-entries map back
into the global parallel-apply state. The expected efficient path is to
overlap this fold with still-running workers: as each cluster worker
finishes, it could acquire a coarse global-state mutex and fold its own
changes directly, so by the time `applySorobanStage` returns from
`future.get()` on the slowest worker, the global state is already up to
date and no further serial fold work remains.

## Mechanism

Today, the per-thread fold is a strictly serial post-parallel pass on the
apply thread that runs *after* every worker has finished (joined via
`future.get()`). Workers that finish early sit idle while the apply thread
waits for the slowest cluster. The actual deviation from expected behavior
is that the per-thread merge work — iterating `mThreadEntryMap` and merging
into `mGlobalEntryMap`, plus merging `mThreadRestoredEntries` into
`mGlobalRestoredEntries` — happens serially on a single thread after all
workers complete, even though it could be performed by each worker
immediately upon completion (with mutex serialization at the merge boundary)
to hide some of its cost behind the slowest worker's remaining execution.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.
Tracy `commitChangesFromThreads` aggregate self-time is ~60.8 ms across
43 stages in the soroswap trace (≈ 1.4 ms/stage critical-path on the apply
thread, ≈ 0.86 ms/ledger averaged across 71 ledgers, or higher on the
hot soroswap ledgers that have non-trivial cluster fan-out).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2545-2572` — `applySorobanStageClustersInParallel` worker dispatch and `future.get()` join loop
- `src/ledger/LedgerManagerImpl.cpp:2656-2660` — `applySorobanStage` calls `commitChangesFromThreads` after join
- `src/transactions/ParallelApplyUtils.cpp:898-925` — `commitChangesFromThread` / `commitChangesFromThreads` implementation
- `src/transactions/ParallelApplyUtils.h:244-251` — fold-API surface

## Evidence

- `commitChangesFromThreads` is strictly serial after the join and runs in
  the apply-thread tail of every parallel stage.
- Cluster workers in soroswap are commonly imbalanced (true footprint-conflict
  clusters with different tx counts), so the fastest-finishing workers have
  idle time during which their fold could complete in parallel.

## Anti-Evidence

- `commitChangesFromThreads` aggregate is ~60.8 ms / 43 stages = 1.4 ms/stage,
  most of which is iteration cost over the per-thread entry maps; mutex
  acquisition and per-key fold are unavoidable regardless of where they
  execute.
- The fold mutates `mGlobalEntryMap` and `mGlobalRestoredEntries`, which are
  scoped under the `GlobalParApply` `LedgerEntryScope`. Letting worker threads
  mutate global-scope state changes the ownership discipline that
  `LedgerEntryScope` enforces (cross-scope writes are intentionally
  prohibited to prevent cross-thread bugs).
- The `addRestoresFrom` invariant requires sequential ordering of restore
  records across clusters in a stage to match the expected meta output; a
  mutex serializes the work but does not free workers to fold in parallel
  with each other.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `004-parallelize-commit-changes-from-threads.md`
(which proposed parallelizing the fold *across* per-thread maps, requiring
invasive `LedgerEntryScope` rescoping). This variant proposes *pipelining*
the per-thread fold behind the slowest worker via a coarse mutex held only
during the per-thread merge, leaving `LedgerEntryScope` discipline intact
within each worker's exclusive ownership window.

### Why It Failed

Sizing against the Medium 3% floor (≈ 8.2 ms/ledger on the 272 ms soroswap
baseline):

- `commitChangesFromThreads` is ≈ 0.86 ms/ledger averaged across 71 ledgers
  (60.8 ms / 71). On a hot soroswap ledger this is likely 2-3 ms wall-clock
  at most.
- The *maximum* recoverable savings from pipelining is bounded by the
  per-cluster fold time × (T-1) workers, but mutex serialization at the
  merge point means at most one worker is folding at any moment. The
  critical path is reduced only by the amount of fold work that completes
  while the slowest worker is still running. With ~8 workers and roughly
  proportional fold work per worker, the realistic critical-path saving is
  on the order of (slowest worker time − slowest cluster execution time) ×
  fold fraction — typically a fraction of the 0.86 ms/ledger total.
- Optimistic upper bound: ≈ 0.4 ms/ledger critical-path saving. That is
  ≈ 0.15% of apply time — well below the Low 1% noise floor and three
  orders of magnitude below the Medium 3% floor.
- The mutex-protected cross-scope fold also crosses the
  `LedgerEntryScope::ThreadParApply → GlobalParApply` boundary inside the
  worker, which (a) needs new `DeactivateScopeGuard` plumbing or a
  scope-adoption helper and (b) changes the established discipline that
  the global-scope state is only mutated by the apply thread.

### Lesson Learned

The serial `commitChangesFromThreads` fold in
`applySorobanStage` is on the order of 0.4-0.9 ms/ledger of critical-path
work. Pipelining it via a mutexed incremental merge inside the worker
threads — even when treated as a more conservative alternative to the
fully-parallel fold rejected in `004-parallelize-commit-changes-from-threads.md`
— still cannot reach the Medium floor and adds non-trivial
`LedgerEntryScope` boundary crossings. Future optimizations to the
post-parallel commit handshake must either (a) remove the fold entirely by
having workers write directly to a unified data structure (a structural
redesign with its own correctness implications, ruled out as NOT_VIABLE in
`001-direct-to-ltx-writeback-eliminate-global-entry-map.md`), or (b)
abandon this code path: every hypothesis attacking the apply-thread tail
of `applySorobanStage` from any angle has now landed sub-Low.
