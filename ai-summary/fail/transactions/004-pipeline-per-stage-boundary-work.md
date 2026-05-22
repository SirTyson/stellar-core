# H004: Pipeline Per-Stage Sequential RW-Key Build and Thread-Commit Across Stage Boundaries

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-stage sequential bottleneck inside `applySorobanStages`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Between consecutive Soroban apply stages, the apply thread should
only block on work that **must** be ordered after stage N's completion
and before stage N+1's first worker dispatch — that is, the commit of
stage N's thread effects into the global state and any state needed by
stage N+1 that cannot be precomputed. Work that is structurally
independent of stage N's worker outputs (notably the read-write-key
scan for stage N+1, which only depends on stage N+1's TxBundle list)
could in principle be computed in parallel with stage N's workers,
shrinking the sequential window between stages.

## Mechanism

Actual behavior: the per-stage loop in
`applySorobanStages` (`ledger/LedgerManagerImpl.cpp:2701-2705`) runs
each stage strictly serially. Inside
`applySorobanStage`, the apply thread synchronously calls:

1. `getReadWriteKeysForStage(stage)`
   (`transactions/ParallelApplyUtils.cpp:104`) — Tracy total 51 ms /
   43 stage events (~1.2 ms / stage), iterates every tx in the stage
   and emplaces footprint RW keys plus TTL keys into a hash set.
2. Worker dispatch via
   `applySorobanStageClustersInParallel` (apply thread waits for all
   futures — 3.42 s self-time across 43 stages).
3. `commitChangesFromThreads`
   (`transactions/ParallelApplyUtils.cpp:908`) — Tracy total 59 ms /
   43 stage events (~1.4 ms / stage), serially merges thread entry
   maps into the global entry map.

Steps (1) and (3) execute back-to-back across the stage boundary
without overlapping each other or with the next stage's worker
dispatch. Even though
`getReadWriteKeysForStage` for stage N+1 depends only on the
already-built `ApplyStage` vector and not on stage N's results, the
current control flow forces it to run after stage N's commit.

## Trigger

Soroswap apply-load run with multiple Soroban stages per ledger.
Tracy shows `applySorobanStage` self-time (3.3 ms / 43 stages),
`getReadWriteKeysForStage` (51 ms total), and
`commitChangesFromThreads` (59 ms total). Across 71 ledgers and
43 stage events, the aggregate sequential boundary work is
~110 ms = 2.16 % of `applyLedger` (5,075 ms total).

## Target Code

- `ledger/LedgerManagerImpl.cpp:2628` — `applySorobanStage` body,
  current ordering of RW-key build, worker dispatch, and commit.
- `transactions/ParallelApplyUtils.cpp:104-132` —
  `getReadWriteKeysForStage` (purely a function of the stage's
  TxBundle list, structurally independent of any prior stage's
  worker output).
- `transactions/ParallelApplyUtils.cpp:908` —
  `commitChangesFromThreads`, currently fully sequential at the end
  of each stage.
- `ledger/LedgerManagerImpl.cpp:2701-2705` — outer stage loop in
  `applySorobanStages` where pipelining would be introduced.

## Evidence

- `getReadWriteKeysForStage` reads only `stage`'s
  `txBundle.getTx()->sorobanResources().footprint.readWrite` —
  no dependency on previous stages' execution outputs.
- Stage boundaries occur 43 times across 71 ledgers (~0.6 stages /
  ledger on average), so there is genuine per-ledger boundary cost
  even at single-stage ledgers (one final commit).
- Existing parallel scheduler exists (workers via `std::async` in
  `applySorobanStageClustersInParallel`), so the infra to overlap
  stage N's tail work with stage N+1's preparation is already in
  place.

## Anti-Evidence

- The total addressable surface is small (51 + 59 ms = 110 ms,
  2.16 % of `applyLedger`). Even perfectly hiding both behind worker
  execution would not reach Medium severity.
- Fail
  `001-parallel-commit-thread-states.md` (transactions/069) already
  rejected a more ambitious commitChangesFromThreads parallelization
  on the same data path because the per-stage cost is too small to
  justify the synchronization overhead.
- Fail
  `001-dependency-dag-soroban-stage-scheduler.md` (transactions/066)
  showed that aggressive cross-stage pipelining for the soroswap
  workload introduces enough scheduling overhead to **regress** the
  benchmark, because the soroswap stage-count distribution rarely
  has independent later-stage clusters to overlap with.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior DAG-scheduler and parallel
thread-commit hypotheses. Those tried to reschedule work across
stages or parallelize commit dirty-entry scans; this candidate
specifically targeted overlapping the *next stage's RW-key precompute*
with the *current stage's worker wait*. No prior record proposed
that exact ordering change.

### Why It Failed

Even fully hiding `getReadWriteKeysForStage` (51 ms) and
`commitChangesFromThreads` (59 ms) behind worker execution recovers
at most 2.16 % of `applyLedger`, below the 3 % Medium floor. The
soroswap workload further reduces realistic recovery because it
averages 0.6 stages / ledger — most ledgers have a single stage with
no "next stage" to overlap with. The transactions-subsystem fails
`069` (parallel commit) and `066` (DAG scheduler) already
established that the synchronization overhead of any cross-stage
pipelining mechanism risks exceeding the recovered savings on this
workload. The aggregate boundary cost is genuinely Low-tier on
soroswap.

### Lesson Learned

The applySorobanStage boundary work (RW-key scan + thread-commit)
is structurally pipelineable but capped at ~2.2 % of `applyLedger`
on soroswap, and the soroswap stage distribution (average 0.6
stages/ledger) makes the practical recovery even smaller. Future
sequential-window hypotheses around stage boundaries need either a
fundamentally different workload (more stages with overlapping
work) or a structural change that converts the dominant
`applySorobanStageClustersInParallel` wait into something
schedulable — not just rearrangement of the small boundary work.
