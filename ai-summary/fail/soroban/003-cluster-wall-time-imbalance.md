# H003: Cluster Wall-Time Imbalance Reduction in `applySorobanStageClustersInParallel`

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 2-5% soroswap apply-time reduction by reducing the
slowest-cluster wall time in the parallel Soroban stage
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStageClustersInParallel` launches one `std::async` per
cluster (`LedgerManagerImpl.cpp:2545-2554`) and waits for ALL clusters
via `future.get()` (line 2556-2572). The stage's wall time equals the
slowest cluster's wall time. For a balanced workload (clusters with
similar tx counts and similar host-execution costs), this is optimal.
The expected behavior is therefore that clusters be balanced by total
work, not just by tx count. For a soroswap workload that concentrates
swap volume on a small number of hot pools, txs touching the same
pool serialize into the same cluster, and one cluster (the hot-pool
cluster) can carry materially more work than the others, making the
slowest cluster the dominant cost in the parallel stage.

## Mechanism

Cluster construction is owned by tx-set construction (out of scope for
this objective), but cluster *execution* is in scope: the apply path
takes the cluster shape as given and runs them in parallel. If
clusters are unbalanced — e.g. one cluster has 25 txs while others
have 8 — the slowest cluster's wall time dominates the stage and the
seven other workers idle for the difference. The actual deviation
from expected behavior is that the apply-time floor is set by the
hottest pool's work, not by the average.

## Trigger

Reproduce the soroswap apply-load run as in `CURRENT_STATE.md`. Add
per-cluster `ZoneScopedN` instrumentation around each cluster's
sequential tx loop in `applyThread`, run the soroswap diagnostic
trace, and measure (max - min) cluster wall-time per stage. If the
ratio max/avg is consistently >1.3x and the absolute gap exceeds
~5 ms, the imbalance is a measurable apply-time floor.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread`: the
  per-cluster sequential tx loop. The loop body for each tx is
  `flushRoTTLBumpsInTxWriteFootprint` + `parallelApply` +
  `commitChangesFromSuccessfulTx`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` —
  `applySorobanStageClustersInParallel`: the launch + join site. All
  clusters launch immediately via `std::async(std::launch::async,
  ...)`, and the main thread waits for them in declaration order.
- `src/transactions/ParallelApplyUtils.cpp:107-...` —
  `getReadWriteKeysForStage`: where cluster footprints are
  determined (and where any cluster-content rebalance must respect
  determinism).

## Evidence

- The parallel cluster-apply zone is the dominant cost of soroswap
  apply-time (estimated ~50 ms/ledger wall-time at the
  baseline-272 ms median, i.e. ~18%). Even a modest imbalance
  reduction (e.g. capping max/avg at 1.15x instead of 1.3x) would
  recover ~5 ms/ledger ≈ 1.8%. A larger imbalance reduction
  (matching avg cluster wall-time) on a hot-pool-skewed soroswap
  workload would recover up to ~8-15 ms/ledger ≈ 3-5%.
- Prior fails (`fail/soroban/001-parallelize-thread-state-setup.md` and
  `fail/soroban/001-parallel-cluster-setup-serialization.md`)
  established that thread-state SETUP serialization is sub-Medium —
  the dominant cost of `applySorobanStageClustersInParallel` is
  worker EXECUTION behind `future.get()`. That conclusion is
  consistent with the imbalance hypothesis: if execution dominates
  and clusters are unbalanced, the slowest cluster sets the floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — cluster wall-time imbalance has not been directly
investigated as a hypothesis; only setup-cost parallelization was
investigated and rejected.

### Why It Failed

Cluster construction (which determines cluster sizes and contents) is
owned by tx-set construction in `buildSurgePricedParallelSorobanPhase`
and is explicitly **OUT OF SCOPE** per the optimize-soroswap
objective context. The apply path receives clusters as a fixed
input from `phase.getParallelStages()` and cannot redistribute txs
across clusters at apply time without (a) changing the observable
ordering of tx execution within a cluster and (b) crossing into
TX-set-construction territory.

Within the apply path itself, every cluster *already* runs on its
own dedicated `std::async(std::launch::async, ...)` thread (line
2550-2553); they all start in parallel, all run independently, and
the main thread joins them in declaration order. There is no
work-stealing opportunity that preserves determinism: txs within a
cluster share at least one footprint key (that is the definition
of a cluster), and txs across clusters are already disjoint and
already parallel. Reordering or migrating txs across clusters would
change the cluster contents, which is a tx-set-construction
optimization, not an apply-path optimization.

The only apply-path lever left is launch order (so the slowest
cluster gets started first to maximize its overlap with classic
prefetch and other concurrent work). With `std::async(launch::async)`
all clusters start *immediately* — there is no queue to reorder
and no pool with bounded slots — so launch-order optimization has
no effect.

### Lesson Learned

For the parallel Soroban stage, "imbalance" is set at tx-set
construction time, not at apply time. The apply path's only
parallel-stage levers are (i) reducing per-worker execution cost
inside the cluster (the broad surface area covered by every other
host/storage/wasmi micro-optimization hypothesis) and (ii)
overlapping the parallel stage with serial pre-/post-stage work
(which is the angle pursued by hypothesis #002). Imbalance
reduction itself is not an apply-path optimization in this
codebase.
