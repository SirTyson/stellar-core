# H006: Apply Thread Work-Steals from Slowest Cluster During future.get() Wait

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Medium (projected)
**Impact**: parallel apply utilization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStageClustersInParallel` (`src/ledger/LedgerManagerImpl.cpp:2530–
2574`) should keep all 9 threads (8 std::async workers + the apply thread) doing
useful Soroban tx work during the cluster execution window. The apply thread
currently spends the cluster window blocked at `threadFuture.get()` (line 2561)
with no CPU work to do, while one of the 8 cluster workers is on the critical
path because its cluster is the slowest. If the apply thread could co-execute
the tail of the slowest cluster's tx list, total parallel-apply wall time would
drop toward the next-slowest cluster's wall.

For the soroswap trace, Tracy shows `applySorobanStageClustersInParallel` at
63.2 ms/stage inclusive, while per-worker `parallelApply` aggregate is ≈ 270 ms
per stage → mean cluster wall ≈ 33.7 ms; observed wall 63 ms ⇒ slowest cluster
is ~2× mean. The ~30 ms gap between mean and max is the cluster-load
imbalance "tail". If the apply thread executes the tail txs of that slowest
cluster, the stage wall could drop by up to ≈ 15 ms (assuming the apply
thread takes ~half of the tail before the second-slowest cluster catches up).

## Mechanism

The current launch loop (line 2545) constructs one `ThreadParallelApplyLedgerState`
per cluster and dispatches each cluster's tx list to its own std::async worker.
The apply thread then serially `future.get()`s the futures. There is no
mechanism for the apply thread to take any tx work itself, and no mechanism for
faster workers to take work from slower ones.

Proposed mechanism: introduce a lock-free atomic index inside each cluster's tx
list. Both the cluster's worker and any other thread that has completed its own
cluster (including the apply thread) can `fetch_add` to claim the next tx in
the slowest-running cluster's tail. Each tx within a cluster is still executed
in canonical order because the atomic counter advances monotonically and each
worker simply takes the next available index.

If this worked, it would reclaim ~15 ms/ledger ≈ 7% of soroswap apply time
median (207 ms). That would be a Medium-severity win.

## Trigger

Run the soroswap apply-load benchmark. Observe `applySorobanStageClustersInParallel`
wall ≈ 63 ms/stage with apply-thread idle (no zones in Tracy between the launch
loop and the join loop).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530–2574` — `applySorobanStageClustersInParallel`
  launch/join loop; would need to host the work-stealing dispatch.
- `src/transactions/ParallelApplyUtils.h/.cpp` — `ThreadParallelApplyLedgerState`
  effects buffers; would need to support reassignment of a tx-slot's effects to
  a different thread state's output.
- `src/transactions/ParallelApplyStage.h/.cpp` — `Cluster` iteration; would need
  to expose an atomic-index iterator instead of `for (auto const& txBundle : cluster)`.

## Evidence

- Per-tx mean apply time is uniform (1.44 ms μ, 0.16 ms σ in worker self-time)
  per Tracy stats — so cluster imbalance is purely from uneven tx counts per
  cluster, NOT from per-tx variance.
- Apply thread is observably idle during the cluster window: Tracy zone times
  sum to ~64.6 ms (clusters 63.2 + commitChangesFromThreads 1.4) within the
  64.7 ms `applySorobanStage` parent — apply thread does essentially nothing
  during the 38.3 ms/ledger cluster wait window.
- 8 workers + 1 apply thread = 9 cores available; `NUM_CLUSTERS = 8` so adding
  the apply thread to the worker pool does not violate the cap.

## Anti-Evidence

- **True intra-cluster footprint conflicts.** fail #022 (cluster splitting
  infeasible) and Meta-Pattern 7 establish that txs within the same cluster
  have OVERLAPPING read-write footprints — that is precisely why they are in
  the same cluster. Two threads cannot execute two such txs concurrently
  without violating the deterministic per-key apply order that the cluster
  contract guarantees.
- Even ordered atomic-index work-stealing within a cluster cannot run any two
  txs in parallel, because the cluster's contract is that subsequent txs see
  the writes of earlier txs in canonical order via
  `ThreadParallelApplyLedgerState`'s entry map. Stealing a tx onto a different
  thread state would require either (a) merging dirty state from the original
  worker (synchronous handoff = same critical path) or (b) running both txs
  serially on the steal-acceptor (= same as leaving them in the original
  worker).
- fail #013 / H060 (apply-thread-runs-cluster-zero) already measured the
  apply-thread-as-9th-worker pattern at ≤ 2.1% ceiling — and that variant did
  NOT face the conflict problem because it owned the whole cluster.
- The premise of "tail txs in the slowest cluster" assumes the slowest cluster
  has the most txs; if instead it has txs with the highest per-tx host-fn cost
  (long-running invokes), even stealing the last tx doesn't help because no
  other thread can run it concurrently with the cluster's owner thread.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — work-stealing across clusters is distinct from fail #013
(apply thread becomes its own static cluster) and fail #022 (cluster splitting
at construction time).

### Why It Failed

Intra-cluster ordering is **semantically** serial, not just incidentally serial.
A cluster is a tx group with overlapping read-write footprints whose canonical
execution order is part of the consensus contract — txs within a cluster
observe each other's writes through the shared
`ThreadParallelApplyLedgerState`. Work-stealing requires two threads to make
forward progress on the same cluster concurrently, which is incompatible with
this contract: any handoff either (1) waits for the donor to finish (no
parallelism gained) or (2) lets two threads race on the cluster's entry map
(determinism broken, fails consensus).

The only way to shed wall time from the slowest cluster is to redistribute its
txs at *cluster construction time* — but fail #022 already established that
those txs are in the same cluster because their footprints actually conflict.
Splitting them would produce inconsistent results across nodes.

### Lesson Learned

For the cluster-imbalance pattern (max ≈ 2× mean wall), runtime work-stealing
is structurally blocked by the cluster invariant — txs within a cluster MUST
execute in canonical order on a single thread of state. Any future hypothesis
attempting to reduce parallel-apply imbalance must operate at cluster
*construction time* (and prove footprints don't actually conflict — fail #022
strongly suggests they do) OR move to a non-cluster execution model entirely
(redesign-scale change far outside hypothesis scope).
