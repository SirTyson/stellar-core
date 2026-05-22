# H054: Persistent thread-affine `ThreadParallelApplyLedgerState` reuse across stages and ledgers

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Sub-noise — projected ≤ 0.4% apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each soroswap apply spawns 8 `std::async(std::launch::async, ...)` futures
in `applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2537-2575`); each worker constructs a
`ThreadParallelApplyLedgerState` with a fresh per-stage `mThreadEntryMap`
(reserved capacity, unordered_map nodes allocated), runs the cluster's
transactions, and then is destroyed at stage end. Across the 70-ledger
benchmark each ledger does this once (soroswap has one Soroban stage per
ledger), so the trace contains ~560 worker-state allocations and 560
unordered_map ctor/dtor cycles. The expected efficient path would pin the
worker pool to physical threads, keep each worker's `ThreadParallelApplyLedgerState`
shell alive across stages (and ledgers), and on each cluster only `.clear()`
+ re-`reserve()` the entry map rather than allocate and free its
bucket array.

## Mechanism

Today, every cluster runs in a freshly spawned `std::async` task. The thread
itself is taken from libstdc++'s async thread pool (which already amortizes
OS thread creation), but the `ThreadParallelApplyLedgerState` is allocated
via `std::make_unique<>` in the main thread, transferred to the worker via
the captured reference, populated, and destroyed at worker return. Its
`mThreadEntryMap` is an `UnorderedMap<LedgerKey, LedgerEntryPtr>` whose
bucket array is `malloc`ed at `reserve(estimatedEntries)` time and `free`d
when the unique_ptr is reset post-stage. With ~250-tx clusters and ~8
footprint+TTL keys reserved per tx, this is roughly a 2,000-slot bucket
array allocated and freed for every cluster of every ledger — ~560 malloc/
free pairs per benchmark, plus the per-node allocator churn for the
populated map entries.

## Trigger

Soroswap apply-load benchmark. Each Soroban-bearing ledger close triggers
8 worker-state allocations + destructions. The proposed reuse would hold a
fixed-size pool of 8 worker-state shells per stellar-core process, only
`.clear() + .reserve()`-ing the entry map per cluster.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2537-2575` —
  `applySorobanStageClustersInParallel` (would draw worker-state shells from
  a per-application pool)
- `src/transactions/ParallelApplyUtils.h:128-...` —
  `ThreadParallelApplyLedgerState` (would add `resetForCluster(...)` method
  to repopulate without reallocating bucket arrays)
- `src/main/ApplicationImpl.cpp` — would own the per-worker shell pool

## Evidence

- 70 ledgers × 8 clusters = 560 allocate-then-free cycles for the worker
  state and its bucket array over the trace.
- `unordered_map::clear()` empties node storage but typically does not free
  the bucket array, so a reused map skips both the bucket-array malloc/free
  and the bucket-array re-zeroing on each reserve.

## Anti-Evidence

- Per H051's direct sizing, the entire per-cluster ctor work — including
  the bucket-array allocation and the populate loop — is well under 1 ms
  per cluster on soroswap. The bucket-array malloc/free portion alone is a
  small fraction of that (a single `malloc` of ~32 KB plus a `free` is
  sub-microsecond on a warm allocator).
- The dtor work after `commitChangesFromThreads` runs on a nearly-empty
  map (fail H024: ~100 ns), so the dtor saving is essentially zero.
- The objective's NUM_CLUSTERS rule pins worker count to the config, so
  pool sizing matches; but the per-stage ctor cost is already ≤ 1 ms per
  cluster aggregate and the malloc/free fraction is sub-100 µs per ledger.
- Reusing worker-state across ledgers introduces a coordination contract
  with the apply thread (the pool must be reset before the next apply,
  and `LedgerEntryScope` adoption must be re-driven cleanly), which is
  intrusive review surface for sub-100 µs savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `002-persistent-soroban-worker-pool`
(which proposed reusing *threads* and was rejected because `future.get()`
wait dominates worker launch overhead). This hypothesis specifically
targets reuse of the per-cluster `ThreadParallelApplyLedgerState` shell
and its unordered_map bucket array allocation, not the OS thread.

### Why It Failed

Below the objective's 3% Medium floor by sizing, and below the 1% Low
threshold. The total per-cluster ctor work is ≤ 1 ms (H051), and the
bucket-array malloc/free sub-component is at most a few hundred
microseconds per ledger across all 8 clusters. Even a 100% elimination of
that sub-component recovers ≤ 0.4 ms/ledger ≈ 0.15% of the 272 ms
soroswap baseline. The dtor saving is essentially zero (H024: the map is
empty post-commit). Per the objective's severity rules, Low projections
are not accepted at the hypothesis stage; this is sub-Low.

Additionally, reusing worker-state across ledgers requires a non-trivial
coordination protocol with the apply thread (pool reset, `LedgerEntryScope`
re-adoption per stage, RO TTL bump buffer reset) — disproportionate
complexity for ≤ 0.15% expected wins.

### Lesson Learned

Per-cluster object-allocation elimination in `applySorobanStageClustersInParallel`
is bounded by the ≤ 1 ms/cluster ctor envelope established by H051 and the
≤ 100 ns dtor envelope established by H024. Allocator-reuse pools for this
path cannot reach Low severity; future structural changes to per-cluster
state must remove an actual work item from the ctor body (footprint copy,
TTL-key derivation, entry-map population), not just amortize the bucket
array's lifetime.
