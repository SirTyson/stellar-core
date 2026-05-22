# H051: Move per-cluster `ThreadParallelApplyLedgerState` construction inside the worker thread to parallelize startup

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Sub-noise — projected ≤ 0.5 ms/ledger critical-path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `LedgerManagerImpl::applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2530-2575`), the per-cluster setup work
— constructing `ThreadParallelApplyLedgerState`, reserving its entry map
(`mThreadEntryMap.reserve(estimatedEntries)`), and walking every transaction
footprint to copy needed entries from `mGlobalEntryMap` via
`collectClusterFootprintEntriesFromGlobal`
(`src/transactions/ParallelApplyUtils.cpp:925-986`) — happens **serially** on
the main apply thread *before* each `std::async` future is launched. The
expected efficient path is for the main thread to immediately launch all 8
worker futures, and have each worker construct its own
`ThreadParallelApplyLedgerState` (and run `collectClusterFootprintEntriesFromGlobal`)
as the first action inside the worker. This would parallelize cluster setup
across the worker pool and remove the staircase startup delay that gives
later-launched clusters less wall time to finish before `future.get()` on the
slowest cluster.

## Mechanism

Today, the loop
```cpp
for (size_t i = 0; i < stage.numClusters(); ++i) {
    auto threadStatePtr = std::make_unique<ThreadParallelApplyLedgerState>(
        app, globalState, cluster, i);
    threadFutures.emplace_back(std::async(std::launch::async,
        &LedgerManagerImpl::applyThread, ...));
}
```
serializes 8 ctor calls before any worker can start its `applyThread` body.
Each ctor runs `mPreviouslyRestoredEntries.addRestoresFrom(...)` plus the
per-tx footprint walk in `collectClusterFootprintEntriesFromGlobal`, which
for a soroswap cluster of ~250 txs × ~8 footprint keys × 2 (key + TTL key)
performs ~4,000 unordered_map probes plus `getTTLKey` SHA256+`xdr_to_opaque`
computations. If the per-cluster ctor takes T ms, cluster i is launched at
i·T ms and has (makespan − i·T) ms to compute before joining. Moving the
ctor into the worker would launch all 8 futures at t≈0 and let each ctor
run in parallel on its own thread.

## Trigger

Run the soroswap apply-load benchmark in `ai-summary/CURRENT_STATE.md`.
Each `applyLedger` iteration enters `applySorobanStageClustersInParallel`
once (one stage), and constructs 8 `ThreadParallelApplyLedgerState` objects
serially before launching workers.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2545-2554` — serial pre-launch ctor loop
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` ctor body
- `src/transactions/ParallelApplyUtils.cpp:925-986` — `collectClusterFootprintEntriesFromGlobal` per-cluster footprint walk
- `src/transactions/ParallelApplyUtils.h:128-...` — `ThreadParallelApplyLedgerState` ctor declaration (would need to accept `unique_ptr<>` to outputs or be split into construct-shell + populate-in-worker phases)

## Evidence

- The ctor loop is strictly serial; later-launched workers start later in
  wall time than earlier ones.
- Each ctor performs `mThreadEntryMap.reserve(...)`, plus
  `collectClusterFootprintEntriesFromGlobal` which iterates ~250 txs ×
  ~16 footprint+TTL keys = ~4,000 lookups with `getTTLKey` (SHA256) on the
  Soroban keys.
- Prior fail `001-parallelize-thread-state-construction.md` rejected a
  similar angle but did so by citing `applySorobanStageClustersInParallel`
  zone self-time as dominated by `future.get()` worker waits — it did not
  directly measure ctor cost on the current baseline.

## Anti-Evidence

- Each unordered_map insert/lookup is ~100 ns and a `getTTLKey` SHA256 over
  a small `LedgerKey` is also sub-microsecond; 8 clusters × ~4,000 ops × a
  few hundred ns is on the order of single-digit milliseconds aggregate,
  not per-cluster. Realistic per-cluster ctor wall time is well under 1 ms.
- `mGlobalEntryMap` is shared and immutable once stage setup completes,
  so concurrent reads from workers are safe; but the design still requires
  `LedgerEntryScope` ownership adoption to be thread-safe at the
  global-scope read side, which is a non-trivial scope-discipline change.
- Even idealized full parallelization saves only the trailing staircase
  ≈ (numClusters − 1) × per-cluster-ctor-time, which is sub-ms per ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — the prior `001-parallelize-thread-state-construction`
fail was framed against generic "thread state construction" and rejected on
profiling-attribution grounds; this hypothesis specifically targets the
serial pre-launch ctor loop. Re-investigation still confirms sub-threshold.

### Why It Failed

Direct sizing of the per-cluster `ThreadParallelApplyLedgerState` ctor work
(an `unordered_map::reserve` of a few thousand slots, plus iteration over
~4,000 footprint+TTL key probes with a `getTTLKey` SHA256) is well under
1 ms per cluster on soroswap. The serial pre-launch staircase therefore
adds at most (numClusters − 1) × <1 ms ≈ a few-hundred-microsecond critical
path tail per ledger — orders of magnitude below the objective's 3% Medium
floor (~8.4 ms/ledger), and well inside benchmark noise. The reviewer's
prior conclusion (`fail/transaction-ledger/001-parallelize-thread-state-construction.md`)
remains correct on the current baseline: the dominant `future.get()` wait is
worker execution, not setup. In addition, moving ctor work into the worker
introduces concurrent reads of `mGlobalEntryMap` and `LedgerEntryScope`
adoption across threads, which expands the `LedgerEntryScope` discipline
surface for sub-millisecond savings — disproportionate complexity.

### Lesson Learned

The serial pre-launch ctor loop in `applySorobanStageClustersInParallel`
is bounded by simple unordered_map operations and a few thousand SHA256s
on small keys; even fully parallelized it saves sub-millisecond per ledger
and cannot reach the Medium floor. Future parallelism hypotheses targeting
this region must show a sizing argument that the *serial* fraction of
pre-launch work exceeds ~3 ms/ledger before being promoted to hypothesis.
