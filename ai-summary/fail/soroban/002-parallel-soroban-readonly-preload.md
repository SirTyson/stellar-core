# H002: Parallelize Soroban read-only footprint preload in GlobalParallelApplyLedgerState

**Date**: 2026-04-29
**Subsystem**: soroban (parallel-apply setup)
**Severity**: Low
**Impact**: apply-thread critical path (parallel-apply preflight)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState::collectModifiedClassicEntries` (which also
preloads Soroban read-only footprint entries at lines 654-718 of
`src/transactions/ParallelApplyUtils.cpp`) should add at most a negligible
amount of latency to the apply path; alternatively, if it is a non-trivial
cost it should overlap with other apply-path work (e.g., the classic apply
phase or the `applySorobanStages` clustering computation) rather than running
strictly serially before the parallel apply phase.

## Mechanism

The single-threaded loop iterates every stage × txBundle × readOnly footprint
key, deduplicating against `mGlobalEntryMap` and calling
`mInMemorySorobanState.get(lk)` (and a second `get` for the TTL key) for each
unique key. For soroswap with 4000 txs × ~2-3 RO entries/tx the de-duplicated
key set could reach a few thousand keys, each costing a hash + map find +
shared_ptr copy + emplace into `mGlobalEntryMap`. If the cost were measurable
on the apply critical path, sharding the loop across worker threads or moving
it into a `std::async` overlapping with `collectModifiedClassicEntries`'s
classic-key load would be a viable optimization.

## Trigger

Observe wall-clock contribution of the
`fetchSorobanReadOnlyEntries from footprints` Tracy zone on the apply
thread during a soroswap apply-load run.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:600-719` —
  `GlobalParallelApplyLedgerState::collectModifiedClassicEntries` and
  the embedded RO preload loop (lines 654-718).
- `src/bucket/InMemorySorobanState.cpp` — `InMemorySorobanState::get` is
  the per-key lookup being repeated.

## Evidence

The loop is structurally serial and fans out across all stages × txs ×
RO-footprint keys. With high tx counts it could plausibly add up.

## Anti-Evidence

Tracy measurement on the current baseline trace
(`/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`)
shows the zone consumes only **2.5 ms cumulative across 66 invocations**
(mean 38 µs per ledger), i.e. ~0.006% of the 596 ms soroswap median apply
time. Even completely eliminating the work would yield a delta deep below
benchmark noise. The sibling `collectModifiedClassicEntries` zone is also
only 10 ms cumulative (~0.025% per ledger). These two combined fall well
below the 1% noise floor and far below the Medium severity threshold (3-10%
= 18-60 ms per ledger). Soroswap footprints contain only a small handful of
unique RO Soroban keys per cluster (the swap-pair instance + token
contracts + their TTLs), and the dedup check at line 668 short-circuits
nearly all repeated work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a parallel preload

### Why It Failed

The targeted preload loop costs **2.5 ms cumulative** across the entire
65-ledger trace (38 µs/ledger). Even a hypothetical 100% elimination is
below benchmark noise (>10× below the 1% floor at 596 ms baseline) and
roughly 1000× below the Medium severity threshold. The dedup check on
line 668 already collapses the nominal O(stages × txs × footprint) loop
to O(unique-RO-keys), and for soroswap that set is tiny (a handful of
contract instance + TTL keys per cluster).

### Lesson Learned

Before proposing parallelization or async restructuring of an apply-path
helper, measure its wall-clock cost in the live trace. The parallel-apply
preflight (`GlobalParallelApplyLedgerState` ctor) is already cheap; the
real apply-thread waste lives downstream in `applySorobanStageClustersInParallel`
(43 ms wall per stage), `finalizeLedgerTxnChanges`/`addLiveBatch` (7-8 ms
mean, with multi-tens-of-ms spikes), and worker-thread `Vm::invoke_function_raw`
(bulk of compute time). Future optimizations should target those zones.
