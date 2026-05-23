# H006 (self-rejected): Skip Soroban RO Entry Pre-load in `fetchSorobanReadOnlyEntries from footprints` when InMemorySorobanState Lookup Is Already Cheap

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Low (projected)
**Impact**: removal of pre-load loop in `GlobalParallelApplyLedgerState` ctor
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The Soroban RO pre-load loop
(`src/transactions/ParallelApplyUtils.cpp:653-718`) eagerly copies every
unique RO Soroban entry (and its TTL) from `InMemorySorobanState` into
`mGlobalEntryMap` during setup. The stated purpose is "to avoid
thousands of redundant per-thread `InMemorySorobanState::get` calls". If
`InMemorySorobanState::get` is itself cheap (an unordered_map lookup) and
worker threads already have lock-free read access, the pre-load is
near-pure overhead: it pays the same lookup cost upfront *and* duplicates
the entries into `mGlobalEntryMap`, doubling memory traffic and
potentially hurting cache locality on the worker side.

## Mechanism

The pre-load runs sequentially in `GlobalParallelApplyLedgerState`
constructor and iterates every tx's RO footprint, calling
`mInMemorySorobanState.get(lk)` and `mInMemorySorobanState.get(ttlKey)`
for each unique key. For soroswap (~222 applied txs × ~6 RO Soroban keys
= ~1 332 iterations / ledger, dedup'd to ~50 unique keys by the
`mGlobalEntryMap.find` guard), the pre-load does ~50 lookups in
`InMemorySorobanState` and 50 entry copies. Workers would otherwise pay
the same ~50 lookups distributed across 8 threads. The pre-load saves
**zero** unique lookups; it just moves the cost from worker threads to
the main thread and adds map insertions on top.

## Trigger

Soroswap apply-load with the standard `tx=2000, t=8` config; the
`fetchSorobanReadOnlyEntries from footprints` Tracy zone fires once per
ledger.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:646-718` — the pre-load loop
  inside `collectModifiedClassicEntries`.

## Evidence

- Tracy zone `fetchSorobanReadOnlyEntries from footprints` self-time is
  ~131 µs/ledger total in the current soroswap trace.
- Comment on line 646-653 explicitly says the purpose is to avoid
  per-thread redundant lookups in `InMemorySorobanState::get`.

## Anti-Evidence

- The comment cites SAC-transfer workloads where "all TXs share the same
  read-only entries (contract instance), this saves thousands of
  redundant lookups per thread." That benefit may be real on max-sac but
  is small on soroswap.
- Pre-loading also unifies the entry under `mGlobalEntryMap`, which lets
  the worker-side `getLiveEntryOpt` skip the `InMemorySorobanState`
  branch entirely. Removing it would force every worker tx to go through
  `InMemorySorobanState::get` per RO key.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a removal candidate

### Why It Failed

The pre-load zone itself is only ~0.131 ms/ledger (Tracy
`fetchSorobanReadOnlyEntries from footprints`). Even fully eliminating
it is below the 1 % Low floor (0.06 % of ~218 ms close). The structural
argument cuts both ways: the pre-load *does* unify worker lookups
through a single map (saving aggregate worker time per ledger that does
not show up cleanly in this zone but in the worker-side
`InMemorySorobanState::get` call count). Without a measured worker-side
ceiling that exceeds the pre-load cost, removal is at best neutral and
at worst a regression on max-sac.

### Lesson Learned

A pre-load step whose Tracy zone is sub-millisecond and which serves a
documented cross-thread dedup purpose should not be removed without
counter-measuring the aggregate worker-side lookup cost it eliminates;
moving cost between phases is not the same as eliminating it. Meta-pattern
6 ("Aggregate Worker Time ≠ Critical-Path Time") cuts both ways here:
the pre-load saves *aggregate* worker time but the saving on the
critical path after dividing by 8 workers is itself sub-millisecond, so
neither direction of change reaches the Medium floor.
