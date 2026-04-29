# H019: Fuse the Three Per-Stage Iterations in GlobalParallelApplyLedgerState Constructor

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Low (rejected — below objective threshold)
**Impact**: Setup-phase loop overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState`'s constructor should iterate the
`stages → cluster → txBundle → footprint` tree at most once during setup,
co-locating: (a) `mGlobalEntryMap.reserve` size estimation, (b) the
`requiresSequentialPreParallelApply` classification, and (c) the
`fetchSorobanReadOnlyEntries from footprints` pre-loading pass. A single
fused pass would be cache-friendlier than three independent traversals.

## Mechanism

Today the constructor performs three distinct full traversals of all
stages/clusters/txBundles:

1. `src/transactions/ParallelApplyUtils.cpp:405-417` — reserve estimation
   loop (just counts footprint sizes).
2. `src/transactions/ParallelApplyUtils.cpp:446-462` —
   classification loop (calls `requiresSequentialPreParallelApply`).
3. `src/transactions/ParallelApplyUtils.cpp:657-718` — soroban-RO pre-load
   loop in `collectModifiedClassicEntries`.

Each pass touches the same set of footprint XDR objects. Fusing them
should reduce L2/L3 cache traffic on the apply thread.

## Trigger

Run the soroswap apply-load matrix and look for any reduction in
`soroban_setup_glbl`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:405-417` — reserve loop
- `src/transactions/ParallelApplyUtils.cpp:446-462` — classification loop
- `src/transactions/ParallelApplyUtils.cpp:657-718` — RO pre-load loop

## Evidence

The three loops independently traverse the same footprint XDR data, which
on cold cache lines costs ~tens of cycles per footprint key access.

## Anti-Evidence

- Tracy aggregates: combined cost of the *bodies* of loops 1 and 3 is
  ≤0.2 ms/ledger (`fetchSorobanReadOnlyEntries from footprints` 0.15 ms;
  the reserve loop is uninstrumented but is purely integer arithmetic on
  ≤2000 cache-hot integers).
- Loop 2's cost is dominated by `LedgerSnapshot::load` calls, *not* by the
  iteration overhead — fusing it with the others doesn't reduce the load
  count, which is the actual bottleneck (see hypothesis H003).
- Hypothesis H003 attacks the underlying load-count cost directly; fusing
  on top of H003 would deliver only the residual cache-traffic win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below the objective's Medium severity floor (3% apply time = ~9 ms/ledger).
Best-case savings from loop fusion are sub-millisecond per ledger
(<0.3% of apply time): the iteration overhead itself is tiny compared to
the per-step work each loop does, and once H003 removes the
`LedgerSnapshot.load` cost from loop 2, the remaining structure already
runs in microseconds. The objective explicitly rejects Low-severity
hypotheses at the hypothesis stage.

### Lesson Learned

Loop-fusion micro-optimizations on cache-hot data structures yield
sub-millisecond wins that fall below benchmark noise; pursue them only
when bundled with a larger structural change to the same code (e.g., as
a free side effect of a redesign already chosen for a different reason).
