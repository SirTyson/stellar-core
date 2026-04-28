# H003: Fork addLiveBatch into std::async like addHotArchiveBatch

**Date**: 2026-04-29
**Subsystem**: bucket / ledger (apply-thread BL commit)
**Severity**: Low
**Impact**: apply-thread critical path (post-apply finalization)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3217-3368`), the three independent
post-apply state-update tasks are:

1. `BucketManager::addHotArchiveBatch` — modifies `mHotArchiveBucketList`
2. `BucketManager::addLiveBatch` — modifies `mLiveBucketList`
3. `InMemorySorobanState::updateState` — modifies `mInMemorySorobanState`

Today (1) and (3) run on `std::async` worker threads while (2) runs
synchronously on the apply thread (line 3356). Since all three operate on
independent state, (2) could also be forked to an async worker, joining
all three at the end of `finalizeLedgerTxnChanges`. This would remove
`addLiveBatch` from the apply critical path.

## Mechanism

`addLiveBatch` currently runs sequentially on the apply thread. The Tracy
trace shows it adds wall-clock latency to every ledger that the next
ledger's apply must wait on. The hot-archive variant has already been
shown to be safely async (the existing pattern at lines 3285-3292), so the
mechanical refactor for the live variant is straightforward and
deterministic — `addLiveBatch` writes only into the `mLiveBucketList` and
its bucket-merge futures, none of which feed back into the *current*
ledger's apply path.

## Trigger

Run apply-load with the soroswap config and observe the wall-clock
contribution of the `addLiveBatch` zone on the apply thread.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3368` —
  `LedgerManagerImpl::finalizeLedgerTxnChanges`, especially lines 3354-3357
  where `addAnyContractsToModuleCache` and `addLiveBatch` run sequentially
  on the apply thread.
- `src/bucket/BucketManager.cpp:1031` — `addLiveBatch` entry point.

## Evidence

The hot-archive sibling already uses exactly this `std::async` pattern with
a join at the bottom of the function. Replicating it for the live batch is
a small mechanical diff with no determinism risk: each list is independent,
and the apply thread's existing join points already serialize publication.

## Anti-Evidence

Tracy measurement on the current baseline trace shows
`addLiveBatch` consumes **502 ms cumulative across 66 calls** (mean 7.6 ms,
max 88 ms). Per-ledger mean is 7.6 ms / 596 ms baseline = **1.3%** —
below the 3% Medium severity floor. The async pattern would not eliminate
all 7.6 ms (the apply thread still must wait at the bottom join, which
becomes the new bound: max(addLiveBatch, addHotArchiveBatch,
updateInMemorySorobanState, addAnyContractsToModuleCache)). Currently
addHotArchiveBatch and updateInMemorySorobanState already run async, so
the apply thread already waits long enough that addLiveBatch may not
extend the critical path much beyond what it already is. Net savings are
likely <1% (well within noise) for typical ledgers, with a possible
larger spike-smoothing benefit on the worst-case ledgers (88 ms tail).

The high-variance max (88 ms) suggests bucket-merge spillover at level
boundaries — those ledgers do dominate the tail and could benefit, but
the soroswap median apply time the objective targets is computed from
many ledgers, so tail-ledger savings are diluted.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a viable parallelization
of `addLiveBatch` (prior async-related fails were about deferring entire
batch *commit* to future ledgers, which breaks correctness; this proposal
keeps the join inside the same `finalizeLedgerTxnChanges` call).

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
The mean per-ledger contribution of `addLiveBatch` on the apply thread is
1.3% of baseline (7.6 ms / 596 ms). Even if the async fork eliminated all
of that overhead — which it cannot, since the bottom-of-function join
serializes against the longest of the three siblings — the savings are
sub-Medium (<3%) and likely sub-noise (<1%) once the join bound is
considered.

### Lesson Learned

When a task is "obviously parallelizable", check whether the joining sibling
already dominates. The hot-archive and InMemorySorobanState updates already
run async; the apply thread already waits for max(*siblings*). Adding
`addLiveBatch` to the parallel set only helps if `addLiveBatch` itself is
strictly the longest of the four — and the trace shows the existing async
siblings are roughly comparable, so the new max is similar to the old max.

To get a Medium-severity win in this region, the apply thread would need
to *not* wait at all in `finalizeLedgerTxnChanges` — i.e., publish the
new bucket-list state asynchronously and let the next ledger's apply
consume the updated state when ready. That redesign breaks the
"one ledger close per apply" invariant and conflicts with how the next
ledger's prefetch/parallel-apply preflight expects the BL to be in its
post-state. So this region is not a near-term Medium target.
