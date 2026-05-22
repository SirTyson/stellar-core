# H004: Bypass `ltxInner` Intermediate in `commitChangesToLedgerTxn`

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (projected, sub-Medium)
**Impact**: redundant LedgerTxn insert+commit on Soroban post-apply seam
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Soroban results from `mGlobalEntryMap` should reach the outer `AbstractLedgerTxn&
ltx` parameter with one hash + insert per dirty entry, since the entries are
already in their final state and the `mIsNew` flag has already disambiguated
INIT vs LIVE.

## Mechanism

Today `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn`
(`src/transactions/ParallelApplyUtils.cpp:722`) creates a child
`LedgerTxn ltxInner(ltx)` and inserts every dirty entry into `ltxInner`,
then calls `ltxInner.commit()` to drain the child into the parent. Each
dirty entry incurs two hash + insert operations (one into `ltxInner`'s
local map, one during `commit` into the parent). The benchmark measures
`commit_to_ltx = 4.22 ms/ledger` (1.7% of soroswap apply time).

Writing directly to the parent `ltx` via `ltx.createWithoutLoading` /
`ltx.updateWithoutLoading` would halve the per-entry hash + insert work.

## Trigger

Soroswap apply; phase is measured via `mLastPhaseTimings.sorobanCommitToLtxMs`
in `src/ledger/LedgerManagerImpl.cpp` (the timing surrounds line 2709
`globalParState.commitChangesToLedgerTxn(ltx)`).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:722-801` — `commitChangesToLedgerTxn`,
  specifically `LedgerTxn ltxInner(ltx)` at 725 and `ltxInner.commit()` at 800.

## Evidence

- The child `ltxInner` exists only for the duration of this function; it has
  no scope (no exception handler, no early commit point) that requires
  sandboxing — the function either completes the whole loop or throws and the
  child is abandoned.
- `createWithoutLoading` / `updateWithoutLoading` already exist on
  `AbstractLedgerTxn` and accept the same arguments, so no new API surface
  is needed.
- The `markRestoredFromHotArchive` / `markRestoredFromLiveBucketList` calls
  later in the function are sub-millisecond and already operate on
  whichever ltx is passed.

## Anti-Evidence

- The child ltx provides per-loop transactional semantics: if any
  `createWithoutLoading` throws partway through, the parent ltx is left
  untouched. Removing the child requires verifying no exception path
  exists, or rolling back manually (complex).
- The parent `ltx` may already have pending changes (from
  `processFeesSeqNums` / classic phase). Writing into a child sandboxes
  the soroban writes from the parent's transactional state during this
  function's run, which the invariant checker may rely on later via
  `getChanges()`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in fail/hypothesis/reviewed/poc

### Why It Failed

Sizing: `commit_to_ltx = 4.22 ms/ledger` total. Removing one of two
hash+insert operations per entry caps savings at ~50% = 2.1 ms/ledger =
**0.84% of apply time**, well below the Medium 3% floor and below the Low
1% floor. The realistic savings are smaller because `ltxInner.commit()`
is a bulk move under the hood (it splices map entries into the parent
without re-hashing each one). Fail 029 already established that
heavyweight per-key work is not in the iteration overhead.

Additionally, the child-ltx pattern is load-bearing for invariant
checking and exception safety — removing it adds correctness risk
disproportionate to a sub-1% gain.

### Lesson Learned

Apparent "redundant intermediate ltx" patterns rarely yield Medium-tier
savings because `LedgerTxn::commit` is typically implemented as a map
splice rather than per-entry rehashing. Always read the `commit`
implementation before sizing the projected savings of bypassing a child
ltx.
