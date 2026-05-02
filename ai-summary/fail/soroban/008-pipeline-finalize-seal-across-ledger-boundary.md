# H008: Pipeline `finalizeLedgerTxnChanges` + `sealLedgerTxnAndStoreInBucketsAndDB` across the ledger boundary

**Date**: 2026-05-02
**Subsystem**: soroban (apply-thread serial path)
**Severity**: Medium (claimed)
**Impact**: apply-thread critical-path reduction (~3.4% of soroswap apply if achievable)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applyLedger` should not spend critical-path time on work whose results are
not consumed before the *next* `applyLedger` actually needs them. In
particular, after parallel Soroban application finishes, the per-ledger
finalize/seal phase (eviction resolution, hot-archive batch, in-memory
state update, `addLiveBatch`, header snapshot, persistent-state write)
arguably only *needs* to be observable before the next ledger's parallel
phase reads from `InMemorySorobanState` / live BucketList snapshots.
Anything that can be deferred without violating that ordering should be
moved off the critical path.

## Mechanism

In the current Tracy trace at the latest baseline (median 272.9 ms apply,
trace `9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`):

- `finalizeLedgerTxnChanges` total = 325 ms across 71 ledgers ≈ 4.5 ms /
  ledger ≈ 1.66% of median apply.
- `sealLedgerTxnAndStoreInBucketsAndDB` outer = 16 ms (it calls
  `finalizeLedgerTxnChanges`), so its own contribution is negligible.
- `addLiveBatch` (already partly parallelized with hot-archive +
  in-memory-state update) is ~4.1 ms/ledger of the 4.5 ms finalize cost.

If we could overlap the entire 4.5 ms finalize/seal block with the *next*
ledger's parallel Soroban work — by structuring the apply pipeline as a
two-stage pipeline (stage A: parallel apply for ledger N+1; stage B:
finalize/seal for ledger N) — then on a back-to-back benchmark the wall-
clock contribution of finalize/seal could approach zero, saving ~3.4%.

## Trigger

Run `apply-load --benchmark soroswap` and measure `applyLedger` wall time
with finalize/seal moved into a future joined at the next ledger's
parallel-stage start.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3368` — `finalizeLedgerTxnChanges`
- `src/ledger/LedgerManagerImpl.cpp:3370-3420` —
  `sealLedgerTxnAndStoreInBucketsAndDB`
- `src/ledger/LedgerManagerImpl.cpp:1659-1780` — `applyLedger` orchestration

## Evidence

- Existing code already runs `addHotArchiveBatch` and
  `updateInMemorySorobanState` as `std::async` futures inside
  `finalizeLedgerTxnChanges` (lines 3285-3292, 3340-3352), which proves
  parts of finalize are deferrable without breaking semantics.
- The 4.5 ms/ledger residual of finalize is mostly `addLiveBatch` plus
  the `getAllEntries` seal step, both of which produce data the *next*
  ledger reads only after its parallel-stage launch.

## Anti-Evidence

- `applySorobanStage` in the next ledger constructs
  `GlobalParallelApplyLedgerState` from `mApplyState.copyLedgerStateSnapshot()`
  *before* the parallel stage launches. That snapshot must reflect the
  current ledger's `addLiveBatch` results. So the finalize/seal block has
  to be fully visible *before* the next applyLedger entry — there is no
  slack to overlap with. In the apply-load benchmark, ledgers run
  back-to-back with no consensus delay, so there is no idle time on the
  apply thread to absorb the deferred work.
- `mLedgerStateMutex` (line 3379) serializes `sealLedgerTxnAndStoreInBucketsAndDB`
  with main-thread readers (Horizon meta export, RPC). Pipelining would
  require either holding the mutex across pipeline boundaries (defeats
  parallelism) or substantial protocol-visible refactors.
- The persistent DB write inside `sealLedger...` and the `snapshotLedger`
  call must complete before LCL is published, which other consumers
  (history, overlay) may observe. Decoupling them would risk staleness.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a *cross-ledger pipeline*
(prior failures `011-async-livebatch` and `003-deferred-livebatch` only
explored deferring `addLiveBatch` itself, not the whole finalize/seal block
across the ledger boundary).

### Why It Failed

The next ledger's parallel-apply stage requires the current ledger's
`InMemorySorobanState` and live BucketList snapshot to be fully updated
before construction of `GlobalParallelApplyLedgerState`. There is no
benchmark slack between consecutive `applyLedger` calls to absorb the
deferred work — in apply-load, the apply thread immediately reenters
`applyLedger` once the previous one returns. Any pipelining therefore
either (a) makes the next ledger block on the previous finalize anyway
(zero net win) or (b) breaks the protocol-visible invariant that LCL is
fully sealed before the next ledger reads from it.

### Lesson Learned

Cross-ledger pipelining is not viable as long as `mApplyState`'s
in-memory state is consumed at the start of the next ledger's parallel
stage. Any future attempt would need to introduce a versioned snapshot
of `InMemorySorobanState` and `BucketList` so that ledger N+1 can read
*either* the pre- or post-finalize view consistently — a much larger
refactor than a perf optimization warrants, and likely impacts
determinism and meta export.
