# H004: Skip clean (non-dirty) entries in `commitChangesFromThread` iteration

**Date**: 2026-05-23
**Subsystem**: ledger / parallel apply
**Severity**: Low
**Impact**: Post-worker serial commit overhead per Soroban stage
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all parallel cluster workers in a Soroban stage finish, the primary apply thread merges each thread's `mThreadEntryMap` into `GlobalParallelApplyLedgerState::mGlobalEntryMap`. Only dirty entries (entries the cluster actually wrote, including TTL bumps) need to participate in this merge. The expected behavior is that the serial commit cost scales with the number of dirty entries per stage, not with the total number of footprint entries per stage.

## Mechanism

`GlobalParallelApplyLedgerState::commitChangesFromThread` (transactions/ParallelApplyUtils.cpp:893) iterates the *entire* `thread.getEntryMap()` (one entry per footprint key the cluster's `collectClusterFootprintEntriesFromGlobal` preloaded, plus everything `commitChangeFromSuccessfulTx`/`upsertEntry`/`eraseEntry` added). For each `[key, entry]`, it calls `commitChangeFromThread` which begins with `if (!parEntry.mIsDirty) { return; }` — so clean entries are skipped, but the iteration cost (hash-table walk, key/value materialization, move-from `entry`) is paid for every entry regardless. The hypothesis was that a side-list of dirty keys (populated by `upsertEntry`/`eraseEntry`/`commitChangeFromSuccessfulTx` when they first mark an entry dirty) could shrink the post-worker merge loop to dirty-only.

## Trigger

Run the soroswap apply-load benchmark and inspect `applySorobanStages -> commitChangesFromThreads -> commitChangesFromThread` zones in the trace. Soroswap clusters have a mix of read-only entries (token contract instance, account, trustline) and read-write entries (pair contract data, balances); the read-only entries are preloaded into `mThreadEntryMap` but never marked dirty.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:893-905` — `commitChangesFromThread` walks all entries.
- `src/transactions/ParallelApplyUtils.cpp:856-891` — `commitChangeFromThread` skip on `!mIsDirty`.
- `src/transactions/ParallelApplyUtils.cpp:924-986` — `collectClusterFootprintEntriesFromGlobal` preloads clean entries from global.
- `src/transactions/ParallelApplyUtils.cpp:1123-1162` — `upsertEntry`/`eraseEntry` mark entries dirty.

## Evidence

The iteration is structurally O(footprint) but the work done per dirty entry is the only state change the merge requires. For soroswap, the read-only footprint (token contract instance, code, TTLs, account, trustline) is preloaded clean per cluster and skipped on commit.

## Anti-Evidence

Quantified from the current diagnostic Tracy trace
(`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`):

- `commitChangesFromThreads` total: 60,569,103 ns across 43 calls ≈ 1.4 ms/stage
- 71 `applyLedger` invocations vs 43 stage commits → 43/71 ≈ 0.61 stages/ledger that produce a measurable commit zone, but real soroswap typically has 1 stage per ledger; many ledgers have empty Soroban phases in the trace.
- Per-ledger upper bound: 60.6 ms / 71 ≈ 0.85 ms/ledger
- `applyLedger` mean: 63 ms
- Fraction of `applyLedger`: 0.85 / 63 ≈ 1.35%

Even if every clean-entry skip were saved (the iteration cost — hash-table walk plus the move/return for skipped entries), the absolute upper bound on savings is the full `commitChangesFromThreads` time minus the dirty-entry work that must remain. Dirty entries are >50% of footprint touches for soroswap (pair RW + SAC balance writes + TTL bumps), so the realistic savings ceiling is well under 0.5 ms/ledger (< 0.8% of `applyLedger`). This is below the 1% Low floor and far below the 3% Medium floor.

The closely related fail entry 001-move-tx-dirty-map-into-thread-state.md already established that post-worker merge optimizations in this region are sub-Medium for soroswap and that wrapper-level gaps in `applySorobanStageClustersInParallel` are dominated by slowest-cluster completion and TTL flushing, not by clean-entry iteration overhead.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior 001-move-tx-dirty-map-into-thread-state.md, which targeted the second-pass old-entry lookups during `commitChangesFromSuccessfulTx`; this hypothesis targets the post-worker `commitChangesFromThread` clean-iteration overhead.

### Why It Failed

Below objective severity threshold. Quantified `commitChangesFromThreads` per-ledger cost is ≈0.85 ms/ledger (≈1.35% of `applyLedger`). Realistic clean-skip savings are bounded below 0.5 ms/ledger (≈0.8% of `applyLedger`), beneath the 1% Low floor and far below the 3% Medium floor.

### Lesson Learned

Post-worker serial merge zones in `commitChangesFromThreads` are small enough that micro-optimizations of the iteration loop cannot reach Medium. Future commit-phase hypotheses must target a structural redesign that eliminates one entire phase (e.g., a journal-based commit that merges directly into `LedgerTxn` from per-thread dirty journals without an intermediate `mGlobalEntryMap` materialization), not loop-level skip optimizations.
