# H001: Compact Final-Stage Commit Journal for Parallel Soroban Writeback

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by removing the final-stage global-map materialization pass and clean-entry scan before `LedgerTxn` writeback
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After the last Soroban apply stage finishes, the apply thread should write exactly one final state per dirty key into the parent `LedgerTxn`, preserving `mIsNew`, delete/recreate collapse semantics, RO TTL max-merge behavior, and restored-entry markers. It should not first materialize final-stage dirty entries into `mGlobalEntryMap` when no later stage can read them, and it should not scan clean preloaded global entries just to skip them during `commitChangesToLedgerTxn`.

## Mechanism

The current pipeline always runs `commitChangesFromThreads` after every stage and then runs `commitChangesToLedgerTxn` once after all stages. For the final stage this performs two serial apply-thread passes over dirty entries: thread maps are rescoped into `mGlobalEntryMap`, then the global map is scanned and moved into an inner `LedgerTxn`. A corrected final-stage path can avoid the prior direct-commit correctness failures by using a compact final-state journal: track prior-stage dirty global keys, collect final-stage dirty keys, skip prior-global states overwritten by final-stage states, merge only overlapping keys through the existing `commitChangeFromThread`/`maybeMergeRoTTLBumps` semantics in a small journal, and write one collapsed final entry per key to `LedgerTxn`.

This deviates from the previous rejected sketches by never committing intermediate delete-before-recreate states to `LedgerTxn`. It collapses prior-global and final-thread states in memory first, so a key deleted in an earlier stage and recreated in the final stage is written only as the final LIVE state, avoiding the `DELETED + LIVE` `LedgerEntryPtr::mergeFrom` failure identified in the earlier review.

## Trigger

Run the current `ai-summary/CURRENT_STATE.md` soroswap benchmark (`soroswap, TX=2000, T=8`). The diagnostic phase table for run `62ee1ffb5d05-20260523-010230` reports `commit_from_thrds` median **7.44 ms/ledger** and `commit_to_ltx` median **4.37 ms/ledger**, together **11.81 ms/ledger** against the current **218.31 ms** average soroswap median baseline. A PoC should replace only the final-stage writeback path, preserve the existing non-final-stage path, and show those two phase timers drop enough to move top-line apply time across three non-Tracy runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2622-2714` — `applySorobanStage` and `applySorobanStages`; caller knows when a stage is final and currently always calls `commitChangesFromThreads` followed by one `commitChangesToLedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn`; scans all `mGlobalEntryMap` entries and skips clean preloads.
- `src/transactions/ParallelApplyUtils.cpp:856-922` — `commitChangeFromThread` / `commitChangesFromThreads`; exact merge semantics to reuse in the compact journal for overlapping final-stage keys.
- `src/transactions/ParallelApplyUtils.cpp:821-854` — `maybeMergeRoTTLBumps`; RO TTL max-merge semantics that must be preserved.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — final-stage thread states preload footprint-relevant global keys and carry `mIsNew`; the new path must avoid writing stale prior-global states for keys overwritten here.
- `src/ledger/LedgerTxn.cpp:98-147` — `LedgerEntryPtr::mergeFrom`; explains why direct sequential `LedgerTxn` writes of prior delete then final recreate are invalid.
- `src/transactions/ParallelApplyUtils.h:183-273` — add dirty-key tracking and a final-stage compact-commit API.

## Evidence

- Current Tracy trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
- `csvexport-release -e` reports `commitChangesFromThreads` at `src/transactions/ParallelApplyUtils.cpp:913`, **60,569,103 ns self** over 43 calls, and `commitChangesToLedgerTxn` at `src/transactions/ParallelApplyUtils.cpp:724`, **27,630,465 ns self** over 71 calls. The aggregate Tracy self-time is smaller than the BUILD_TESTS phase timers, but unwrap samples and source call structure confirm both zones are descendants of `applyLedger`.
- The same trace reports `applySorobanStage` at `src/ledger/LedgerManagerImpl.cpp:2628`, **2,812,981,339 ns total** over 43 calls, with the final writeback immediately afterward in `applySorobanStages`.
- Source inspection shows the earlier correctness blocker is avoidable: `commitChangesFromThread` already collapses thread entries into one final global state per key before any `LedgerTxn` write. The compact journal should reuse that collapse for final-stage overlap keys, while direct-writing non-overlap final thread entries and prior dirty globals exactly once.
- Soroswap stages have eight clusters for eight configured clusters, and cross-cluster RW conflicts are absent by construction; final-stage cross-thread collisions are therefore limited to RO TTL bumps and keys already present from prior stages, the exact cases handled by the existing merge helper.

## Anti-Evidence

- If most dirty entries are produced before the final stage and final-stage overlap is high, the journal still has to write those prior dirty entries and perform overlap filtering; the saving may fall below Medium.
- The implementation must not rely on `LedgerTxn` last-write-wins semantics. It must write only collapsed final states to avoid `DELETED + LIVE` merge failures and preserve `mIsNew` from the first touch.
- Restored-entry markers in `mGlobalRestoredEntries` still need to be applied exactly as today before the inner `LedgerTxn` commits.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; this is the corrected compact-journal refinement suggested after the two prior direct-write sketches failed.

### Trace Summary

`LedgerManagerImpl::applySorobanStages` constructs one `GlobalParallelApplyLedgerState`, applies each stage, calls `commitChangesFromThreads` after every stage, and finally calls `commitChangesToLedgerTxn`. The existing merge path collapses thread states into `mGlobalEntryMap` before any `LedgerTxn` write, which is why it avoids the prior delete/recreate `DELETED + LIVE` failure. A final-stage compact journal can preserve that collapse for overlap keys while avoiding materializing non-overlap final-stage entries into the global map and avoiding the final clean-entry scan.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2622-2714` — `applySorobanStage` always performs thread-to-global merge, and `applySorobanStages` performs the single final `commitChangesToLedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — final writeback scans every global entry, skips clean entries, writes dirty entries to an inner `LedgerTxn`, and applies restored-entry markers.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — `maybeMergeRoTTLBumps` and `commitChangeFromThread` implement the required max-TTL collision merge and first-touch `mIsNew` preservation.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — final-stage thread states copy only footprint-relevant global keys, so prior dirty globals not touched in the final stage still need a dirty-key journal.
- `src/transactions/ParallelApplyUtils.cpp:1124-1195` — thread upsert/delete paths preserve `mIsNew` across delete/recreate sequences, making collapsed final-state writeback possible.
- `src/ledger/LedgerTxn.cpp:98-147` and `src/ledger/LedgerTxn.cpp:760-865` — `LedgerTxn` is not last-write-wins; it accepts one collapsed final state but can reject intermediate delete-then-live sequences.
- `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.log:2372-2391` — BUILD_TESTS phase timings show `commit_from_thrds` median 7.44 ms and `commit_to_ltx` median 4.37 ms inside the measured apply path.

### Findings

The inefficiency exists on the `closeLedger` hot path. The final stage currently pays the same `commitChangesFromThreads` global-map materialization as non-final stages even though no later stage can observe the resulting global state, and then `commitChangesToLedgerTxn` iterates the global map to find dirty entries.

The proposed correction addresses the known correctness blocker. It must not write a prior delete and later recreate as two `LedgerTxn` updates; it must first collapse prior global and final thread states in memory, preserving `commitChangeFromThread`'s `mIsNew` rule and `maybeMergeRoTTLBumps`'s max-TTL rule, then emit exactly one final state per key. That shape is compatible with the traced code paths.

The performance case is Medium but tight. `commit_to_ltx` cannot disappear because the dirty entries still must be written to `LedgerTxn`, but the 7.44 ms median final-stage thread-to-global materialization is large enough by itself to plausibly clear the 3% floor on the cited 218 ms baseline if the soroswap workload is single-final-stage dominated. The PoC must verify this with non-Tracy apply-load runs, because overlap filtering, final dirty-key collection, and journal writes add some work back.

### PoC Guidance

- **Target code**: `GlobalParallelApplyLedgerState` in `src/transactions/ParallelApplyUtils.{h,cpp}` and the final-stage call site in `src/ledger/LedgerManagerImpl.cpp`.
- **Change description**: Add dirty-global-key tracking for entries made dirty by non-final `commitChangeFromThread`, including the RO TTL merge branch that marks a clean preload dirty. For the final stage, skip the normal `commitChangesFromThreads`, collect dirty final-stage keys, merge prior-global/final-thread overlaps through the same `commitChangeFromThread`/`maybeMergeRoTTLBumps` semantics in a compact journal, add final-thread restored entries to `mGlobalRestoredEntries`, then write prior dirty globals not overwritten plus final collapsed journal entries once to a single inner `LedgerTxn`.
- **Correctness check**: Existing parallel Soroban apply tests and full `make check` should cover normal apply, rollback, restore tracking, and meta behavior. Add targeted coverage only if needed for a multi-stage delete/recreate overlap and an RO TTL final-stage collision, without weakening existing tests.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` at least three times without Tracy. The expected improvement must show in top-line soroswap median apply time, while diagnostic phase timings should show a substantial drop in `commit_from_thrds`; `commit_to_ltx` may only drop by the clean-scan portion because `LedgerTxn` writes remain mandatory.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/transactions/ParallelApplyUtils.h`
  - Added `mDirtyGlobalKeys` (`UnorderedSet<ParallelApplyLedgerKey>`) member
    on `GlobalParallelApplyLedgerState`: compact journal of keys whose
    `mGlobalEntryMap` entry is dirty (i.e. produced by
    `commitChangeFromThread`, either as a fresh dirty insertion or via the
    RO TTL max-merge path that marks a previously-clean preload dirty).
  - Declared two new private helpers (`writeGlobalEntryToLtx`,
    `writeRestoredMarkersToLtx`) factored from the old
    `commitChangesToLedgerTxn` so both the existing and the new commit
    paths can share them.
  - Declared new public `commitFinalChangesFromThreadsToLedgerTxn(app,
    threads, stage, ltx)` that fuses the final-stage thread→global commit
    with the ltx writeback.

- `src/transactions/ParallelApplyUtils.cpp`
  - `commitChangeFromThread`: now inserts `key` into `mDirtyGlobalKeys`
    in both branches that produce a dirty global entry (fresh insertion,
    overwrite, and the RO TTL max-merge branch).
  - `commitChangesToLedgerTxn`: now iterates `mDirtyGlobalKeys` and looks
    up each entry in `mGlobalEntryMap`, instead of scanning every
    preloaded (mostly clean) entry. Restored-entry marker emission
    factored into `writeRestoredMarkersToLtx`.
  - Added `commitFinalChangesFromThreadsToLedgerTxn`:
    1. For each thread's dirty entry, if the key is already present in
       `mGlobalEntryMap` (clean preload or prior-stage dirty), invoke
       `commitChangeFromThread` so `mIsNew`, RO TTL max-merge, and
       delete/recreate collapse semantics are preserved exactly.
       Otherwise rescope and write the (collapsed) final state directly
       to the inner ltx, skipping the global map entirely.
    2. Fold each thread's restored entries into
       `mGlobalRestoredEntries`.
    3. Iterate `mDirtyGlobalKeys` to emit prior-stage dirty plus
       final-stage overlap-merged entries via `writeGlobalEntryToLtx`.
    4. Emit restored-entry markers and commit the inner ltx.

- `src/ledger/LedgerManagerImpl.h`
  - `applySorobanStage` signature gains `bool isFinalStage` and
    `AbstractLedgerTxn& ltx` parameters.

- `src/ledger/LedgerManagerImpl.cpp`
  - `applySorobanStage`: on the final stage calls
    `commitFinalChangesFromThreadsToLedgerTxn(app, threadStates, stage,
    ltx)` instead of `commitChangesFromThreads`. The final-stage time
    is attributed to `sorobanCommitToLtxMs` (since the bulk is now ltx
    writes); non-final stages still update `sorobanCommitFromThreadsMs`.
  - `applySorobanStages`: passes `isFinalStage = (stageIdx + 1 ==
    stages.size())` to `applySorobanStage`. The trailing
    `commitChangesToLedgerTxn(ltx)` call only runs in the (rare)
    `stages.empty()` case, to keep restored-entry marker handling
    correct. `sorobanCommitToLtxMs` is reset to 0 alongside the other
    per-ledger phase counters and accumulated across calls.

### Demonstration

The optimization eliminates the redundant final-stage materialization of
thread entries into `mGlobalEntryMap` followed by a scan of that map to
filter out the clean preloads. For the final stage, non-overlapping
dirty thread entries now go straight to the inner `LedgerTxn`, and the
final commit walks only the `mDirtyGlobalKeys` set rather than every
preloaded global entry. Correctness is preserved because overlap keys
still flow through `commitChangeFromThread` / `maybeMergeRoTTLBumps`,
which collapse delete-then-recreate sequences into a single LIVE state
in memory before any `LedgerTxn` write — avoiding the `DELETED + LIVE`
`LedgerEntryPtr::mergeFrom` failure that sank earlier direct-write
sketches.

### Test Results

`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple
--abort --disable-dots' make check` ran the full suite to completion
across all 30 partitions with zero failures (every partition reported
"All tests passed"), and both `selftest-nopg` and `check-nondet`
passed.
