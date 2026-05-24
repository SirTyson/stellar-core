# H001: Final-Stage Dirty-Entry Direct LedgerTxn Commit

**Date**: 2026-05-24
**Subsystem**: soroban / parallel apply commit
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by removing the final-stage global-map merge and full clean-entry scan before `LedgerTxn` writeback
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After the last Soroban apply stage finishes, all dirty entries produced by prior stages and the last stage should be written to the parent `AbstractLedgerTxn` exactly once, preserving the same final ledger state and restored-entry markers. The final stage should not populate `mGlobalEntryMap` for entries that no later stage can read, and `commitChangesToLedgerTxn` should not scan clean preloaded global entries just to skip them.

## Mechanism

The current pipeline always runs `commitChangesFromThreads` after each stage, then runs one final `commitChangesToLedgerTxn` after all stages. This means the last stage pays two serial apply-thread passes: thread maps are rescoped into `mGlobalEntryMap`, then the whole global map is scanned and dirty entries are moved into an inner `LedgerTxn`. A refined direct-commit design can keep the existing global path for all non-final stages, track a compact `mDirtyGlobalKeys` journal for prior-stage dirty entries, and on the final stage write `(dirty prior global entries) + (dirty final thread entries)` directly into one `LedgerTxn ltxInner(ltx)`.

This differs from the earlier rejected "bypass global map" sketch: it explicitly preserves prior-stage dirty entries that are not present in final-stage footprints, and it does not claim to preserve unordered-map write iteration order. Determinism comes from `LedgerTxn` last-write-wins by key and from preserving the canonical stage order: write dirty global entries first, then final-stage thread entries in cluster-index order, applying the same RO TTL `max` merge and restored-entry markers before the single `ltxInner.commit()`.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The diagnostic phase table reports `commit_from_thrds` median **7.44 ms/ledger** and `commit_to_ltx` median **4.37 ms/ledger** inside `parallel_total`, a combined **11.81 ms/ledger** on a current non-Tracy baseline around **218 ms**.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2622-2710` — `applySorobanStage` / `applySorobanStages`, where the caller knows which stage is final and where direct final writeback can replace the normal final `commitChangesFromThreads` + later global scan.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn`, the full global-map dirty scan and restored-entry marker path.
- `src/transactions/ParallelApplyUtils.cpp:856-922` — `commitChangeFromThread` / `commitChangesFromThreads`, the per-thread merge into `mGlobalEntryMap` to bypass for the final stage.
- `src/transactions/ParallelApplyUtils.cpp:821-854` — `maybeMergeRoTTLBumps`, whose max-merge semantics must be preserved for final-stage direct writes.
- `src/transactions/ParallelApplyUtils.h` — add a dirty-key journal and a final-stage direct commit API.

## Evidence

- Current diagnostic timing (`62ee1ffb5d05-20260523-010230` soroswap log) measures `commit_from_thrds` at **7.44 ms median** and `commit_to_ltx` at **4.37 ms median** per ledger. Full elimination is 5.4% of the 218 ms baseline; even recovering ~60% clears the 3% Medium floor.
- The current Tracy trace confirms both zones are descendants of `applyLedger`: unwrap overlap gives `commitChangesFromThreads` **60.57 ms** and `commitChangesToLedgerTxn` **27.63 ms** inside `applyLedger` windows. Tracy under-reports these phase-table serial bookends relative to the benchmark's steady-clock phase timers, but containment verifies scope.
- Prior-stage correctness blocker is addressable: a `mDirtyGlobalKeys` journal records only dirty keys already merged into `mGlobalEntryMap`, so final direct writeback can write all earlier-stage dirty entries without scanning clean read-only preloads.
- Stage ordering is deterministic. Non-final stages keep the existing merge path. On the final stage, dirty prior globals are already the canonical result of all earlier stages; final thread maps are merged in cluster-index order exactly as the current `commitChangesFromThreads` caller iterates `threads`.

## Anti-Evidence

- If soroswap has many stages with most dirty entries produced before the final stage, the direct path saves less of `commit_from_thrds` than projected; the dirty-key journal still avoids scanning clean global entries but cannot avoid writing prior-stage dirty entries.
- `LedgerTxn` writeback itself remains single-threaded and necessary. This is not a parallelization proposal; the Medium claim depends on removing one global-map materialization pass and one clean-entry scan, not on eliminating all commit work.
- The implementation must preserve `mIsNew`, delete handling, `mGlobalRestoredEntries`, and RO TTL max-merge behavior exactly. Any shortcut that drops prior-stage dirty entries or restored markers would be consensus-breaking.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The hot path exists, and the refined dirty-key-journal idea is not a duplicate of the earlier failed final-stage bypass sketch, but this specific mechanism is still incorrect. It relies on "`LedgerTxn` last-write-wins by key" when writing prior dirty globals first and final-stage thread entries second, but `LedgerTxn` stores INIT/LIVE/DELETED state and merges those states with correctness checks rather than simple overwrites.

A concrete valid multi-stage overlap breaks the proposal: an earlier stage deletes an entry that existed before the ledger, so `mGlobalEntryMap` contains a dirty `nullopt` with `mIsNew=false`; the final stage recreates the same key, and `ThreadParallelApplyLedgerState` preserves `mIsNew=false` from the preloaded deleted global entry. The proposed direct path would first record the prior delete in `ltxInner`, then write the final recreated entry with `updateWithoutLoading`; `LedgerEntryPtr::mergeFrom` rejects DELETED + LIVE with `cannot set deleted entry to live`. The current code avoids this because `commitChangesFromThreads` first collapses the final thread entry into `mGlobalEntryMap`, so `commitChangesToLedgerTxn` writes only the final LIVE state.

### Alternative Angle

A viable refinement must avoid committing intermediate prior-global states for keys that are overwritten by the final stage. One safe shape is to build a compact set of final-stage dirty keys, skip those keys when writing prior dirty globals, and then write final-stage entries after applying the same `commitChangeFromThread` semantics for overlaps, `mIsNew`, deletes, RO TTL max merges, and restored-entry aggregation. Another safe shape is a compact final-state journal that pre-merges dirty prior globals and final thread entries using the existing global merge rules, then writes exactly one final state per key to `LedgerTxn`.

The performance case should be re-estimated after this refinement because the overlap filtering or compact pre-merge adds work back into the final stage. The refined design must still show that it removes enough of the final `commitChangesFromThreads` plus clean global-map scan cost to clear the 3% Medium threshold.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:2622-2710` — `applySorobanStage` always commits every stage's thread states to global state, then `applySorobanStages` performs one final `commitChangesToLedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` scans `mGlobalEntryMap`, skips clean entries, writes one final dirty state per key, and marks restored entries before committing `ltxInner`.
- `src/transactions/ParallelApplyUtils.cpp:856-922` — `commitChangeFromThread` and `commitChangesFromThreads` currently collapse thread updates into global state before any `LedgerTxn` write, preserving first-touch `mIsNew` and RO TTL max semantics.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — final-stage thread maps preload only footprint-relevant global keys, including deleted/null entries and their `mIsNew` flag.
- `src/transactions/ParallelApplyUtils.cpp:1124-1195` — thread-level upsert/delete handling preserves the first-touch `mIsNew` flag from preloaded state, producing `mIsNew=false` for recreation of an entry that existed before the ledger and was deleted by an earlier stage.
- `src/ledger/LedgerTxn.cpp:98-147` — `LedgerEntryPtr::mergeFrom` is not last-write-wins; DELETED + INIT becomes LIVE, but DELETED + LIVE throws.
- `src/ledger/LedgerTxn.cpp:760-865` and `src/ledger/LedgerTxn.cpp:2487-2523` — `createWithoutLoading` and `updateWithoutLoading` feed INIT/LIVE states into `updateEntry`, which merges against prior state and can reject invalid intermediate sequences.
