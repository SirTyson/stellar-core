# H002: Bulk Import Parallel Apply Global State Into LedgerTxn

**Date**: 2026-05-21
**Subsystem**: transactions
**Severity**: Medium
**Impact**: apply-time reduction in final Soroban parallel apply LedgerTxn materialization, strongest on max-sac
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Once all Soroban stages have merged into `GlobalParallelApplyLedgerState`, dirty global entries should be materialized into the child `LedgerTxn` with one bulk, pre-sized import path that preserves the current INIT/LIVE/DELETED semantics. The final parent `LedgerTxn` state, bucket output, restored-entry tracking, invariants, and transaction meta should match the existing per-entry `createWithoutLoading` / `updateWithoutLoading` loop exactly.

## Mechanism

`GlobalParallelApplyLedgerState::commitChangesToLedgerTxn` moves dirty entries one at a time, wraps each in `InternalLedgerEntry`, calls either `LedgerTxn::createWithoutLoading` or `updateWithoutLoading`, and each call repeats thread/child checks, `mActive` lookup, key extraction, `shared_ptr<InternalLedgerEntry>` allocation, and `mEntry.emplace` growth. The max-sac Tracy trace shows the self-time of this apply-descendant loop as 100,846,301 ns across 28 apply windows, or about 3.7% of `applyLedger`; the soroswap trace shows the same code path at 27,286,249 ns. A dedicated bulk API that reserves `LedgerTxn::Impl::mEntry`, validates inactive state once, and inserts moved `InternalLedgerEntry` values with known INIT/LIVE state should remove most per-entry overhead without changing consensus output.

## Trigger

Run the max-sac apply-load scenario (`sac, TX=6000, T=8`) with Tracy and inspect `commitChangesToLedgerTxn` under `applyLedger`. The hotspot is triggered after successful parallel SAC transfers produce tens of thousands of dirty `CONTRACT_DATA` and TTL entries; the final main-thread phase serially imports them into a fresh child `LedgerTxn` before `ltxInner.commit()`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState::commitChangesToLedgerTxn:722-801` — per-entry dirty scan and per-entry `LedgerTxn` calls.
- `src/ledger/LedgerTxn.cpp:LedgerTxn::Impl::createWithoutLoading:796-812` — repeated moved-entry INIT import path.
- `src/ledger/LedgerTxn.cpp:LedgerTxn::Impl::updateWithoutLoading:848-864` — repeated moved-entry LIVE import path.
- `src/ledger/LedgerTxn.cpp:LedgerTxn::Impl::updateEntry:2487-2561` — map insertion/merge and offer-book handling that a Soroban-only bulk path can bypass for non-offer entries while preserving general behavior for deletes/offers.
- `src/ledger/LedgerTxn.h:652-660,841-845` — public/override surface where a bulk no-load import API could be added.

## Evidence

The current code already tracks `mIsNew` in parallel apply specifically to avoid per-entry existence checks before this final import, so the remaining per-entry overhead is mechanical `LedgerTxn` materialization rather than semantic validation. In the current SAC diagnostic trace, `commitChangesToLedgerTxn` self-time is 100,846,301 ns while `applyLedger` totals 2,722,490,387 ns; this is a Medium-tier upper bound even before including downstream gains from fewer `mEntry` rehashes. The source also shows `commitChangesToLedgerTxn` is called once after all stages in `LedgerManagerImpl::applySorobanStages`, so it is serial critical-path work, not worker aggregate time.

## Anti-Evidence

The full 100 ms zone is an upper bound: a correct implementation still has to scan `mGlobalEntryMap`, move scoped entries safely, allocate or represent `LedgerEntryPtr` state, handle deletes exactly, mark restored entries, and commit the child `LedgerTxn`. Offer entries require order-book maintenance in `updateEntry`, so a bulk fast path should either be Soroban-entry-only or explicitly fall back to existing per-entry behavior for non-Soroban/offer keys.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`LedgerManagerImpl::applySorobanStages` constructs `GlobalParallelApplyLedgerState`, applies each stage, and then synchronously calls `commitChangesToLedgerTxn` before the apply path can proceed. `commitChangesToLedgerTxn` creates a child `LedgerTxn`, scans `mGlobalEntryMap`, imports each dirty live entry via `createWithoutLoading` or `updateWithoutLoading`, handles deletes through `load`/`erase`, marks restored entries, and commits the child transaction. The inefficiency is real, but the cited 3.7% max-sac number is the whole zone, not the removable portion of the proposed bulk API.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2672-2717` — `applySorobanStages` calls `globalParState.commitChangesToLedgerTxn(ltx)` after all Soroban stages and measures it as `sorobanCommitToLtxMs` in test builds.
- `src/transactions/ParallelApplyUtils.cpp:721-800` — `commitChangesToLedgerTxn` performs the dirty scan, per-entry import, restored-entry marking, and final `ltxInner.commit()`.
- `src/ledger/LedgerTxn.cpp:796-864` — moved-entry `createWithoutLoading` and `updateWithoutLoading` already avoid the deep copy but still perform thread/seal/child checks, `mActive` lookup, key extraction, `shared_ptr<InternalLedgerEntry>` allocation, and `updateEntry`.
- `src/ledger/LedgerTxn.cpp:570-626` — committing the child `LedgerTxn` iterates the child entries and calls `updateEntry` on the parent, so a child-side bulk import alone does not remove the final per-entry parent merge.
- `src/ledger/LedgerTxn.cpp:2487-2561` — `updateEntry`'s non-offer path is already essentially `mEntry.emplace` plus merge semantics; the order-book branch is bypassed for Soroban contract/TTL entries.
- `src/ledger/LedgerTxn.cpp:2642-2661` and `src/ledger/LedgerTxn.h:527-528` — `prepareNewObjects` already exists to reserve `LedgerTxn::Impl::mEntry`, so the lowest-risk reserve-only portion does not require a new bulk import mechanism.

### Why It Failed

The proposed change cannot plausibly clear the objective's Medium threshold. The max-sac evidence gives only a 3.7% whole-zone upper bound, so reaching the required 3% apply-time reduction would require eliminating more than 80% of `commitChangesToLedgerTxn`. A correct implementation still must scan dirty global entries, move scoped ledger entries, allocate or otherwise represent `LedgerEntryPtr`s, insert them into a LedgerTxn map, preserve delete/restored-entry semantics, and then commit the child into the parent, which performs another per-entry `updateEntry` merge. The easy reserve optimization is already available through `prepareNewObjects`, and the soroswap-specific cited cost is only 27 ms before subtracting mandatory work.

### Lesson Learned

For final parallel-apply materialization, treat `commitChangesToLedgerTxn` as an upper bound that includes mandatory child commit and parent merge work. A viable Medium-tier hypothesis needs either a direct measurement of the removable child-import subset above 3% of apply time, or a broader LedgerTxn commit redesign that safely removes both child and parent per-entry overhead rather than only wrapping `createWithoutLoading` / `updateWithoutLoading` in a bulk API.
