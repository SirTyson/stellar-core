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
