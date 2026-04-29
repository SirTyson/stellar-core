# H007: C++ Apply Support Path Micro-Optimizations

**Date**: 2026-04-29
**Subsystem**: transactions
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

C++ support work around Soroban parallel apply should validate signatures, process fees and sequence numbers, load C++ footprint buffers, and record host ledger effects with the same results as today, while avoiding redundant per-transaction loads and scans where possible.

## Mechanism

Several C++ apply-side helper paths looked like possible soroswap bottlenecks: `processFeesSeqNums`, `preParallelApply`, `addFootprint`/`addReads`, `recordStorageChanges`, and BucketList point loads from footprint access. Timestamp-filtering them into `applyLedger` showed that each path is real but individually too small to clear the 3% objective floor.

## Trigger

Run the current soroswap diagnostic trace from `ai-summary/CURRENT_STATE.md` and timestamp-filter the candidate zones against `applyLedger`. The relevant measured overlaps were approximately: `processFeesSeqNums` 142.36 ms, `preParallelApply` 111.94 ms, `addFootprint` 138.13 ms, `recordStorageChanges` 50.95 ms, BucketList `load` 84.51 ms, and `InMemoryIndex::scan` 69.12 ms.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — fee and sequence-number processing.
- `src/transactions/TransactionFrame.cpp:2250-2383` — pre-parallel read/write validation and sequence updates.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-552` — C++ footprint loading and CxxBuf construction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — host output ledger-change validation and C++ state updates.
- `src/bucket/BucketListSnapshot.cpp:171-201,313-335` and `src/bucket/InMemoryIndex.cpp:249-262` — point lookup/load paths observed during apply.

## Evidence

All listed zones are descendants of the measured `applyLedger` windows, and the source confirms they sit directly around `TransactionFrame::parallelApply` and `InvokeHostFunctionOpFrame::doParallelApply`. They perform repeated per-transaction work, so they are plausible micro-optimization targets.

## Anti-Evidence

The measured overlap is too small. Even eliminating any one path entirely would fall below the objective's Medium threshold, and many of the paths are correctness-sensitive validation, fee, or resource-accounting code where a correct optimization would recover only a fraction of the measured time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — the combined timestamp-filtered C++ support-path bound was not previously recorded as an individual fail file

### Why It Failed

The candidate paths are real but bounded below objective severity. They are useful context for future profiling, but they should not be promoted as separate soroswap optimization hypotheses unless future traces show substantially higher apply-window overlap.

### Lesson Learned

For C++ support zones around parallel Soroban apply, timestamp-filter first and compare the whole-zone bound against the Medium floor before investigating lower-level micro-optimizations.
