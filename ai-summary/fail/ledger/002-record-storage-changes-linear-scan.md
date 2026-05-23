# H002: Replace recordStorageChanges linear footprint scan

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Low
**Impact**: C++ Soroban result writeback bookkeeping
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, C++ should record modified entries and TTL changes in the transaction's close meta while preserving the exact read/write footprint semantics and metadata order. A faster lookup structure for read/write keys would only be worthwhile if the current scan were a material apply-time bottleneck.

## Mechanism

`recordStorageChanges` iterates each modified entry and uses a linear scan over `sorobanData.resources.footprint.readWrite` to determine whether the key is writable. The suspected deviation was an O(modified entries * rwKeys) path on soroswap transactions, where a prebuilt key set could replace repeated scans.

## Trigger

Run the current soroswap apply-load benchmark and inspect the `recordStorageChanges` Tracy zone inside `applyLedger`. Transactions with multiple modified ledger entries and larger read/write footprints would exercise the nested scan.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-690` — `recordStorageChanges` loops over `modifiedLedgerEntries` and scans `footprint.readWrite` for each key.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:797-817` — surrounding C++ result collection path that calls `recordStorageChanges` after Rust invocation.

## Evidence

The code has a clear nested-loop shape and sits in the ledger apply path for every successful Soroban invocation.

## Anti-Evidence

The current trace measured `recordStorageChanges` self-time at roughly 64,125,336 ns across the whole soroswap trace. Spread over 71 apply windows, even eliminating the zone entirely would be below the Medium threshold; a realistic key-set replacement would only save a fraction of it.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in this session record

### Why It Failed

The structural O(n*m) pattern exists, but measured apply-contained self-time is too small for the optimize-soroswap objective. This is below objective severity threshold (Low not accepted at hypothesis stage).

### Lesson Learned

Do not promote visually inefficient C++ writeback loops unless Tracy shows enough self-time to matter; several result/meta bookkeeping paths are far smaller than host storage and VM execution.
