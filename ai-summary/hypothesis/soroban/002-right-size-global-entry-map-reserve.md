# H002: Right-Size Global Parallel Entry Map Reservation

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing single-threaded global-state setup allocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`GlobalParallelApplyLedgerState` should allocate enough hash-table capacity for the unique entries it may actually hold during a ledger close, not for every footprint occurrence across every transaction. For soroswap, repeated contract-code, contract-instance, pool, token, and TTL keys appear in thousands of footprints but collapse to a much smaller unique key set; setup should not spend measurable apply time allocating buckets for duplicates that can never become distinct map entries.

## Mechanism

The constructor currently computes `estimatedEntries` by summing `fp.readWrite.size() * 2 + fp.readOnly.size() * 2 + 1` for every transaction in every stage and immediately calls `mGlobalEntryMap.reserve(estimatedEntries)`. This is a duplicate-count estimate, not a unique-key estimate, so workloads with many repeated read-only Soroban keys can over-reserve the `UnorderedMap` by a large factor. The current soroswap phase timing reports `soroban_setup_glbl` at a median 24.11 ms/ledger, while the zoned sub-work inside that constructor is much smaller, making the uninstrumented reserve/allocation and duplicate footprint pass a plausible Medium-sized serial setup target.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark and inspect the phase timing breakdown:

- `soroban_setup_glbl` median 24.11 ms/ledger
- current soroswap median close time about 207.6 ms

Add temporary Tracy zones around the `estimatedEntries` pass and `mGlobalEntryMap.reserve(estimatedEntries)` in `GlobalParallelApplyLedgerState::GlobalParallelApplyLedgerState`, and log both `estimatedEntries` and final `mGlobalEntryMap.size()` for soroswap ledgers. If the reserve count is several times the final unique-entry count and the reserve zone explains a meaningful fraction of `soroban_setup_glbl`, prototype a capped or unique-aware reservation strategy and rerun the three-run non-Tracy matrix.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:386-429` — `GlobalParallelApplyLedgerState` constructor performs the setup and calls `preParallelApplyAndCollectModifiedClassicEntries`.
- `src/transactions/ParallelApplyUtils.cpp:401-417` — duplicate-count `estimatedEntries` calculation and `mGlobalEntryMap.reserve(estimatedEntries)`.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — later read-only Soroban preload shows the same repeated-footprint shape but inserts only unique keys into `mGlobalEntryMap`.

## Evidence

The current diagnostic log's `soroban_setup_glbl` phase is a serial apply-thread cost large enough to clear Medium if reduced by even a third. Tracy aggregate rows for the visible subzones (`preParallelApply`, `collectModifiedClassicEntries`, and `fetchSorobanReadOnlyEntries from footprints`) do not account for that full phase, leaving constructor-local unzoned work as a candidate. Structurally, the reservation estimate is obviously duplicate-sensitive: it scales with transaction count and footprint width even though the global map's read-only entries are de-duplicated by `mGlobalEntryMap.find(lk)` before insertion.

## Anti-Evidence

The phase-timing evidence is not yet an isolated Tracy measurement. Prior failures already rejected several narrow `GlobalParallelApplyLedgerState` preload and classifier optimizations as sub-threshold, so this is only viable if the unzoned reserve/allocation itself is large. A unique-aware prepass can also cost as much as it saves; the promising shape is a cheap cap/heuristic or reuse of key sets already built for stages, not a new full duplicate-removal pass on the apply thread.
