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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — reserve-specific over-allocation was not previously investigated; related RO-preload loop-fusion failures are not exact duplicates
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches the target through `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages`, which constructs `GlobalParallelApplyLedgerState` and records that whole constructor as `soroban_setup_glbl`. The duplicate-sensitive `reserve` call exists, but it is only the first small part of the constructor; the same timing bucket also includes V26 pre-parallel transaction validation, read-only pre-apply fan-out, buffered write commits, modified-classic collection, and Soroban read-only footprint preload. The proposed right-sizing would at most reduce an unordered-map bucket-array allocation and a cheap size-summing pass, while a unique-aware reservation prepass would add hashing/dedup work over the same footprint keys it is trying to save. That does not plausibly clear the optimize-soroswap Medium floor of roughly 6.2 ms per 207.6 ms ledger.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2673-2690` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState` and records the entire constructor duration as `sorobanSetupGlobalMs`.
- `src/ledger/LedgerManagerImpl.cpp:2701-2738` — even the current single-stage fast path still constructs the global state before applying workers, so constructor setup remains on the measured path.
- `src/transactions/ParallelApplyUtils.cpp:386-417` — the target inefficiency exists: `estimatedEntries` sums per-transaction footprint sizes including duplicates and calls `mGlobalEntryMap.reserve(estimatedEntries)`.
- `src/transactions/ParallelApplyUtils.cpp:432-467` — after the reserve, the constructor runs V26 `preParallelApplyAndCollectModifiedClassicEntries`, including per-transaction classification, `readOnlyPreParallelApply`, buffered writes, and modified-classic collection.
- `src/transactions/ParallelApplyUtils.cpp:526-598` — `readOnlyPreParallelApply` launches worker tasks over transaction bundles, and `commitBufferedPreParallelApplyWrites` opens per-transaction write-side pre-apply work; both are charged to `soroban_setup_glbl`.
- `src/transactions/ParallelApplyUtils.cpp:600-718` — modified-classic collection and Soroban read-only preload deduplicate inserts into `mGlobalEntryMap`; this confirms duplicate footprints collapse, but it also shows the useful preload work still requires key probing/loading independent of reserve size.
- `src/transactions/TransactionFrame.cpp:2146-2198,2271-2312` — each read-only pre-apply transaction constructs a signature checker, computes Soroban resource fees, runs `commonValid`, processes signatures read-only, and checks the Soroban operation; this is a substantial per-transaction component inside the same setup timing.
- `src/transactions/TransactionFrameBase.h:88-91,155-163` — `mGlobalEntryMap` is an `UnorderedMap<ParallelApplyLedgerKey, ParallelApplyEntry<GlobalParApply>>`; `reserve` allocates hash-table bucket capacity, not the ledger-entry payloads themselves.
- `ai-summary/fail/soroban/summary.md:167` — a related prior investigation of fusing `collectModifiedClassicEntries` with Soroban RO preload estimated only ~0.12-0.36 ms/ledger, reinforcing that the footprint iteration/preload surface is far below Medium.

### Why It Failed

The hypothesis attributes a large fraction of the 24.11 ms `soroban_setup_glbl` median to uninstrumented reserve/allocation work, but the source trace shows that timing covers much heavier per-transaction pre-apply validation and writeback. The actual reserve waste is limited to over-allocating an unordered-map bucket array and computing an estimate from vector sizes once per transaction; even a large duplicate factor only wastes pointer-bucket memory, not per-entry construction. A correct unique-aware reserve would need to hash/deduplicate footprint keys on the apply thread and risks costing more than it saves, while a capped heuristic can only recover allocator overhead that is structurally sub-Medium. Under the objective rule that Low findings are rejected, this cannot proceed.

### Lesson Learned

Do not size allocator-capacity heuristics from a broad constructor phase timer. For `GlobalParallelApplyLedgerState`, first separate `reserve`, V26 pre-parallel validation, buffered pre-apply writes, modified-classic collection, and RO preload; bucket-reserve tuning must prove isolated multi-millisecond savings before it can satisfy the Medium threshold.
