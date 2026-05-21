# H002: Mutate enforcing StorageMap writes in place instead of rebuilding MeteredOrdMap per put

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban enforcing storage writes
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated immutable-map reconstruction on successful storage writes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During enforcing-mode host execution, storage writes should update the per-invocation `StorageMap` without cloning and rebuilding the entire sorted backing vector on every write. The final observable map ordering must remain deterministic, and budget/accounting semantics must either remain equivalent or be protocol-gated to reflect work actually eliminated.

## Mechanism

`Storage::put_opt_helper` calls `self.map = self.map.insert(...)` for every persistent/temporary storage write. `MeteredOrdMap::insert` is immutable: it performs a binary search, clones all entries before and after the insertion/replacement point, collects a fresh vector through `from_exact_iter`, charges a deep clone, and scans the whole map again in `from_map`. The actual behavior therefore turns successful soroswap storage writes into repeated vector rebuilds even though enforcing storage owns the map uniquely for the current host invocation; an enforcing-only mutable replacement path can preserve sorted order while avoiding the clone/reallocate/scan loop.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each successful swap mutates SAC balance entries and pair/router contract data through `Storage::put`, which reaches `Storage::put_opt_helper` and then `MeteredOrdMap::insert` under `applyLedger -> applyParallelPhase -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` — enforcing-mode `put_opt_helper` and `put` call `self.map.insert` on every write.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` — immutable `MeteredOrdMap::insert` rebuilds a complete vector on replace/insert.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `from_exact_iter` allocates, deep-clone-charges, and delegates to `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-138` — `from_map` rescans and revalidates ordering.

## Evidence

Timestamp-filtered Tracy on the current soroswap trace confirms the target sits under `applyLedger`: `storage put` totals 119.302 ms across 33,882 calls, `new map` totals 449.678 ms across 170,072 calls, `map lookup` totals 580.114 ms across 502,648 calls, and `map lookup indexed` totals 543.656 ms across 779,242 calls inside apply windows. The source has the structural O(N) rebuild pattern on every storage write, and soroswap repeatedly writes balance and pool state in the same small enforcing map. A mutable enforcing-only `replace_or_insert_sorted` helper could turn each write into one binary search plus an in-place replacement/insert into uniquely-owned storage, avoiding the repeated full-vector clone and `from_map` scan.

## Anti-Evidence

A prior journaled enforcing-storage-map redesign reached final review but was rejected before benchmark confirmation because tests did not complete cleanly; this hypothesis is narrower and should avoid frame rollback redesign by only replacing the internal map update primitive used when `Storage` already owns the enforcing map. The full `new map` and lookup totals include setup, conversion, and read paths, so the PoC must add narrower attribution around `Storage::put_opt_helper` to prove that the write-side mutable path clears the Medium threshold. Budget charges are protocol-visible: either preserve the old charges explicitly or gate any reduced charge model behind the next protocol.

---

## Review

**Verdict**: NOT_VIABLE — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-in-place-storage-map-updates.md`
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `002-in-place-storage-map-updates.md`
**Failed At**: reviewer

### Trace Summary

The traced code confirms the structural mechanism: `Storage::put` enters `put_opt_helper`, enforces read-write footprint access, and assigns `self.map = self.map.insert(...)`; `MeteredOrdMap::insert` then binary-searches and rebuilds a new vector via `from_exact_iter` and `from_map`. The apply path also matches the hypothesis: `applyParallelPhase` builds Soroban stages, `applySorobanStageClustersInParallel` runs cluster workers, `applyThread` calls transaction `parallelApply`, and `InvokeHostFunctionOpFrame::doParallelApply` invokes the Rust host path where storage writes occur. However, this exact optimization has already been investigated and failed the objective threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` — `put_opt_helper` performs footprint recording/enforcement and writes through immutable `StorageMap::insert`; `put` wraps it with the `storage put` Tracy span.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_map` scans and validates ordering; `from_exact_iter` collects a fresh vector, charges deep clone cost, and delegates to `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` — `insert` clones prefix/suffix entries and constructs a replacement map for both replace and insert cases.
- `src/ledger/LedgerManagerImpl.cpp:2483-2575` — Soroban cluster workers call `parallelApply` and are waited on by `applySorobanStageClustersInParallel`.
- `src/ledger/LedgerManagerImpl.cpp:2966-3032` — `applyParallelPhase` builds apply clusters and dispatches Soroban stages.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — parallel invoke-host-function operations enter `InvokeHostFunctionParallelApplyHelper`.
- `ai-summary/fail/transaction-ledger/summary.md:24` — prior failure records the same "Add in-place storage-map update path for enforcing Soroban storage writes" hypothesis as below threshold.

### Why It Failed

This is a duplicate of the previously failed `002-in-place-storage-map-updates.md` investigation summarized in `ai-summary/fail/transaction-ledger/summary.md`. That review already covered the same in-place enforcing storage-map write mechanism and rejected it because the measured aggregate worker self-time must be divided by the eight parallel soroswap clusters, yielding only about 15 ms critical-path upper-bound savings, below the optimize-soroswap Medium threshold.

### Lesson Learned

For Soroban worker-side storage optimizations, aggregate Tracy totals are not apply-time savings; normalize by active cluster parallelism and compare the critical-path upper bound against the 3% Medium objective floor before promoting write-map micro-optimizations.
