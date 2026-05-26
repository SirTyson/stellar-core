# H002: Bypass Global Parallel State for Single-Stage Soroswap Ledgers

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating single-stage global map setup and merge/writeback tails
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban ledger has exactly one parallel stage and the stage is partitioned into deterministic independent clusters, the apply path should not need to materialize a multi-stage global dirty-entry map and then merge all thread states back through it before writing to `LedgerTxn`. The observable ledger result should be identical if each cluster records its final changes in deterministic transaction order, the main thread commits those disjoint changes directly to the parent `LedgerTxn`, and read-only TTL bump conflict resolution is applied with the same ordering rules as the existing merge.

## Mechanism

The current pipeline always constructs `GlobalParallelApplyLedgerState`, initializes per-thread states from it, runs one stage, merges thread results back to `mGlobalEntryMap`, and then consumes that map into `LedgerTxn`. That design is needed for multi-stage propagation, but the soroswap benchmark asserts a single Soroban stage with the maximum configured cluster count, so the global map mostly acts as an intermediate copy/merge layer. A one-stage specialization can keep the existing worker parallelism capped at `ledgerMaxDependentTxClusters` / `NUM_CLUSTERS`, preserve deterministic cluster and transaction ordering during final commit, and skip the global-state propagation path that the phase log attributes to `soroban_setup_glbl`, `commit_from_thrds`, and `commit_to_ltx`.

## Trigger

Run the current soroswap apply-load workload. `ApplyLoad` resolves bucket futures before timing, applies a tx set that forms one Soroban stage, and then times `applyLedger`; each ledger pays the generic multi-stage setup and merge/commit path even though there is no later stage that can consume `mGlobalEntryMap`.

## Target Code

- `src/simulation/ApplyLoad.cpp:2260-2334` — benchmark timing resolves bucket futures before timing and asserts the single-stage/max-cluster soroswap shape.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` and `applyParallelPhase` construct the global parallel apply state and time the setup/parallel/commit phases.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` runs at most the configured cluster futures and already has a deterministic cluster vector.
- `src/transactions/ParallelApplyUtils.h:183-273` — `GlobalParallelApplyLedgerState` owns `mGlobalEntryMap` and exposes the merge and final `LedgerTxn` commit APIs.
- `src/transactions/ParallelApplyUtils.cpp:721-801` — `commitChangesToLedgerTxn` drains the global map into `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:821-922` — `commitChangesFromThreads` merges thread maps into the global map, including read-only TTL bump handling.
- `src/transactions/ParallelApplyUtils.cpp:924-1252` — `ThreadParallelApplyLedgerState` already owns the per-cluster final entry maps that the single-stage path could commit directly after deterministic validation.

## Evidence

The current accepted soroswap baseline is about 207.59 ms median. The diagnostic run reports `parallel_total` at 186.03 ms median, with `soroban_setup_glbl` at 24.11 ms, `commit_from_thrds` at 7.64 ms, and `commit_to_ltx` at 4.29 ms. Even a partial removal of the single-stage-only setup/merge/writeback overhead clears the 3% Medium threshold. The apply-contained Tracy aggregation also places the relevant zones under `applyLedger`: `applyParallelPhase` accounts for about 3.02 s aggregate in the trace, `applySorobanStageClustersInParallel` for about 2.72 s aggregate, and the serial commit helpers appear as the post-worker tail inside the same apply windows.

The source shape suggests a deterministic specialization is possible. The stage already contains a fixed vector of clusters; workers do not need additional parallelism beyond those clusters; and a one-stage direct commit can replay clusters in sorted stage order on the main thread, keeping observable writes deterministic. Multi-stage ledgers can keep the existing global map path, while the single-stage path can assert or prove disjoint write footprints and preserve the current `maybeMergeRoTTLBumps` rules before writing to `LedgerTxn`.

## Anti-Evidence

A previous direct-commit investigation was rejected during final review because the claimed source implementation was absent, so this must not be treated as already proven. The new hypothesis is broader than a merge-tail shortcut: it requires a source-present, one-stage-specific path that bypasses global-state propagation only when no later stage can observe `mGlobalEntryMap`. The hard part is preserving every edge case in `commitChangeFromThread`, especially restored entries, classic entries read by Soroban, read-only TTL bumps, and duplicate-key conflict handling; if any of those cannot be proven disjoint or replayed deterministically, the specialization must fall back to the existing multi-stage path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — direct-commit portion duplicates `ai-summary/fail/soroban/001-single-stage-direct-thread-ledgertxn-commit.md`; setup-timer portion substantially overlaps `ai-summary/fail/soroban/002-right-size-global-entry-map-reserve.md`
**Failed At**: reviewer

### Trace Summary

The close-ledger path is `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages`, where the measured single-stage soroswap workload constructs a `GlobalParallelApplyLedgerState`, applies one stage, merges thread states to `mGlobalEntryMap`, and drains dirty global entries into an inner `LedgerTxn`. The one-stage direct-to-`LedgerTxn` part was already reviewed in `001-single-stage-direct-thread-ledgertxn-commit.md`, including the same `commit_from_thrds` and `commit_to_ltx` timing evidence and the same RO TTL/restored-entry correctness constraints. The new claim that `soroban_setup_glbl` can also be bypassed does not hold as stated: that timer contains required pre-parallel validation/writeback and thread-state input preparation, not just removable multi-stage dirty-map propagation.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2260-2334` — the model benchmark resolves live/hot bucket futures before timing, closes the ledger, and asserts one Soroban stage with the configured maximum dependent clusters.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` creates one `ThreadParallelApplyLedgerState` per cluster using the global state and joins futures in deterministic cluster-vector order.
- `src/ledger/LedgerManagerImpl.cpp:2622-2724` — `applySorobanStage` always calls `commitChangesFromThreads`; `applySorobanStages` always constructs `GlobalParallelApplyLedgerState` and then calls `commitChangesToLedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` gathers parallel phases, calls `applyParallelPhase`, and records the setup/parallel/commit phase timings inside the apply path.
- `src/transactions/ParallelApplyUtils.cpp:386-429` — the global-state constructor reserves `mGlobalEntryMap` and calls `preParallelApplyAndCollectModifiedClassicEntries`; it also owns the shared snapshot/config context used to seed threads.
- `src/transactions/ParallelApplyUtils.cpp:432-523` — pre-parallel work is required before worker apply: it runs transaction pre-apply validation, processes sequence/signature effects, and collects classic entries modified by earlier ledger-close phases.
- `src/transactions/ParallelApplyUtils.cpp:526-718` — the setup timer includes V26 read-only pre-apply fan-out, buffered pre-apply writes, modified-classic collection, and Soroban read-only/TTL preload.
- `src/transactions/ParallelApplyUtils.cpp:721-922` — the already-investigated direct-commit surface merges thread entries into `mGlobalEntryMap`, max-merges read-only TTL bumps, preserves first-touch `mIsNew`, then writes dirty entries to an inner `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:924-1252` — each thread state depends on global state for prior-stage/restored-entry visibility, footprint entry preloading, and independent thread-safe access to snapshot/in-memory state.
- `src/transactions/TransactionFrame.cpp:2145-2383` — `preParallelApplyReadOnly` and `preParallelApplyWrite` perform substantial required per-transaction validation, sequence/signature updates, metadata-before changes, and Soroban metrics updates.

### Why It Failed

This is substantially a re-promotion of an already reviewed one-stage direct-commit hypothesis. The prior review covered the same single-stage premise, direct thread-map-to-`LedgerTxn` mechanism, deterministic ordering requirement, RO TTL max-merge requirement, restored-entry bookkeeping, and Medium projection from `commit_from_thrds + commit_to_ltx`.

The broader setup-bypass addition is not viable as written. `soroban_setup_glbl` is a broad constructor bucket, and the source shows it includes mandatory pre-parallel transaction validation/writeback and collection of classic entries changed by fee/sequence processing. A single-stage path can avoid needing global state for later-stage propagation, but it cannot skip that required work; replacing the global map with a lighter context would either move equivalent snapshot/classic/RO preload work into per-thread setup, duplicate loads across clusters, or risk incorrect visibility of modified classic entries and restored entries. After removing the duplicate direct-commit portion, the new setup-only opportunity is at most a low-severity refactor unless isolated measurements prove otherwise, which is below the objective's Medium floor.

### Lesson Learned

Do not treat a broad phase timer named `soroban_setup_glbl` as removable global-map overhead. Future hypotheses should either implement and benchmark the already-reviewed single-stage direct-to-`LedgerTxn` design as source-present work, or isolate a specific constructor subcost with measurements that exclude required `preParallelApply`, classic-entry visibility, and thread-state seeding work.
