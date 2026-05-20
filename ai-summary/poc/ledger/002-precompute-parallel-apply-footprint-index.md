# H002: Precompute a per-ledger parallel-apply footprint index

**Date**: 2026-05-20  
**Subsystem**: ledger / parallel Soroban apply setup  
**Severity**: Medium  
**Impact**: 3-10% soroswap apply-time reduction by shrinking the serial `soroban_setup_glbl` phase before worker execution  
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The parallel Soroban apply setup should traverse each transaction footprint once, derive TTL keys once, and reuse the resulting classified key sets for global-map reservation, classic-entry collection, read-only Soroban preloading, and per-stage read-write conflict checks. This should preserve the same loaded entries, TTL handling, and deterministic stage order while reducing serial setup time before `applySorobanStageClustersInParallel` can start.

## Mechanism

`GlobalParallelApplyLedgerState` currently performs multiple full walks over the same `ApplyStage`/footprint graph: one pass estimates `mGlobalEntryMap` capacity, later passes collect classic keys, preload Soroban read-only entries and TTLs, and `getReadWriteKeysForStage` recomputes read-write/TTL sets per stage. A `ParallelApplyFootprintIndex` built in `applyParallelPhase` could hold per-ledger and per-stage unique RO/RW/classic/Soroban key vectors plus precomputed TTL keys, so setup code consumes indexed vectors instead of repeatedly hashing `LedgerKey`s and calling `getTTLKey` across identical footprints.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) and inspect the phase timing table. The current accepted diagnostic log reports `soroban_setup_glbl` with median 24.08 ms and mean 24.28 ms per ledger before parallel workers launch; repeated footprint walks should be visible in `getReadWriteKeysForStage`, `fetchSorobanReadOnlyEntries from footprints`, and the global constructor paths. The proposed index should reduce `soroban_setup_glbl` while leaving `soroban_parallel` transaction execution and final ledger hashes unchanged.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` builds `ApplyStage`s and immediately constructs global apply state, which is the natural place to build a reusable footprint index.
- `src/transactions/ParallelApplyUtils.cpp:104-132` — `getReadWriteKeysForStage` scans all read-write footprints and derives TTL keys for each stage.
- `src/transactions/ParallelApplyUtils.cpp:386-429` — `GlobalParallelApplyLedgerState` constructor separately scans all stages to reserve the global entry map.
- `src/transactions/ParallelApplyUtils.cpp:600-718` — global setup re-walks footprints to collect classic keys and preload Soroban read-only entries plus TTL entries.

## Evidence

The current soroswap benchmark log shows the serial `soroban_setup_glbl` phase at 24.28 ms mean / 24.08 ms median, roughly 9% of the 272.90 ms accepted soroswap median baseline and a larger target than the already-rejected sub-threshold prefetch and post-apply micro-optimizations. Tracy also confirms related apply-path zones are descendants of `applyLedger`: `getReadWriteKeysForStage` at `transactions/ParallelApplyUtils.cpp:107` appears 43 times, and `fetchSorobanReadOnlyEntries from footprints` at `transactions/ParallelApplyUtils.cpp:656` appears once per applied ledger in the measured apply window.

## Anti-Evidence

Previous narrow TTL-key caching and cluster-state setup parallelism attempts failed or regressed, so this should not be implemented as a larger side map that increases cache pressure or as extra concurrent footprint scanning. The index must be compact, deterministic, and preferably built while `ApplyStage` objects are already being materialized to avoid adding an additional pass that merely moves the cost.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed repeated footprint walks are real on the Soroban parallel apply path. `applyParallelPhase` materializes `ApplyStage`s, then `applySorobanStages` synchronously constructs `GlobalParallelApplyLedgerState`; that constructor reserves by scanning all footprints, runs V26 pre-parallel triage over transaction footprints, scans again for classic keys, then scans read-only footprints again to preload Soroban entries and derive TTL keys. Per-stage commit also rebuilds a read-write-plus-TTL set with `getReadWriteKeysForStage`, and thread-state construction independently walks each cluster footprint before worker execution. The main caveat is attribution: `getReadWriteKeysForStage` is timed under commit-from-threads rather than `soroban_setup_glbl`, so the PoC must measure both top-line apply time and the affected subphases rather than claiming all savings appear in global setup.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` builds `TxBundle`s and `ApplyStage`s immediately before calling `applySorobanStages`, making this the only place where an index can be built without an extra full pass over completed stages.
- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` times `GlobalParallelApplyLedgerState` construction as `sorobanSetupGlobalMs`, then applies stages and commits global changes back to `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:386-429` — `GlobalParallelApplyLedgerState` reserves `mGlobalEntryMap` by scanning every transaction footprint and summing read-write/read-only sizes.
- `src/transactions/ParallelApplyUtils.cpp:431-467` — V26 setup scans all transactions to split sequential pre-parallel apply from read-only pre-parallel apply, then still calls `collectModifiedClassicEntries`.
- `src/transactions/ParallelApplyUtils.cpp:600-718` — `collectModifiedClassicEntries` scans read-write and read-only footprints for classic keys, then separately scans read-only footprints to preload Soroban entries and their TTL entries.
- `src/transactions/ParallelApplyUtils.cpp:104-132, 907-922` — every stage commit rebuilds a `ParallelApplyLedgerKeySet` from read-write footprints and computes TTL keys for Soroban read-write keys before merging thread changes.
- `src/transactions/ParallelApplyUtils.cpp:924-1001` — each `ThreadParallelApplyLedgerState` pre-reserves and walks its cluster footprints, including repeated TTL-key derivation, before the async worker can apply transactions.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey(LedgerKey const&)` serializes the key and computes SHA-256, so repeated calls are not just cheap pointer comparisons.
- `src/transactions/TransactionFrameBase.h:47-91` — `ParallelApplyLedgerKey` already caches the `std::hash<LedgerKey>` result, making precomputed key wrappers a natural representation for a compact index.

### Findings

The inefficiency exists and is in scope: the repeated scans execute once per applied Soroban ledger and, for stage read-write sets and thread-state setup, once per stage or cluster inside `closeLedger`. Existing code has local mitigations such as map reservation and read-only Soroban preloading, but those optimizations still derive their inputs by re-walking the same `ApplyStage`/footprint graph. A compact index can remove duplicate classification, duplicate global-map probes for repeated read-only keys, and duplicate `getTTLKey` calls while preserving current serial ordering.

The projected severity is Medium, not High. The reported `soroban_setup_glbl` phase is large enough that eliminating a meaningful fraction of duplicate footprint/key work could clear the 3% objective floor, especially for soroswap's repeated contract footprints, but the whole 24 ms setup phase is not removable: pre-parallel apply, snapshot checks, entry loads, and entry copies must remain. Prior failures also show that broad concurrent footprint scanning can regress from memory/cache pressure, so the viable shape is a compact, single-build index consumed by existing serial paths, not another parallel setup pass.

Correctness constraints are tight but manageable. The index must preserve stage/cluster/transaction order for ordered vectors, include TTL keys for every Soroban read-write key used by conflict/merge logic, avoid stale decisions when `mGlobalEntryMap` already contains a dirty entry from an earlier stage, and leave `preParallelApply`/`readOnlyPreParallelApply` semantics unchanged. It should use ordered unique vectors plus membership sets during construction; consumers should still perform the same existence checks against `mGlobalEntryMap`, `InMemorySorobanState`, and the LCL snapshot at the point they currently do.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyStage.h`, `src/transactions/ParallelApplyUtils.{h,cpp}`, and `src/ledger/LedgerManagerImpl.cpp`.
- **Change description**: Build a compact `ParallelApplyFootprintIndex` while `applyParallelPhase` is already materializing `TxBundle`s/`ApplyStage`s. Store per-ledger unique classic footprint keys, per-ledger unique Soroban read-only keys with TTL keys, per-stage read-write-plus-TTL sets for merge conflict checks, and optionally per-cluster ordered key/TTL vectors for thread-state initialization. Pass the index into `GlobalParallelApplyLedgerState` and stage commit paths so they consume precomputed vectors/sets instead of rescanning stage footprints.
- **Correctness check**: Existing parallel-apply and Soroban transaction tests should cover merge semantics, TTL bumps, restores, and deterministic result/meta ordering. The PoC should also compare apply-load ledger hashes/results before benchmarking, because changed preloading order must not alter observable ledger output.
- **Benchmark focus**: Run the normal three non-Tracy `scripts/run_apply_load_matrix.py` measurements and require at least a reproducible 3% soroswap apply-time reduction. Attribute with phase timing and Tracy afterward: expected improvements should appear in `soroban_setup_glbl`, `commit_from_thrds` via avoided `getReadWriteKeysForStage`, and possibly the pre-worker portion of `soroban_parallel` if cluster footprint collection is indexed.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-20
**PoC by**: gpt-5.5, high

### Changes Made

- `src/transactions/ParallelApplyUtils.h:72-119, 164-182, 276-324, 336-339` — added `ParallelApplyFootprintIndex` and threaded its per-stage/per-cluster data through the global and thread parallel-apply state interfaces.
- `src/transactions/ParallelApplyUtils.cpp:240-382` — implemented index construction helpers that classify classic keys, Soroban read-only keys with precomputed TTL keys, per-stage read-write-plus-TTL sets, and per-cluster ordered key vectors.
- `src/transactions/ParallelApplyUtils.cpp:497-603, 680-762, 952-1024` — changed global setup, Soroban read-only preloading, stage commit, and thread-state initialization to consume indexed keys instead of rescanning footprints and recomputing TTL keys.
- `src/ledger/LedgerManagerImpl.h:379-402` and `src/ledger/LedgerManagerImpl.cpp:2530-2555, 2625-2712, 2973-3042` — built the index while `applyParallelPhase` materializes `TxBundle`s/`ApplyStage`s and passed the matching indexed stage/cluster footprints through parallel apply.

### Demonstration

The production change moves duplicate footprint classification and TTL-key derivation into a single pass performed while stages and clusters are already being materialized. Global setup now reserves from the precomputed estimate and reuses unique classic/Soroban read-only key vectors; per-stage thread merges reuse the precomputed read-write-plus-TTL set; and thread-state initialization reuses each cluster's ordered key vector, preserving deterministic stage and cluster behavior while removing repeated scans.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`. Built successfully with `make -j $(nproc)` using `ALL_SOROBAN_GIT_STATE_STAMPS=` to work around this linked-worktree submodule stamp path. Full regression suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j $(nproc) check ALL_SOROBAN_GIT_STATE_STAMPS=`; final output reported `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
