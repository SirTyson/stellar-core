# H001: Journal enforcing storage writes and frame rollback instead of rebuilding maps

**Date**: 2026-05-03
**Subsystem**: transaction-ledger / Soroban host storage apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by combining storage-map write rebuilding and frame rollback snapshots into one protocol-gated mutable enforcing-storage design
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In enforcing Soroban apply, each transaction should produce the same storage reads, writes, events, auth results, rollback behavior, and ledger changes in the same deterministic order. On successful frames, however, the host should not need to clone the whole enforcing `StorageMap` at frame entry and then rebuild the whole sorted map again for every write when the enforcing key set is already fixed by the footprint.

For p26 ledgers, exact existing metering must remain unchanged. For a next-protocol-gated optimization, the expected behavior is that resource-limit safety and deterministic ledger output are preserved while the protocol intentionally adopts cheaper budget numbers for the now-cheaper storage bookkeeping.

## Mechanism

The accepted baseline already builds enforcing-mode side indices for footprint and storage positions, but the hot write path still treats `StorageMap` as a persistent vector map. `Storage::put_opt_helper` calls `MeteredOrdMap::insert_at_known_position`, which charges the old lookup/build profile and constructs a fresh vector around the replaced position; independently, every `Host::push_context` snapshots the full storage map for possible rollback. Soroswap executes many nested Wasm and SAC frames that usually succeed, so the actual behavior pays both full-map rollback snapshots and full-vector write replacement on the success path.

A next-protocol PoC can replace enforcing-mode storage with a fixed-key mutable value vector plus per-frame rollback journal. Each write records the old value for the current frame only once, updates the known position in place, and discards the journal on successful pop; on error, the journal restores prior values in reverse order. This preserves deterministic map order and rollback semantics while removing the shared root cause behind two previously sub-threshold optimizations: full-map frame snapshots and per-write vector rebuilds.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Add narrow Tracy spans or counters around `Host::push_context` storage-map cloning, `Storage::put_opt_helper` indexed replacement, and `MeteredOrdMap::insert_at_known_position` vector construction. The hypothesis is triggered by successful router/pair/SAC calls in a normal soroswap swap, especially SAC transfer frames that write balance slots and extend TTLs.

Implement the journaled map only for enforcing mode, keep recording mode on the existing path, protocol-gate any budget change, and compare three non-Tracy matrix runs against the accepted 270-276 ms soroswap median range.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-522` — accepted baseline builds the initial enforcing storage map, clones it as `init_storage_map`, derives positional metadata, and constructs the host storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — enforcing storage already builds fixed-key side indices, which make stable positional mutation feasible.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-345` — indexed read path proves enforcing-mode lookups can use known positions while preserving the legacy error budget profile.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` — indexed write path still replaces values by calling `insert_at_known_position` and assigning a rebuilt map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:356-384` — `insert_at_known_position` still charges access/binsearch/deep-clone/scan and constructs a new vector for each replacement.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` snapshots the whole storage map for rollback before pushing every frame.

## Evidence

Current Tracy validation from the recorded soroswap trace confirms these costs are in the `applyLedger` subtree. In the longest `applyLedger` window, `push context` accounts for **135.482 ms** over 13,676 calls, `new map` for **113.353 ms** over 42,832 calls, `storage put` for **29.779 ms** over 8,543 calls, and `map lookup indexed` for **138.028 ms** over 196,479 calls. These zones are reached under `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`.

The source structure shows a common removable mechanism rather than two unrelated micro-optimizations: enforcing storage key positions are fixed, but the implementation still clones or rebuilds full vector maps for rollback and writes. Previous isolated attempts at in-place storage updates and lazy frame snapshots were below the objective threshold individually; a single journaled enforcing-storage representation attacks both costs at once and can plausibly clear Medium if it removes a substantial fraction of the combined success-path bookkeeping.

## Anti-Evidence

Budget accounting is protocol-visible. A PoC that simply removes `MeteredOrdMap` clone/rebuild charges on p26 would change `cpu_insns`/`mem_bytes` and could alter budget-exceeded outcomes; the optimization must either reproduce exact old charges or be gated behind the next protocol with expected budget updates.

The full Tracy categories are not wholly removable. `push_context` includes auth-frame work, `storage put` includes footprint checks and entry validation, and `new map` is shared with non-storage map construction. The PoC must add narrow measurement around the storage-map clone/rebuild subset and demonstrate the combined non-Tracy apply-time improvement survives three runs.

The mutable map must preserve rollback exactly across nested frames, including failed Wasm calls, failed SAC calls, event rollback, auth rollback, and storage writes followed by reads in the same frame. Recording mode and tests that directly mutate `Storage` internals should remain on the existing immutable-map path unless equivalence is proven separately.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related standalone in-place-write and lazy-frame-snapshot hypotheses were rejected as individually below threshold, but this combined journaled enforcing-storage representation has not been previously reviewed; existing success records cover setup-time bulk map construction and typed SAC balance storage, not runtime frame rollback plus write journaling.

### Trace Summary

The close-ledger soroswap path applies Soroban transactions through parallel cluster workers, each invoke-host operation constructs enforcing p26 host storage in `e2e_invoke::invoke_host_function`, then executes nested Wasm and SAC frames through `Host::with_frame`. The current accepted storage representation already fixes enforcing map key positions with side indices, but `Host::push_context` still clones the whole `StorageMap` for rollback on every frame and each enforcing write or TTL extension still rebuilds a fresh vector through `MeteredOrdMap::insert_at_known_position`. On successful frames, those rollback snapshots are discarded by `pop_context(None)`, making the clone/rebuild pair a real success-path cost in the current 270-276 ms soroswap baseline.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:24-26,95` — prior in-place storage-map update and lazy rollback snapshot reviews found each component below the Medium floor in isolation and emphasized cluster-normalized critical-path sizing; neither reviewed the combined journaled representation.
- `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md:57-74` — existing success covers setup-time construction of footprint/storage maps before host execution, not runtime writes or per-frame rollback.
- `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:57-74` — existing success covers SAC typed storage conversion, not storage-map rollback/write representation.
- `ai-summary/CURRENT_STATE.md:41-54,71-84` — the authoritative current soroswap baseline is three non-Tracy `TX=2000, T=8` medians of 272.250 / 275.886 / 270.551 ms; Tracy attribution is diagnostic only.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — after building the enforcing storage map, the host clones `init_storage_map` for final ledger diffing, constructs `Storage::with_enforcing_footprint_and_map`, derives positional metadata from `storage.map`, and then creates the host.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-194` — `Storage` carries the `StorageMap` plus enforcing-only `LedgerKey -> position` side indices; comments state the enforcing key set is fixed and only values change.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — `with_enforcing_footprint_and_map` builds side indices over the footprint and storage vectors once, making stable positional mutation feasible for enforcing mode.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352` — read access can already bypass binary search with `get_at_known_position` while preserving legacy error/budget behavior, confirming the fixed-position model is already accepted.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` — `put_opt_helper` enforces write access, then uses `insert_at_known_position` when the enforcing side index is present; the returned rebuilt map is assigned back to `self.map`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:600-628` — TTL extension performs the same indexed replacement through `insert_at_known_position` when live-until changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — ordinary `insert` reconstructs the vector around the changed entry through cloned prefix/suffix iterators and `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:356-384` — `insert_at_known_position` skips comparisons but still charges access/binsearch/deep-clone/scan, collects a new vector, and returns a new `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:44-48,190-204` — `RollbackPoint` owns a full `StorageMap`, and `push_context` fills it by `metered_clone` of the current storage map before every frame is pushed.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:210-230,404-562` — `with_frame` rolls storage back from the snapshot only on error; on success, `pop_context(None)` discards the snapshot after required instance-storage persistence and lifecycle hooks.

### Findings

The inefficiency exists on the traced hot path. Enforcing storage already has fixed key positions, so replacing one entry value does not require rebuilding the sorted `(LedgerKey, value)` vector for ordering correctness; similarly, successful frames do not need a full storage-map rollback image if the same old values can be restored from a journal only when an error occurs.

The path is hot for soroswap. Every invoke-host transaction enters the p26 host, router/pair execution creates nested Wasm/SAC frames, and SAC transfer/write/TTL code reaches `Storage::put` and `Storage::extend_ttl`. The prior component reviews show upper bounds around one to two percent each when isolated on older baselines; on the current 270-276 ms baseline, removing a substantial fraction of the combined clone/rebuild work is plausibly in the 3-10% objective band, while the full raw Tracy categories remain too broad to count wholesale.

The proposed fix is structurally correct if implemented narrowly. Enforcing mode preinitializes the storage map with all footprint keys and keeps the key set fixed, so a mutable value vector plus position side index can preserve deterministic iteration order and final ledger changes. A per-frame journal must record the old value for each position at most once per frame, restore in reverse frame order on error, and discard on success after `persist_instance_storage` / reload checks decide whether the frame actually succeeded.

The main correctness constraint is protocol-visible metering. Current p26 behavior deliberately charges the old `MeteredOrdMap` lookup/build profile even on indexed writes; the PoC must either keep p26 charges exact while only reducing wall-clock allocation/copy cost, or gate cheaper charges behind the next protocol and update budget-number expectations accordingly. Recording mode, test-created storage without side indices, final materialization for `get_ledger_changes`, event rollback, and authorization rollback should continue to use their existing semantics.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, and any narrow `e2e_invoke.rs` adaptation needed to materialize final/initial `StorageMap` views for ledger changes.
- **Change description**: Add an enforcing-only storage representation that keeps the sorted key vector and mutable value slots by position, with a per-frame rollback journal. Replace enforcing `put_opt_helper` and TTL-extension value replacement with in-place slot updates; replace `RollbackPoint.storage: StorageMap` with a journal checkpoint for enforcing storage while preserving the existing snapshot path for recording/test storage or p26 exact-metering fallback.
- **Correctness check**: Preserve frame success/error behavior in `Host::with_frame`, `persist_instance_storage`, `maybe_reload_instance_storage_on_frame_pop`, event rollback, and `AuthorizationManager::pop_frame`; existing host tests around SAC rollback, invoker auth rollback, event rollback, and storage lifetime extension are the most relevant regression coverage.
- **Benchmark focus**: Add temporary narrow counters/spans for storage-map clone bytes/count in `push_context`, vector rebuild count/bytes in `insert_at_known_position`, and journal restore/discard counts. The PoC should compare three non-Tracy `soroswap, TX=2000, T=8` runs against the `272.250 / 275.886 / 270.551 ms` baseline and should only claim success if the median improvement is reproducibly at least 3%.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-34,252-388,550-559,711-720` — added an enforcing-mode rollback journal, initialized it for enforcing storage only, charged p26-compatible clone/rebuild budget without cloning on frame push, restored journaled values on error, merged successful child-frame journals into parent frames, discarded the outermost journal on success, and routed indexed writes plus TTL extensions through in-place replacement.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1-17,44-48,190-238` — changed rollback points to carry a storage rollback token, asked `Storage` to create a journal-or-snapshot rollback point during `push_context`, and committed or rolled back that point from `pop_context` while preserving event and authorization rollback behavior.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:1-12,391-431` — exposed helpers to charge a metered clone without performing it and to replace a known-position value in-place while preserving the legacy indexed-write budget profile.

### Demonstration

The PoC demonstrates the reviewed optimization by using the already-fixed enforcing storage key positions as mutable value slots and recording old values once per frame in a rollback journal. Successful nested Soroban/SAC frames now merge their rollback entries into the parent frame, so a later parent failure still restores child writes, while fully successful invocations discard small journal vectors instead of dropping full cloned storage maps. Writes and TTL extensions avoid rebuilding the sorted storage vector and still preserve deterministic order plus p26-visible budget charges.

### Test Results

`./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` completed successfully, `make -j30` completed successfully after fixing compile issues, and `NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make check` completed successfully. The final test tail included p26 Rust host tests passing (`751 passed; 0 failed; 2 ignored`) and the top-level check summary `All 2 tests passed`.
