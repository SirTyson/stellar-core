# H001: Unify enforcing storage footprint and value lookups to remove duplicate `MeteredOrdMap` searches

**Date**: 2026-05-01
**Subsystem**: ledger / Soroban host storage
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by eliminating one binary-search-and-metering pass from every enforcing-mode host storage access
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During enforcing-mode Soroban execution, every storage access should validate that the key is in the transaction footprint and then load or update the corresponding storage value. Because the enforcing storage map is populated with every footprint key, this should require one deterministic lookup per key access, returning both the declared `AccessType` and the current `Option<EntryWithLiveUntil>` value.

## Mechanism

The current host keeps footprint permissions and storage values in two separate `MeteredOrdMap`s: `Footprint(pub FootprintMap)` and `Storage::map`. `Storage::try_get_full_helper` first calls `prepare_read_only_access`, which calls `Footprint::enforce_access` and performs a `MeteredOrdMap::get`/binary search over the footprint, then immediately performs another `MeteredOrdMap::get` over `Storage::map` for the same key. `Storage::put_opt_helper` similarly enforces access in the footprint and then calls `StorageMap::insert`, which performs another lookup before rebuilding the map. In enforcing mode the two maps have the same key set because `build_storage_map_from_xdr_ledger_entries` explicitly inserts `None` for every footprint key that has no ledger entry, so the duplicate lookup is avoidable: store `(AccessType, Option<EntryWithLiveUntil>)` in a single enforcing-mode table or build an enforcing-only side table that returns both permission and value by ordinal.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the current baseline trace. Each successful swap invokes host storage operations for router, pair, token, and instance entries. Every `storage get`, `storage has`, TTL extension, and write in enforcing mode currently performs permission lookup and value lookup separately, so the overhead scales with every contract storage access in `Host::invoke_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — separate `FootprintMap` and `StorageMap` aliases that currently force two maps for the same enforcing key set.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-153` — `Footprint::enforce_access`, the first lookup on every enforcing storage access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper`, which calls `prepare_read_only_access` and then looks up the same key in `self.map`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — `Storage::put_opt_helper`, which enforces write access and then calls `self.map.insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-718` — `prepare_read_only_access`, the enforcing read-access check.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1046-1051` — enforcing storage construction pads `StorageMap` with `None` for footprint-only keys, proving the enforcing key set matches the footprint key set.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-193` — `MeteredOrdMap::find`, the binary-search and budget-charge path paid repeatedly.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports:

- `map lookup` (`soroban-env-host/src/host/metered_map.rs:173`) = `638,139,693 ns` / 378,631 calls; sorted timeline overlap check shows `636,488,924 ns` and 377,067 calls are contained in `applyLedger`.
- `map lookup indexed` (`soroban-env-host/src/host/metered_map.rs:330`) = `387,476,789 ns` / 586,459 calls; `386,587,986 ns` and 584,355 calls are contained in `applyLedger`.
- `storage get` (`soroban-env-host/src/storage.rs:329`) = `454,643,242 ns` / 229,684 calls; `453,518,609 ns` and 228,838 calls are contained in `applyLedger`.
- `storage put` (`soroban-env-host/src/storage.rs:488`) = `54,008,999 ns` / 25,502 calls; `84,640,083 ns` total event time from the non-exclusive timeline export is almost entirely contained in `applyLedger`.

The code structure explains why map-lookup time is high: a single enforcing read pays one lookup in `Footprint::enforce_access` and another in `StorageMap::get`, even though the maps were built from the same footprint. Removing one of those searches for storage accesses targets a multi-percent aggregate zone without changing guest-visible storage ordering or ledger outputs.

## Anti-Evidence

- Not every `map lookup` event is from durable `Storage`; `MeteredOrdMap` is also used for host object maps, instance storage, restored-key sets, and TTL maps. The PoC must add narrower Tracy zones or counters to prove the duplicate footprint/value lookup share alone reaches the Medium threshold.
- The footprint lookup also performs budget metering. A unified lookup must preserve intended budget accounting or intentionally lower exact budget numbers only where the implementation is truly cheaper; tests that assert budget values may need narrow numeric updates.
- Recording mode has different semantics: `FootprintMode::Recording` reads through a snapshot and mutates the footprint. The optimization should be restricted to `FootprintMode::Enforcing`, where the key sets are fixed and already padded.
- The previously accepted bulk-build storage-map optimization addressed construction-time repeated inserts. This hypothesis is different: it targets per-access duplicate lookups during host execution after the map has already been built.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The hot enforcing path is `invoke_host_function` building an enforcing `Storage` from the transaction footprint, then `Host::invoke_function` dispatching contract storage operations through `Host::{has,get,put,del}_contract_data` and host data helpers. Durable storage reads call `Storage::try_get_full_helper`, which first enforces read permission through `Footprint::enforce_access` and then looks up the same key in `Storage::map`; writes similarly enforce `ReadWrite` permission and then call `StorageMap::insert`, which performs its own `find`. In enforcing mode the construction path pads `StorageMap` with `None` for footprint-only keys, and writes/deletes replace values rather than removing keys, so the footprint map and storage map have the same sorted key set for the lifetime of the invocation.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — `invoke_host_function` builds the footprint, builds the storage map, then constructs `Storage::with_enforcing_footprint_and_map` before `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956` — footprint construction inserts read-write and read-only keys into one metered ordered map with `AccessType` values.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — storage-map construction verifies every supplied ledger entry is in the footprint and pads missing footprint keys with `None`, establishing the enforcing key-set invariant.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-153` — `Footprint::enforce_access` performs a metered binary search and checks the requested `AccessType`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `try_get_full_helper` calls `prepare_read_only_access` and then immediately does `self.map.get` for the same key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — `put_opt_helper` enforces read-write access and then calls `self.map.insert`, which re-searches the storage map before rebuilding it.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-429, 431-642` — `has` and TTL extension paths funnel through `try_get_full` / `get_with_live_until_ledger`, so they inherit the duplicate read lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2210-2285` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:113-164, 509-560` — contract storage host functions and helper paths call the durable `Storage` get/has/put APIs during guest execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — `MeteredOrdMap::get` runs `find`, charges binary-search access, and then charges value access; this is paid twice for enforcing reads today.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-249` — `insert` also calls `find`, while `get_at_index` can access an already-known ordinal with only indexed access charging.

### Findings

The inefficiency exists and is on the objective hot path. The duplicate lookup is not a construction-time artifact: it happens during `Host::invoke_function` for every durable contract-data read, has, TTL extension read, and write. The same-key lookup pattern is structural in enforcing mode because access permissions and values live in separate `MeteredOrdMap`s even though enforcing storage is constructed with the same key set as the footprint and later updates preserve that key set.

The optimization is correctness-preserving if restricted to `FootprintMode::Enforcing`. A safe design can either store access type and value in one enforcing-mode table, or have access enforcement return the found ordinal/access type and use that ordinal to access or replace the storage value. Recording mode must retain its current behavior because it records new accesses, reads through a snapshot, and can have storage/footprint discrepancies after failed nested calls.

The severity is Medium, not High. The cited in-apply `storage get` time is about 454 ms in a 5.77 s apply trace, so eliminating one of the two per-read ordered-map searches can plausibly recover a 3-5% top-line slice when combined with write/TTL paths, but the aggregate `map lookup` zones include other users. A PoC must isolate the durable enforcing-storage footprint lookup share and prove the benchmark delta across repeated non-Tracy runs.

Budget accounting is the main implementation constraint. Removing a real binary search should remove its corresponding metered work, but the PoC must not accidentally under-meter unrelated operations or change recording-mode budgets. Any test updates should be limited to exact lower budget/instruction expectations caused by the eliminated ordered-map search.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/storage.rs` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs`; possibly `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` if choosing a unified enforcing storage representation at construction time.
- **Change description**: For enforcing mode only, avoid doing both `FootprintMap::get` and `StorageMap::get`/`insert` by reusing a single lookup result. The narrowest approach is to add an internal `MeteredOrdMap` API that returns the found index with the value, have `Footprint::enforce_access` return that index/access type in enforcing reads/writes, then use `StorageMap::get_at_index` or a new replace-at-index helper after asserting/debug-checking the key at that index matches. A broader approach is an enforcing-only map value that stores `(AccessType, Option<EntryWithLiveUntil>)`, while keeping recording mode on the existing separate footprint/storage machinery.
- **Correctness check**: Existing Soroban invoke, storage, TTL extension, authorization, and recording-mode tests should cover footprint enforcement, missing values, read-only/write violations, deletes, TTL bumps, and budget-sensitive behavior. Pay special attention to tests that assert budget/instruction counts and to recording-mode tests where storage and footprint do not necessarily have identical key sets.
- **Benchmark focus**: Add temporary Tracy zones or counters separating `Footprint::enforce_access` calls made from enforcing durable `Storage` reads/writes from other `MeteredOrdMap` users. The PoC should show fewer `map lookup` events in `Host::invoke_function`/`storage get` descendants and a reproducible 3-10% improvement in soroswap apply time across the objective's repeated non-Tracy apply-load matrix runs.
