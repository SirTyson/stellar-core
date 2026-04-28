# H002: Add an Indexed Read Path for Enforcing Host Storage Maps

**Date**: 2026-04-28
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in host storage and footprint lookups
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During enforcing Soroban apply, host storage and footprint lookups should preserve the current sorted-map iteration order and the current budget charges, but repeated reads of transaction-local `StorageMap` and `FootprintMap` entries should not pay a full metered binary search and fallible comparison chain every time. The map should be able to answer hot `get`/`contains` lookups through a deterministic side index built from the already-validated footprint/storage keys, while keeping the canonical sorted vector for iteration, XDR output ordering, and rollback.

## Mechanism

`Storage::try_get_full_helper` reads through `self.map.get`, and footprint enforcement reads through `self.footprint.enforce_access`; both are backed by generic `MeteredOrdMap::find`. `find` charges a binary-search budget cost, then performs `binary_search_by_pre_rust_182` with a fallible `Compare` closure over XDR-heavy `LedgerKey` values. For enforcing storage, all keys are known before invocation in `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries`; a storage-specific indexed wrapper can keep the same budget charge and sorted vector semantics while replacing the wall-clock lookup with precomputed key-to-index lookup.

## Trigger

Run the current soroswap apply-load benchmark. SAC swaps repeatedly call `try_get_contract_data`, `get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl`, causing many storage-map and footprint-map probes per host invocation. A PoC should introduce an enforcing-mode storage/footprint index keyed by `LedgerKey` identity or a cached deterministic hash, route `Storage::{try_get_full_helper,put_opt_helper}` and `Footprint::{enforce_access,record_access}` hot reads through it, and verify identical ledger changes and metering.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — generic `MeteredOrdMap::find` is the hot `map lookup` zone and performs budget charging plus binary search/comparison.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:227-242` — `get` uses `find` for every storage and footprint read.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper` checks footprint access and then performs a `StorageMap` lookup.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — writes enforce RW footprint access and update the same transaction-local map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956` — enforcing footprints are built from XDR before execution, giving a natural point to build an index.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — storage maps are built from the same predeclared key set before execution and later iterated for ledger changes.

## Evidence

The current soroswap trace shows `map lookup,soroban-env-host/src/host/metered_map.rs,173` at **403,316,483 ns self-time** and **643,139,659 ns total event duration**. Timestamp containment against `applyLedger` windows found **334,490 of 350,923** map-lookup events inside `applyLedger`, totaling **619,797,065 ns**. Related host storage work is also visible inside the same windows: `storage get` has **82,208 calls** in the aggregate trace, and `visit host object` / budget `charge` account for additional per-lookup overhead around key conversion and metering.

The code path is an `applyLedger` descendant: `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> worker `parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> Rust `invoke_host_function` -> host storage operations. Unlike the already-reviewed in-place `StorageMap` write hypothesis, this one targets the read/probe side: preserving current charges while avoiding repeated binary-search wall-clock work for enforcing-mode maps whose key set is fixed before invocation.

## Anti-Evidence

`MeteredOrdMap` is generic and guest-visible maps rely on its immutable sorted-vector semantics, so the optimization must not replace the generic map type globally. A side index has memory and construction cost, and soroswap footprints are not huge; the PoC must show that lookup savings exceed index setup. Because budget consumption is consensus-visible, the indexed read path should still perform the same logical `charge_binsearch` / access charges as today unless the change is explicitly treated as a p26 metering adjustment and validated against metering tests.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The enforcing Soroban invocation path builds a `Footprint` and `StorageMap` from the declared XDR resources before constructing `Storage::with_enforcing_footprint_and_map`, so the target maps have a known key set before contract execution. Persistent/temporary contract-data host functions construct fresh `Rc<LedgerKey>` values from `Val`s, then read through `Storage::try_get_full_helper`, which first calls `Footprint::enforce_access` and then `StorageMap::get`; both operations route through `MeteredOrdMap::find` and its `map lookup` span. SAC balance paths in soroswap call `try_get_contract_data`, `put_contract_data`, and TTL extension helpers repeatedly, and `try_get_contract_data` still performs the known has-then-get double read, so the indexed path would cover many repeated storage and footprint probes rather than a one-time setup cost. The optimization must not be a pointer-identity-only index, because hot query keys are freshly allocated; it needs a `LedgerKey`-equivalence lookup, preferably with cached/precomputed hashes for stored keys while preserving the current budget charges.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — `invoke_host_function` decodes resources, builds the enforcing footprint and storage map, clones the initial storage map for diffing, then creates the host with `Storage::with_enforcing_footprint_and_map`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` validate supported keys, populate all declared keys, and add `None` entries for missing footprint keys before execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — `MeteredOrdMap::find` charges the binary-search budget and then performs a binary search using `Ctx::compare` for every lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:227-300` — `get` and `contains_key` are thin wrappers around `find`, so storage, footprint, TTL-map, and restored-key probes all enter the same hot span.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` performs a metered map lookup for every enforcing read or write access check.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper` checks read access and then performs the storage-map lookup, cloning the found entry pair.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — `Storage::put_opt_helper` enforces read-write access and then reinserts into the storage map; in enforcing mode the key should already be present from the declared footprint.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-720` — enforcing read preparation is just `Footprint::enforce_access`, confirming the hot read path has one footprint lookup plus one storage lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2317` — persistent/temporary `put_contract_data`, `has_contract_data`, `get_contract_data`, and `extend_contract_data_ttl` convert contract keys to ledger keys and route through the storage helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — SAC's helper `try_get_contract_data` calls `has_contract_data` and then `get_contract_data`, so successful reads intentionally pay the lookup sequence twice.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-96,120-145,172-199` — SAC balance reads/writes exercise persistent contract-data `try_get`, `put`, and TTL extension for contract endpoints.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166` — `storage_key_from_val` creates a new ledger key from the current contract and host `Val`; hot lookups therefore cannot rely on `Rc` pointer identity with prebuilt footprint keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:382-430` — `Budget` comparison for `LedgerKey` validates supported types and recursively compares account/trustline/contract-data fields, which is the comparison chain the index can avoid on successful probes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292` — `get_ledger_changes` iterates the sorted storage map and probes footprint/TTL/restored maps after execution, so the canonical sorted vector must remain authoritative for output ordering and diffs.

### Findings

The inefficiency exists on the described hot path. In enforcing mode, every persistent/temporary storage read performs at least two generic `MeteredOrdMap::find` calls: one in `Footprint::enforce_access` and one in `StorageMap::get`; writes and TTL extension add further footprint checks, storage insert/find operations, and post-execution diff lookups. The SAC balance code exercised by soroswap is a direct caller of these host functions, and successful `try_get_contract_data` calls compound the cost by doing has-then-get while preserving current metering semantics.

The proposed fix is correctness-preserving if it is storage-specific and keeps `MeteredOrdMap` as the canonical sorted vector. Iteration order, XDR output order, rollback cloning, and `get_ledger_changes` should continue to read the vector; the side index should only accelerate equivalent-key lookup and should still execute the same logical budget charges (`charge_binsearch`, `charge_access`, and comparison-equivalent metering decisions where applicable). A pure `Rc` identity index would be incorrect for the host-function path because query keys are reconstructed from contract `Val`s; the viable design is an index keyed by `LedgerKey` equality with stored-key hashes precomputed when the enforcing footprint/storage maps are built or refreshed.

The severity clears the review threshold as a Medium candidate. The supplied trace attributes roughly 620 ms of aggregate apply-contained `map lookup` duration, and the traced storage path accounts for a large fraction of lookup events: 82k `storage get` calls alone imply roughly 164k footprint/storage map probes before writes, TTL extension, and post-execution diff probes are counted. Even allowing for parallel worker aggregation and side-index construction cost, replacing repeated binary-search/comparison work on this subset is plausibly above the objective's 3% apply-time floor, while leaving enough uncertainty for the PoC benchmark gate to confirm or reject the exact win.

### PoC Guidance

- **Target code**: add an enforcing-storage-specific indexed wrapper around `FootprintMap` and `StorageMap` in `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, with construction hooks in `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052`. Avoid replacing generic `MeteredOrdMap` globally.
- **Change description**: keep each map's sorted `Vec<(Rc<LedgerKey>, V)>` as canonical, but build a side index from `LedgerKey` to vector index for enforcing mode. Route `Footprint::enforce_access`, `Storage::try_get_full_helper`, and enforcing-mode `Storage::put_opt_helper`/TTL update replacement lookups through the index while charging the same budget as today. Update or rebuild the index on map replacement, and make clone/rollback behavior copy a consistent index. Do not rely on `Rc` pointer identity for query keys.
- **Correctness check**: existing Rust host storage tests cover footprint enforcement, storage access, TTL extension, and metering-sensitive storage behavior; existing Soroban/SAC tests exercise `try_get_contract_data`, `put_contract_data`, and TTL extension through real host calls. The PoC should specifically verify identical ledger changes, events, and budget/resource results for persistent contract-data reads, writes, missing entries, TTL extension, and rollback.
- **Benchmark focus**: run the soroswap apply-load matrix multiple times and compare top-line median apply time against `ai-summary/CURRENT_STATE.md`'s 596.381 ms reference. Tracy should show reduced self/total duration for `map lookup,soroban-env-host/src/host/metered_map.rs,173` or a replacement storage-index zone, and the accepted result must show a reproducible 3-10% apply-time improvement to remain Medium.
