# H002: Cache per-host contract call plans across repeated Soroswap calls

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in repeated contract-call setup for soroswap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one Soroban host invocation, repeated calls to the same contract should observe the latest contract instance and executable while avoiding redundant setup work when that instance has not changed. A host-local call-plan cache keyed by `ContractId` should be able to reuse the already-loaded `ScContractInstance`, executable discriminator, and cached `ParsedModule` handle for subsequent calls, invalidating deterministically if the contract instance entry is written or the contract is upgraded during the same invocation. This should preserve call order, fresh VM instantiation semantics, storage rollback behavior, and final ledger output.

## Mechanism

`Host::call_contract_fn` currently creates the contract-instance ledger key, retrieves the instance from enforcing storage, copies the args, and then either instantiates a Wasm VM through the module cache or enters the SAC frame on every contract call. Soroswap transactions repeatedly call a small set of router/pool/SAC contracts in one top-level invocation, so the same immutable contract instance and module handle can be looked up multiple times before any relevant instance mutation occurs. A host-local call-plan cache would leave VM instances fresh, but reuse the storage-derived plan and parsed-module `Arc`, cutting repeated `storage get`, `map lookup`, `ScVal to Val`, and module-cache lock work around the dominant `SAC transfer` / Wasm-call path.

## Trigger

Run the current soroswap apply-load benchmark. Each swap invokes a router/pool path and performs multiple token/SAC calls; across the trace there are 6,776 top-level host invocations but 20,389 Wasm instantiations and 13,527 SAC transfers, indicating several contract frames per transaction and repeated contract setup inside the worker threads.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `Host::call_contract_fn` retrieves the contract instance and dispatches to Wasm or SAC for every call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-803` — `instantiate_vm` validates contract-code presence and locks `ModuleCache` to fetch `Arc<ParsedModule>` on each Wasm contract call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:54-68,189-195` — module lookup locks the shared `BTreeMap` and clones the parsed-module `Arc`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266,693-719` — enforcing storage reads perform footprint access plus storage-map lookup for each contract-instance retrieval.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer is the hot built-in contract call path exercised by soroswap.

## Evidence

The current accepted soroswap Tracy trace was checked against `applyLedger` windows, and the target zones are descendants of apply execution rather than TX-set construction:

| Zone | Apply-window time | Calls | Source |
|---|---:|---:|---|
| `SAC transfer` | 2,153,411,257 ns total | 13,527 | `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` |
| `Vm::instantiate_wasmi - instantiate` | 1,317,542,205 ns total | 20,389 | `soroban-env-host/src/vm.rs:171` |
| `storage get` | 641,710,601 ns self | 305,065 | `soroban-env-host/src/storage.rs:329` |
| `map lookup` + `map lookup indexed` | 1,123,770,554 ns self | 1,281,890 | `soroban-env-host/src/host/metered_map.rs:173,330` |
| `ScVal to Val` | 995,921,819 ns self | 691,521 | `soroban-env-host/src/host/conversion.rs:436` |

The call-plan cache does not rely on unsafe wasmi instance reuse, so it avoids the previously rejected pristine-instance and `InstancePre` problems. It attacks repeated setup surrounding each fresh frame: instance-key construction and conversion, enforcing storage lookup, module-cache lookup, and executable dispatch. If soroswap repeatedly calls the same token/pool contracts within a transaction, invalidation-aware reuse can remove a broader slice than any single previously rejected SAC address, module-cache, or TTL micro-cache.

## Anti-Evidence

The cache must invalidate whenever contract-instance storage changes, including contract upgrades and instance storage writes that alter the stored `ScContractInstance`; otherwise it could call stale code or observe stale instance data. The PoC should keep Wasm `Vm` instantiation fresh, because reusing initialized wasmi instances is already known unsafe with the pinned wasmi API. Prior SAC metadata and module-cache-only hypotheses were below threshold, so this only remains Medium if trace or instrumentation shows enough repeated same-`ContractId` calls per host invocation for the combined setup slice to exceed those narrower rejected targets.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a combined host-local call-plan cache in retained Soroban fail/success records
**Failed At**: reviewer

### Trace Summary

The repeated setup exists: each top-level invoke-host transaction builds an enforcing `Host`, then `Host::invoke_function` enters a `HostFunction` frame, converts the invoked function and arguments, and routes contract calls through `Host::call_n_internal` to `Host::call_contract_fn`. For every contract frame, `call_contract_fn` rebuilds the instance ledger key, reads the contract instance through enforcing `Storage`, clones call arguments, and either retrieves a cached `ParsedModule` before fresh VM instantiation or enters the SAC built-in frame. Contract-instance writes and upgrades flow through `store_contract_instance`, `persist_instance_storage`, and `update_current_contract_wasm`, so a correct cache would need explicit invalidation on those paths and on rollback.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — each Soroban host invocation builds the footprint/storage map, constructs a fresh enforcing `Host`, installs the shared module cache, and calls `Host::invoke_function` inside the apply path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` pushes rollback-scoped frames, persists modified instance storage before success pop, reloads re-entrant parent frames, and rolls back storage/events/auth on errors.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1115` — `call_n_internal` performs reserved-name and reentry checks before dispatching every real contract call to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` constructs the instance key, retrieves and clones `ScContractInstance`, copies args, then dispatches to either a fresh VM frame or a SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-900` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-217` — cached-module Wasm calls still perform contract-code liveness check, module-cache lookup, protocol/import checks, and fresh wasmi `Store`/`Instance` creation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:54-68,185-195` — `ModuleCache::get_module` locks the shared `BTreeMap` and clones an `Arc<ParsedModule>`; a call-plan cache could skip this lookup only for repeated Wasm calls with an unchanged executable.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154,252-266,693-720` — enforcing reads first check footprint access, then look up and clone the storage-map entry; this is the actual storage component a call-plan cache can avoid for instance reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:75-120,167-245` — instance-key construction and contract-instance extraction are metered/cloned, and `store_contract_instance` mutates the same ledger entry that would invalidate a cached plan.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334,2541-2561` — SAC functions repeatedly extend current instance/code TTLs, and `update_current_contract_wasm` changes the executable by storing a new contract instance.
- `ai-summary/fail/soroban/summary.md:12-13,25-26` and `ai-summary/fail/soroban/001-fused-enforcing-storage-map.md:60-79` — prior retained investigations found single-lookup contract-data, SAC metadata, TTL-extension, and broader storage-map reductions real but below the optimize-soroswap Medium threshold.

### Why It Failed

The hypothesis adds several broad trace zones that the proposed cache would not remove. It does not avoid `SAC transfer` execution, fresh `Vm::instantiate_wasmi - instantiate`, argument copying, most contract-data `storage get` calls, storage writes/TTL extensions, or most `ScVal to Val` conversions; it only targets contract-instance lookup/key construction, repeated executable dispatch, and module-cache lookup around each frame.

The measured call counts bound the impact below the objective threshold. Even treating every `20,389` Wasm frame plus `13,527` SAC transfer as an avoidable instance lookup gives only about `33,916 / 305,065` of the cited `storage get` population. At the cited `storage get` self-time, that is roughly 71 ms aggregate worker CPU before parallel normalization, and the corresponding footprint/storage `map lookup` subset is of the same small order. The module-cache lookup is only a mutex-protected `BTreeMap` lookup plus `Arc` clone for 20k Wasm calls; fresh VM instantiation, the known expensive part, remains mandatory. Normalized over the 8 Soroban worker clusters used by this benchmark, the removable setup is far below the ~157 ms wall-time reduction needed to clear 3% of the 5.23 s apply-window trace.

Correct implementation would also add nontrivial invalidation machinery: `persist_instance_storage` writes modified instance storage on frame exit, immediate self-reentry explicitly persists before reentering, `maybe_reload_instance_storage_on_frame_pop` reloads parent frames, `update_current_contract_wasm` changes the executable, and `with_frame` can roll storage back. That machinery is feasible but would further reduce or offset a small cache-hit benefit. The finding is therefore a real Low/sub-1% micro-optimization, but this optimize-soroswap objective rejects Low severity at review time.

### Lesson Learned

For Soroban host-call setup hypotheses, isolate the subset of broad host zones attributable to contract-frame planning before projecting severity. A cache that preserves fresh VM instantiation and actual SAC execution can only remove instance lookup and parsed-module lookup microcosts; prior retained records already show adjacent SAC metadata, TTL-extension, single-lookup storage, and broad storage-map ideas are below the Medium floor unless new non-Tracy measurements prove otherwise.
