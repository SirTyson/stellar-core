# H002: Validated Pristine wasmi Snapshots for Resettable Soroswap Modules

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce repeated per-invocation wasmi instantiation for resettable soroswap router/pool modules
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban contract invocation must start from the same initialized Wasm memory/table/global state that a fresh `wasmi::Module` instantiation would produce, with the same imports, fuel behavior, traps, and exported function semantics. For modules that can be statically proven not to mutate instance-reset-sensitive state outside ordinary linear memory writes that are discarded between invocations, the host should be able to clone a validated pristine instance image instead of walking the full wasmi instantiation path for every call.

## Mechanism

`Host::instantiate_vm` retrieves an already parsed module from `ModuleCache`, but `Vm::from_parsed_module_and_wasmi_linker` still creates a new `wasmi::Store`, runs `wasmi_linker.instantiate`, allocates an `InstanceEntityBuilder`, validates/imports functions, extracts functions/tables/memories/globals/exports, initializes elements/data, and looks up memory on every router and pool call. A previous generic pristine-instance snapshot PoC failed because arbitrary Wasm can call `memory.grow`, drop passive segments, or mutate tables in ways the pinned public API cannot reset. This narrower hypothesis adds a `ParsedModule`-time resettable-module validator and only enables snapshots for modules that have no `memory.grow`, no table mutation, no passive data/element drops, and only active initialization that can be copied from an immutable pristine image; all other modules keep the existing path.

## Trigger

Run the current soroswap apply-load benchmark. Every swap invokes cached soroswap router/pool Wasm code through `Host::instantiate_vm`; the diagnostic trace shows `Vm::instantiate_wasmi - instantiate` is entirely inside the apply window for 20,389 invocations. The PoC trigger is the router/pool modules in `src/rust/apply-load-wasm/` passing the resettable-module validator and then using a pristine-image clone path during `Vm::instantiate_wasmi`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cached-module path that currently always constructs a fresh `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — repeated `Vm::instantiate_wasmi` work to replace for validated modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:138-220` — parsed-module construction point where a resettable-module analysis result could be stored next to the `wasmi::Module`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78` — wasmi instantiation pipeline that allocates a fresh instance and initializes imports/functions/tables/memories/globals/exports/data/elements.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/instance/builder.rs:31-70` — per-instantiation builder allocation sized from module metadata.

## Evidence

The current trace reports `Vm::instantiate_wasmi - instantiate` at 1,315,387,452 ns self-time across 20,389 calls, and unwrap containment shows all 20,389 calls are inside `applyLedger`. This is a broad enough physical cost center that a resettable-image path can plausibly clear the 3% Medium floor if it removes most builder/import/export/data initialization work for the router/pool invocations while preserving the same fresh-instance semantics.

The prior generic pristine snapshot failed on arbitrary-module reset hazards, not because the target cost was absent. This candidate narrows the domain to statically validated cached modules and requires the validator to reject any Wasm that uses reset-hostile instructions or passive segments. The vendored soroswap workload has fixed router/pool Wasms (`src/rust/apply-load-wasm/soroswap_router.wasm`, `soroswap_pool.wasm`) and stable code hashes, making it testable to prove whether they satisfy the resettable subset before attempting the clone path.

## Anti-Evidence

This is still an invasive wasmi-internal optimization. If the router or pool Wasm uses `memory.grow`, mutable tables, passive segment drops, or any instance state that cannot be restored through the pinned wasmi internals, the validator must reject it and the hypothesis becomes non-viable for soroswap. A clone path must also preserve store-owned host imports, fuel limiter wiring, `Host` ownership, memory limits, start-function rejection, trap behavior, and deterministic allocation limits. If the resettable subset only avoids a small slice of instantiation after fresh memory allocation/copy remains mandatory, the expected improvement will fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md:29` (`006-reuse-wasmi-store-across-invocations.md + 002-resettable-wasmi-instance-pool.md`)
**Failed At**: reviewer

### Trace Summary

The target path is real: Soroban Wasm contracts enter `Host::call_contract_fn`, fetch a cached `ParsedModule`, and still build a fresh `Vm` by creating a new `wasmi::Store`, running `Linker::instantiate`, validating imports, finalizing `InstancePre`, and looking up the exported memory. The current wasmi instantiation path allocates store-owned instance, function, table, memory, global, data, element, and export state; those handles are guarded by a per-store `StoreIdx`, so a reusable image cannot be copied across stores through the public API. The vendored router and pool Wasms do avoid `memory.grow`, table mutation, passive drops, `memory.init`, and `data.drop`, but both mutate globals heavily and use active tables/data plus `call_indirect`, so a correct reset path still needs private wasmi state reset or clone machinery. This is therefore the same resettable Store/instance-pool family already rejected, and its best-case savings are also below the objective's Medium threshold after normalizing worker aggregate time by the 8 Soroswap clusters.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:29` — prior resettable wasmi Store/instance-pool investigation failed because the pinned wasmi public API has no `Store::reset`, and even a successful reset path was only projected at Low severity.
- `ai-summary/fail/soroban/summary.md:31,57` — related instantiation-cache attempts (`InstancePre`, minimal linkers) already found that broad `Vm::instantiate_wasmi` time cannot be removed by caching public wasmi instantiation artifacts.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls always invoke `instantiate_vm`; a module-cache hit only skips parsing and still calls `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218` — `instantiate_wasmi` creates a fresh `Store<Host>`, installs the limiter, charges cached instantiation, checks imported host functions, calls `wasmi_linker.instantiate`, ensures no start function, and records the memory export before returning a new `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:212-227,527-711` — `ParsedModule` currently stores only the parsed `wasmi::Module`, protocol, and cost inputs; the existing manual wasmparser pass can count sections but does not expose or retain a resettable instance image.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78,161-223,300-365` — wasmi instantiation allocates a new instance handle, pushes imports/functions/tables/memories/globals/exports, initializes active element and data segments, and returns a one-shot `InstancePre`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/store.rs:267-283,327-407,730-894` — a `Store` has private arenas keyed by a unique `StoreIdx`; public reset support is limited to fuel counters, not instances, functions, memories, tables, globals, data, or element segments.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/memory/buffer.rs:22-35`, `src/memory/mod.rs:131-164`, and `src/table/mod.rs:151-177,343-397` — fresh memory/table creation and active segment initialization are real per-instantiation work, but preserving fresh-instance semantics requires either repeating them or adding invasive private reset/clone support.
- `src/rust/apply-load-wasm/soroswap_router.wasm` and `src/rust/apply-load-wasm/soroswap_pool.wasm` — `wasm-tools print` inspection found no `memory.grow`, table mutation, `memory.init`, `data.drop`, or `elem.drop`, but found active element/data segments, `call_indirect`, and many `global.set` instructions, so the workload still depends on resettable mutable instance state.

### Why It Failed

This is not novel relative to the retained Soroban failure record for resettable wasmi Store/instance pooling. The narrowed validator checks remove some reset hazards for the fixed Soroswap Wasms, but they do not provide an actual reusable public wasmi artifact: `InstancePre` is one-shot, `Store`/`Instance`/`Memory`/`Table` handles are private store-owned arena references, and the public API has no way to reset or clone the full instance state other than fuel. Implementing this would require forking or extending wasmi internals to reset or clone private arenas while preserving `Host` ownership, resource limiter behavior, fuel synchronization, import trampolines, active segment semantics, mutable globals, table entries, traps, and allocation limits.

It also fails the optimize-soroswap severity floor. The cited 1.315s `Vm::instantiate_wasmi - instantiate` self-time is aggregate worker time; the objective requires wall-clock apply-time improvement, and the retained Soroban guidance says to normalize aggregate VM time by `NUM_CLUSTERS`. With 8 clusters, eliminating the entire zone would save about 164ms across the cited run, below the approximate 173ms Medium floor for the 5.77s apply-window total; any realistic snapshot path would still need to allocate or reset a store, preserve host import/fuel state, copy or reinitialize memory/table/global state, and look up exports, so it cannot remove the full zone.

### Lesson Learned

wasmi instantiation proposals must first identify a reusable artifact that exists in the pinned API, or explicitly account for the risk and remaining work of changing private wasmi store/entity internals. For Soroswap, even apparently large aggregate instantiation zones need cluster-normalized wall-clock accounting before claiming Medium severity.
