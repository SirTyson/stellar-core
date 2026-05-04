# H001: Pristine wasmi instance snapshots to bypass repeated module instantiation

**Date**: 2026-05-04
**Subsystem**: soroban-env / rust
**Severity**: High
**Impact**: Dominant-phase redesign of the remaining Wasm instantiation path in soroswap `closeLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every contract call should start from the same post-instantiation, pre-start state it starts from today: the same imported host functions, function/table/global/memory indices, data segments, exports, absence of start-function execution, resource limits, fuel state, and `Host` user data. Replacing per-call instantiation with a cached pristine instance snapshot must produce identical `wasmi::Instance`, memory, table, global, and export behavior for each invocation, while still installing the current transaction's `Host` into the store and preserving deterministic error behavior for invalid modules.

## Mechanism

The current p26 VM path parses and caches `ParsedModule`, but every contract frame still creates a fresh `wasmi::Store`, runs `Linker::instantiate`, allocates imported host funcs, allocates internal funcs/tables/memories/globals, initializes data/table segments, calls `ensure_no_start`, and then looks up memory. The current soroswap trace reports `Vm::instantiate_wasmi - instantiate` at `1,315,387,452 ns` self-time over `20,389` calls, all inside `applyLedger`; this is a dominant remaining in-apply leaf zone after prior host-metering and storage-map optimizations. A wasmi-fork-level `PristineInstanceSnapshot` cached alongside `ParsedModule` could capture the finished no-start instance/store entity layout once per module and clone/reset that immutable template into a fresh `Store<Host>` for each invocation, replacing the expensive instantiate path with deterministic arena copies plus host-data replacement.

## Trigger

Run the accepted current soroswap apply-load workload (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Each ledger repeatedly invokes the same small set of Soroswap Wasm contracts; the trace records `20,389` `Vm::instantiate_wasmi` calls under `applyLedger` for `6,776` invoke-host transactions, so normal swap execution pays fresh module instantiation roughly three times per transaction even though module code and initial instance layout are invariant.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates the fresh `Store`, runs linker instantiation, ensures no start, and looks up memory on every contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-217` — `Vm::from_parsed_module_and_wasmi_linker` wraps the instantiated store and instance; this is where a snapshot-instantiated store could be returned instead.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-25,85-95` — `ModuleCache` already owns a shared engine/linker and cached parsed modules; it is the natural home for per-module pristine instance snapshots.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:49-77` — wasmi `Module::instantiate` builds the instance entities and returns an `InstancePre`.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:106-125,730-752` — `Store<T>` owns `StoreInner` plus user data and exposes `data_mut`, suggesting a fork-level snapshot clone could replace the host data after cloning pristine entities.

## Evidence

The diagnostic trace named in `CURRENT_STATE.md` is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `Vm::instantiate_wasmi - instantiate,soroban-env-host/src/vm.rs,171,1315387452 ns,20389 calls`; an unwrap overlap check found all `20,389` events inside the `71` `applyLedger` windows. This is distinct from the rejected `InstancePre` cache: it does not try to reuse a store-bound, one-shot `InstancePre`; it proposes adding an explicit pristine-store/entity snapshot facility to the forked wasmi layer and cloning it into a fresh invocation store in the same entity order.

## Anti-Evidence

This is a deep wasmi-fork redesign, not a small capacity hint. The snapshot must prove that mutable Wasm memories/globals/tables are restored to the exact initial state, that imported host functions still call the current transaction's `Host`, that fuel/resource-limiter state starts empty, and that `StoreIdx`/guarded entity identity remains valid. The parent instantiate zone also includes work that may be hard to snapshot safely, so the first PoC should add sub-zones around snapshot clone vs. current instantiate and reject the design if template cloning plus host-data replacement does not clear the 3% Medium floor.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger Soroban parallel path launches per-cluster workers, and each invoke-host operation crosses the C++/Rust bridge into p26 `e2e_invoke`, installs the shared `ModuleCache`, and calls `Host::invoke_function`. For `InvokeContract`, the host enters `call_contract_fn`, retrieves the contract instance, calls `instantiate_vm`, hits `ModuleCache::get_module`, and then still creates a fresh `wasmi::Store<Host>` and runs `Vm::instantiate_wasmi` for every Wasm frame. Inside wasmi, `Linker::instantiate` resolves every import and allocates new store-local host functions/trampolines, then `Module::instantiate` builds the instance, allocates internal funcs/tables/memories/globals, initializes table and memory segments, and `ensure_no_start` consumes the `InstancePre` into the store. The repeated instantiation work is real, hot, and materially broader than the previously rejected public-API `InstancePre` reuse idea.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` runs Soroban clusters on worker threads and waits on their futures, so worker-local VM instantiation contributes to the apply critical path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-584,1358-1375` — parallel invoke-host application builds bridge buffers and calls `rust_bridge::invoke_host_function` with the shared `SorobanModuleCache`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/bridge.rs:193-208` — the CXX bridge selects the protocol host module and invokes p26 host execution with the module cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — constructs a fresh `Host` for the transaction, installs the passed `ModuleCache`, and enters `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1148,1186-1193` — top-level `InvokeContract` conversion enters contract-call execution and returns the final `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-801` — every Wasm contract frame calls `instantiate_vm`; cache hits return `Vm::from_parsed_module_and_wasmi_linker` with a cached `ParsedModule` but still instantiate a new VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,191-217` — `instantiate_wasmi` creates a new `Store`, charges instantiation, sets the limiter, checks imports, runs linker instantiation, calls `ensure_no_start`, and looks up exported memory before wrapping the resulting `Store`, `Instance`, and `Memory` in `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-25,85-95,160-195` — `ModuleCache` stores only shared engine/linker and `Arc<ParsedModule>` entries today; it does not cache any post-instantiation state.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:300-367,646-658` — `Linker::instantiate` processes imports each time, and linker-owned host functions allocate fresh trampolines plus fresh `FuncEntity::Host` entries into the current store.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:49-77,167-247` — `Module::instantiate` allocates an instance placeholder, extracts imports/internal functions/tables/memories/globals/exports/start, initializes table and memory segments, and returns a store-bound `InstancePre`.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/pre.rs:67-80` — `InstancePre::ensure_no_start` consumes the partially built instance and initializes the store-owned `InstanceEntity`, confirming why caching `InstancePre` itself was invalid but also identifying the exact post-no-start state a new snapshot facility would target.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:104-154,267-282,730-768,886-899` — `Store` owns `StoreInner`, store-local arenas, fuel counters, trampoline arena, host data, and resource limiter; a snapshot clone must create fresh mutable entities and fresh `Host` data while preserving zero fuel and limiter behavior.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/wasmi_arena-0.4.1/src/guarded.rs:3-34` — handles are guarded by `StoreIdx`, so a correct snapshot cannot blindly reuse stored handles from a template store unless it also preserves or remaps guarded identity safely.

### Findings

The inefficiency exists on the described hot path. `ModuleCache` avoids reparsing and recompilation, but the cache-hit path still pays fresh `Store::new`, import protocol checking, linker import processing, host trampoline/function allocation, internal entity allocation, element/data initialization, `ensure_no_start`, and memory-export lookup for each Wasm frame. The cited trace count is consistent with source structure: soroswap repeatedly invokes a small contract set, but `Vm` is per frame and not reused across invocations.

The proposed fix is technically plausible only as a fork-level wasmi change, not through current public APIs. Prior failures rule out caching `InstancePre` and generic `Store::reset`, but they do not rule out adding an explicit immutable/pristine entity snapshot plus clone path inside the fork. The wasmi internals support the idea conceptually because linker-owned host trampolines are `Arc`-backed and store-independent until `Definition::as_func` materializes store-local `FuncEntity::Host` handles, while the transaction-specific `Host` lives in `Store<T>::data` and can be installed in each cloned store.

Correctness constraints are substantial but concrete. The clone path must deep-copy mutable memories, tables, globals, data/element segments, instance entities, and trampolines so contract execution cannot mutate the cached template; install the current transaction's `Host`; set the same resource limiter; start with zero fuel; preserve deterministic import/type/start-function errors; preserve table/memory/global/export indices; and either remap every `Stored<Idx>` guard to the fresh store's `StoreIdx` or deliberately prove that template `StoreIdx` reuse cannot allow cross-store handle confusion. It also must preserve resource-limit checks currently performed during memory/table creation, either by checking them when the snapshot is built under equivalent limits or replaying equivalent checks during clone.

The expected impact clears the objective's Medium floor but should not be recorded as High without benchmark proof. The broad `Vm::instantiate_wasmi - instantiate` leaf is 1.315 s over the trace and all events overlap `applyLedger`; normalized across the eight soroswap worker clusters, eliminating the whole leaf is roughly a 3% wall-time ceiling before counting clone cost, while the unnormalized Tracy share is much larger. A successful snapshot will not remove every byte copy because pristine memories/tables/globals still need fresh mutable state, but it targets the bulk linker/import/entity-initialization path rather than a narrow micro-operation, so it is viable for PoC with Medium severity.

### PoC Guidance

- **Target code**: Add the snapshot facility in the forked wasmi crate around `Store`, `StoreInner`, `InstanceEntity`, guarded handles, and `Module::instantiate`/`InstancePre::ensure_no_start`; wire it from `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs`.
- **Change description**: Build a pristine no-start instance once per cached `ParsedModule` and clone it into a fresh `Store<Host>` for each VM instantiation, with current `Host` data and limiter installed. The clone must deep-copy mutable Wasm state and preserve all handle/export indices exactly as current instantiation would.
- **Correctness check**: Run existing Soroban VM/host tests that cover Wasm instantiation, import validation, missing memory/export errors, start-function rejection, nested contract calls, auth calls, and budget/fuel behavior. Add focused wasmi-fork unit tests for snapshot-vs-instantiate equivalence, StoreIdx/handle remapping, memory/table/global mutation isolation, and current-Host dispatch through imported functions.
- **Benchmark focus**: Add Tracy sub-zones for current instantiate, snapshot build, and snapshot clone. The PoC must show `Vm::instantiate_wasmi - instantiate` wall contribution dropping enough that repeated `scripts/run_apply_load_matrix.py` soroswap medians improve by at least 3% versus the `CURRENT_STATE.md` baseline; reject if clone cost leaves the top-line delta below Medium.
