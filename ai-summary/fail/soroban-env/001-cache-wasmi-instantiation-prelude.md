# H001: Cache Wasmi Instantiation Prelude for Repeated Soroswap Calls

**Date**: 2026-04-27
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: soroswap apply-time reduction by reducing repeated Wasm instantiation overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When many soroswap transactions invoke the same small set of already-cached contract modules in one ledger close, the host should reuse all deterministic, module-specific instantiation work that does not depend on per-transaction `Host` state. Each transaction still needs a fresh `Store<Host>`, memory, globals, and execution state, but import resolution and other immutable module/linker preparation should be performed once per cached module/protocol rather than on every invocation.

## Mechanism

`ModuleCache` stores parsed `wasmi::Module`s and a shared maximal linker, but `Vm::instantiate_wasmi` still calls `wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` for every VM construction. In the current soroswap trace, `Vm::instantiate_wasmi - instantiate` accounts for 316,914,184 ns self-time across 4,686 calls inside `applyLedger`; if a pre-resolved `InstancePre` or equivalent immutable instantiation prelude were cached with each `ParsedModule`, repeated soroswap calls could instantiate from that prelude while preserving fresh per-call state. This should reduce apply time without changing determinism because cached data would be derived solely from contract Wasm, protocol host imports, and the selected wasmi engine, not from transaction order or mutable ledger state.

## Trigger

Run the current `soroswap, TX=4000, T=8` apply-load benchmark using the baseline trace in `ai-summary/CURRENT_STATE.md`. The trigger is a ledger with thousands of invoke-host-function operations that repeatedly instantiate the same soroswap and SAC Wasm modules from the shared module cache.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a fresh store and invokes linker instantiation on every VM construction.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-207` — `Vm::from_parsed_module_and_wasmi_linker` routes every cached module invocation through `instantiate_wasmi`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` currently caches parsed modules and one linker, but not per-module pre-instantiation state.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:147-154` — `ParsedModule` contains only the parsed module, protocol, and cost inputs; this is the likely place to associate immutable per-module instantiation metadata.

## Evidence

The current soroswap Tracy trace (`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`) reports `applyLedger` total time of 4,591,086,908 ns over 65 ledgers. Self-time export reports `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` with 316,914,184 ns self-time over 4,686 calls, about 6.9% of the measured `applyLedger` envelope. Unwrapped samples for that zone occur on worker threads during `applyLedger` windows, confirming this is apply-path work rather than TX-set construction.

The source already separates parsed-module caching from instantiation: `ModuleCache` keeps `Arc<ParsedModule>` values, and `Vm::from_parsed_module_and_wasmi_linker` still passes each one to `instantiate_wasmi` for a fresh linker instantiation. Soroswap is a repeated-contract workload, so a per-module cached instantiation prelude has a plausible multi-percent win.

## Anti-Evidence

Wasmi instances include mutable memory, globals, fuel/store state, and a `Host` in the store, so whole `Vm` or `Instance` reuse would be unsafe and nondeterministic unless all mutable state were reset exactly. The viable optimization must cache only immutable, protocol- and module-derived pre-resolution state and must keep one fresh store/instance per invocation. If the wasmi version used here cannot expose a reusable pre-instantiation object for the current linker/import setup, this may require a larger dependency/API change and could fail at review despite the hot zone.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### What's Wrong

The hot path and repeated work are real, but the proposed cache object is not viable as stated. In the pinned `soroban-wasmi` version, `wasmi::Linker::instantiate` returns `InstancePre`, but that value is already tied to the specific `Store` used for the current invocation: it contains an allocated `Instance` handle and an `InstanceEntityBuilder`, and `ensure_no_start` consumes it to initialize that store. Caching and reusing this `InstancePre` would reuse per-invocation mutable VM state rather than just immutable module/linker preparation.

The measured `Vm::instantiate_wasmi - instantiate` zone also includes unavoidable per-invocation work: allocating the instance, creating store-local imported host `Func` handles, allocating internal Wasm funcs, creating fresh tables/memories/globals, initializing table elements and memory data, and building exports. The current target code in `soroban-env-host` does not expose a way to cache only the import-resolution subset, and the hypothesis overstates the amount of the 6.9% zone that a safe prelude cache could remove. Under the optimize-soroswap objective's Medium-only review gate, this needs a concrete cacheable subset and measured/estimated 3-10% top-line impact before promotion.

### Alternative Angle

A refined hypothesis could target a precise immutable artifact rather than `InstancePre`: for example, a new `soroban-wasmi` instantiation-plan API that precomputes module import keys/types against the fixed host linker, then still allocates fresh store-local funcs, memory, globals, tables, data segments, and exports on every invocation. A smaller host-only angle is to cache `ParsedModule` import-symbol/protocol-gating metadata so `check_contract_imports_match_host_protocol` does not rebuild the import-symbol set on every VM instantiation, but that is likely below the Medium threshold unless profiling shows it dominates.

### Additional Code Paths

- `src/rust/src/soroban_proto_any.rs:310-440` — C++/Rust invoke-host-function bridge enters Soroban execution during ledger apply and passes the shared module cache into `e2e_invoke`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — contract calls instantiate a VM before pushing the `ContractVM` frame and invoking the exported function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit path retrieves `Arc<ParsedModule>` from `ModuleCache` and still calls `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,189-195` — `ModuleCache` caches a shared engine, maximal linker, and parsed modules, but no reusable per-module instantiation plan.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — every VM construction creates a fresh `Store<Host>`, charges instantiation, checks import/protocol compatibility, runs `wasmi_linker.instantiate`, calls `ensure_no_start`, and looks up memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153,212-228,265-268,403-454` — `ParsedModule` stores only the parsed module, protocol, and cost inputs; import-symbol extraction and protocol-gating are recomputed from module imports.
- `soroban-wasmi/src/linker.rs:646-658,670-702` — linker instantiation resolves each module import against linker definitions, checks types, and returns store-local `Extern` values.
- `soroban-wasmi/src/linker.rs:341-367` — resolving a linker-owned host function allocates a new host `Func` in the current store, so the resolved function handle itself cannot be reused across stores.
- `soroban-wasmi/src/module/instantiate/pre.rs:4-15,67-79` — `InstancePre` owns a store-allocated instance handle and builder and is consumed by `ensure_no_start`.
- `soroban-wasmi/src/module/instantiate/mod.rs:49-77,94-159,167-367` — module instantiation performs store-local allocation and initialization of imports, funcs, tables, memories, globals, exports, element segments, and data segments.
