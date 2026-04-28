# H001: Cache Wasmi Instance Templates for Repeated Soroswap Contract Calls

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated Wasmi linker instantiation for the same cached contract modules
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban Wasm contract call in apply should still execute against a fresh store, fresh linear memory, fresh globals, identical fuel transfer, identical budget charges, and identical host imports. The module cache should continue to validate that the contract code exists in storage, should not share mutable guest state across calls or transactions, and should preserve deterministic call ordering within every cluster.

## Mechanism

`Host::call_contract_fn` instantiates a new `Vm` for every Wasm contract frame, even when the `ModuleCache` already holds the parsed module and shared linker for that contract hash. The current soroswap trace shows this is on the measured apply path: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has 341.274 ms of self-time across 5,100 calls, with 304.614 ms of those events overlapping `applyLedger`; the enclosing `Vm::instantiate_wasmi` events overlap 685.751 ms of aggregate apply time. Caching a protocol/module-specific instantiation template such as a Wasmi pre-instantiation artifact, while still creating a fresh store/instance per call, should remove repeated import-link resolution and instance preparation without changing consensus-visible VM state or exceeding the existing `NUM_CLUSTERS` parallelism.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) using the trace listed in `ai-summary/CURRENT_STATE.md`. The issue triggers on every transaction that calls the same router/pair/SAC-adjacent Wasm contracts repeatedly through `InvokeHostFunctionOpFrame::doParallelApply`, causing `Host::call_contract_fn` to instantiate the cached module again for each contract frame.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — `Host::call_contract_fn` retrieves the contract instance and calls `instantiate_vm` for every Wasm frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-900` — `instantiate_vm` checks storage, fetches `ParsedModule` from `ModuleCache`, and calls `Vm::from_parsed_module_and_wasmi_linker` on every cache hit.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` constructs a `Store`, charges instantiation cost inputs, calls `wasmi_linker.instantiate`, ensures no start function, and records the hot `Vm::instantiate_wasmi - instantiate` Tracy zone.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-25` — `ModuleCache` currently stores parsed modules and a linker, but not an instantiation template.

## Evidence

The headline soroswap trace confirms the zone lives inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` has 5,100 events, 341.274 ms self-time at `vm.rs:171`, and 4,644 events overlapping apply windows for 304.614 ms of aggregate apply time. The broader `Vm::instantiate_wasmi` zone overlaps 685.751 ms of aggregate apply time, while `Vm::invoke_function_raw` overlaps 4.682 s, confirming the repeated instantiation happens under `InvokeHostFunctionOpFrame doParallelApply` rather than tx-set construction. Structurally, `ModuleCache` already avoids reparsing/recompiling modules, but every cache hit still pays `wasmi_linker.instantiate` before each call; soroswap repeatedly calls a small set of contracts, making a fresh-instance-from-template path plausibly worth 3-10% top-line apply time if it removes most of the 304 ms aggregate instantiation self-time.

## Anti-Evidence

Wasmi instances and stores are mutable: linear memory, globals, fuel, and host state must not be reused across calls. A viable PoC must therefore cache only immutable or safely reusable instantiation preparation, not a live `Vm`, `Store`, or `Instance` whose guest state may have been mutated. The existing storage-existence check before a module-cache hit is a correctness guard and should remain; if Wasmi does not expose a reusable pre-instantiation representation that still creates fresh instances cheaply, the removable portion may be below Medium severity.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The p23+ Soroban parallel apply path enters `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge, constructs a fresh p26 `Host`, installs the shared `ModuleCache`, and invokes the host function. For each Wasm contract call, `Host::call_contract_fn` retrieves the contract instance, checks contract-code storage before trusting the cache, and then calls `Vm::from_parsed_module_and_wasmi_linker` even on cache hits. `Vm::instantiate_wasmi` creates a new store, charges cached-instantiation budget, validates imports against the host protocol, calls `wasmi_linker.instantiate`, finalizes with `ensure_no_start`, and records the memory export. The repeated instantiation cost is real, but the proposed reusable instance-template mechanism is not available in the current wasmi fork without caching mutable per-store state or changing wasmi internals.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `InvokeHostFunctionApplyHelper::invokeHostFunction` serializes apply inputs and calls `rust_bridge::invoke_host_function` for every Soroban transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` confirms this path is used by protocol-23+ parallel Soroban apply.
- `src/rust/src/soroban_invoke.rs:7-60` — Rust bridge dispatch selects the protocol-specific host and forwards the shared `SorobanModuleCache`.
- `src/rust/src/soroban_proto_any.rs:410-448` — p26 dispatch builds the budget and calls `invoke_host_function_with_trace_hook_and_module_cache` inside the measured invoke function span.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — the host is constructed fresh for the invocation, auth/storage/ledger/module-cache state are installed, and `host.invoke_function` is called.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` — `HostFunction::InvokeContract` converts arguments and enters `call_n_internal`, which calls `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — `call_contract_fn` and `instantiate_vm` retrieve the contract instance, preserve the storage-existence guard, load `ParsedModule` from `ModuleCache`, and instantiate a fresh `Vm` on every cache hit.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh `Store`, charges instantiation costs, validates imports, runs the hot `wasmi_linker.instantiate`, ensures no start function, and extracts memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-25,160-204` — `ModuleCache` stores a shared `Engine`, maximal `Linker`, and parsed modules, but has no reusable instance-template storage.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:81-135,146-153,213-228` — cached modules avoid parsing, but instantiation budget and per-instance setup are still charged separately.
- `src/rust/src/soroban_module_cache.rs:22-60` and `src/rust/src/soroban_proto_any.rs:761-776` — shallow clones share the underlying protocol cache, so any added template would also have to be thread-safe across C++ apply workers.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:646-658` — the public linker API resolves imports and returns a fresh `InstancePre` from `module.instantiate`; it does not expose a reusable prelinked template.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/pre.rs:11-80` — `InstancePre` is a single-use partial instance containing an allocated `Instance` handle and builder, consumes itself in `ensure_no_start`, and is not `Clone`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:49-78` — module instantiation allocates a new instance and initializes imports, functions, tables, memories, globals, exports, table elements, memory data, and start metadata for the current store.

### Why It Failed

The claimed inefficiency exists, but the proposed "cache Wasmi instance templates/pretemplates" fix is not viable in the target code. The only wasmi pre-instantiation type currently exposed is `InstancePre`, and it is not an immutable reusable template: it is constructed inside a specific store, owns an allocated instance handle plus builder state, consumes itself to initialize that store, and cannot be cloned or shared. Caching a live `Vm`, `Store`, `Instance`, or `InstancePre` would share mutable linear memory, globals, fuel state, relative object tables, or host references across calls and would break Soroban execution isolation.

Changing only stellar-core / soroban-env-host can therefore keep the existing parsed-module/linker cache, but cannot skip `wasmi_linker.instantiate` while still producing fresh instances. A deeper wasmi redesign might precompute import lookups or instance-layout metadata, but the mandatory per-call work still includes fresh store allocation, instance allocation, memory/table/global/export initialization, data segment copying, and no-start finalization. The cited 304.614 ms apply-overlap self-time is an upper bound over all of `Linker::instantiate`, not the small subset that a safe template could remove; without a reusable wasmi template API, the implementable savings are below the optimize-soroswap Medium threshold.

### Lesson Learned

For Soroban VM instantiation, `InstancePre` is not a cacheable "pretemplate"; it is a per-store, single-use partially instantiated instance. Hypotheses targeting cached instantiation need either an explicit wasmi API that creates fresh instances from immutable prelinked metadata, or isolated measurements showing that a narrower safe optimization such as import lookup caching can clear the 3% apply-time floor.
