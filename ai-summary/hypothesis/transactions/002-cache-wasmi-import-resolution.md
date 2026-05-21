# H002: Cache Wasmi Import Resolution Without Reusing Contract Instances

**Date**: 2026-05-21
**Subsystem**: transactions / Soroban VM apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated per-invocation Wasmi linker/import work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban contract invocation should still receive a fresh `wasmi::Store`, `wasmi::Instance`, linear memory, globals, and fuel state, so contract execution remains stateless across invocations except for ledger storage. However, the resolution of a parsed module's imports against the same maximal Soroban host linker and the same ledger protocol should be reusable per `ParsedModule`. Reusing only deterministic import-resolution metadata should not alter contract memory, globals, traps, host-function dispatch, budget totals, or execution order.

## Mechanism

`Vm::instantiate_wasmi` creates a fresh store and then calls `wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` for every contract invocation. The current soroswap trace reports `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` with **1,315,387,452 ns self-time across 20,389 calls**, and timestamp unwrapping confirmed all of those events occur inside `applyLedger`; divided across `T=8`, this is about 164 ms, just over 3% of the 5.23 s traced apply window. A cache of protocol-checked, module-specific import bindings or an equivalent wasmi prelink plan would keep fresh instances while avoiding repeated linker-definition lookup and import compatibility work for the same router/pair modules invoked thousands of times by soroswap.

## Trigger

Run the current soroswap apply-load benchmark. Each successful invoke reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses into `rust_bridge::invoke_host_function`, and invokes multiple Wasm contracts; the trace shows **20,389 Wasmi instantiations for 6,776 parallel apply invocations**. A PoC should add instrumentation inside `wasmi_linker.instantiate` or around import lookup, cache only immutable import-resolution data keyed by `(contract code hash, host protocol/interface version)`, and compare repeated non-Tracy apply-load runs plus the `Vm::instantiate_wasmi - instantiate` zone.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-186` — `Vm::instantiate_wasmi` creates the fresh store, checks import protocol compatibility, and calls `wasmi_linker.instantiate` on every invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-210` — `from_parsed_module_and_wasmi_linker` constructs a new `Vm` around the fresh Wasmi state.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` already stores parsed modules, a shared engine, and a maximal linker, but not a per-module resolved-import plan.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-95` — `ModuleCache::new` builds the shared engine/linker once, the natural home for immutable link metadata.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply path calls `rust_bridge::invoke_host_function` for every Soroban tx, making the repeated VM instantiation cost part of `closeLedger`.

## Evidence

The relevant zone is a verified `applyLedger` descendant, not TX-set construction: unwrapped events showed all **20,389** `Vm::instantiate_wasmi - instantiate` events inside `applyLedger` windows. The broader `Vm::instantiate_wasmi` total is **1,648,211,481 ns** across the same calls, while `ParsedModule::check_contract_imports_match_host_protocol` contributes another **229,238,299 ns** in the same apply windows. Source inspection shows `ModuleCache` already avoids reparsing/recompiling modules and shares one maximal linker, leaving repeated per-invocation linker/import resolution as a plausible remaining cost center.

This is not the rejected `InstancePre`/VM-template caching line: the proposal must not cache or clone `wasmi::Instance`, `Store`, memory, globals, fuel, or any mutable contract state. It targets immutable import binding metadata only, preserving a fresh instance per invocation.

## Anti-Evidence

Wasmi may not expose an API that separates reusable import-resolution metadata from instance allocation; if the `instantiate` child zone is dominated by unavoidable fresh instance allocation rather than linker lookup, the recoverable fraction will fall below Medium. The cache must also remain protocol-aware: host imports are gated by protocol/interface version, and stale import plans across a protocol change would be incorrect. If implementation requires patching wasmi internals, the risk and maintenance cost may outweigh the projected 3-5% soroswap gain.
