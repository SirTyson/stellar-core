# H002: Cache parsed-module host import protocol validation across VM instantiations

**Date**: 2026-05-03
**Subsystem**: ledger / Soroban VM instantiation during apply
**Severity**: Medium
**Impact**: 3-4% soroswap apply-time reduction by removing repeated per-instantiation scans of cached Wasm module imports
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Once a contract Wasm module has been parsed into the shared `ModuleCache` for the current protocol, repeated VM instantiations of that cached module during `closeLedger` should not rescan the same imported host-function symbol set on every contract call. The host should still reject modules that import functions outside the module protocol or current ledger protocol, but for cache hits in a fixed-protocol ledger the validation result should be computed once per parsed module/protocol and reused by each instantiation.

## Mechanism

`Vm::instantiate_wasmi` calls `parsed_module.check_contract_imports_match_host_protocol(host)` before every `wasmi_linker.instantiate`, even when `Host::instantiate_vm` just retrieved the same immutable `ParsedModule` from the inter-ledger `ModuleCache`. That check walks the module's imported symbols and the full `HOST_FUNCTIONS` table, applying the same `min_proto`/`max_proto` tests for each of 20,389 instantiations in the soroswap trace. Storing the validated import-protocol compatibility in `ParsedModule` at parse/cache insertion time, or memoizing it by ledger protocol in the parsed module, would preserve deterministic rejection behavior while avoiding repeated O(imports x host-functions) scans on the hot apply path.

## Trigger

Run soroswap apply-load with cached router/pool/token Wasm modules. Each host invocation performs roughly three Wasm contract calls, so `Host::call_contract_fn` retrieves a cached parsed module and `Vm::from_parsed_module_and_wasmi_linker` instantiates it repeatedly during `applyLedger`; each instantiation repeats import protocol validation for a module whose imports and protocol metadata are unchanged throughout the ledger.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — `call_contract_fn` and `instantiate_vm` load contract instances, find cached parsed modules, and instantiate a `Vm` for each Wasm contract call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` (`fa1226b3`) — `Vm::instantiate_wasmi` charges instantiation, calls `check_contract_imports_match_host_protocol`, and then invokes `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` (`fa1226b3`) — `Vm::from_parsed_module_and_wasmi_linker` runs for every cached module instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` (`fa1226b3`) — `ParsedModule::check_contract_imports_match_host_protocol` repeatedly reads ledger protocol, iterates import symbols, and scans `HOST_FUNCTIONS` for min/max protocol compatibility.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:14-24` (`fa1226b3`) — `ModuleCache` stores parsed but not instantiated modules and a reusable linker, making it the natural place to attach one-time parsed-module import validation state.

## Evidence

The current soroswap trace shows `ParsedModule::check_contract_imports_match_host_protocol` with 224,014,414 ns self-time over 20,389 calls, fully overlapping `applyLedger`. The enclosing VM-instantiation path is much larger: `Vm::instantiate_wasmi - instantiate` is 1,315,387,452 ns self-time over the same 20,389 calls, and `Vm::instantiate_wasmi` itself is called from the contract-call path inside `Host::invoke_function`. The check is structurally redundant for ModuleCache hits because `ParsedModule` is immutable, its import set is fixed at parse time, and the apply ledger protocol is constant for the entire ledger.

## Anti-Evidence

The check intentionally preserves exact upload/execution rejection semantics for old, current, and future protocol contracts, so the PoC must not simply remove it. Modules uploaded and first executed in the same ledger may bypass the shared cache and must still be validated on their throwaway parsed-module path. The cache key must include the ledger protocol (or otherwise prove the module was parsed for the same protocol being executed), because a parsed module can be valid under one ledger protocol and invalid under another once host-function min/max ranges change.
