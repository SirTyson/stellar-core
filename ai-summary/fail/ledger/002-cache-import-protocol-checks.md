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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/ledger` or `ai-summary/success/ledger`
**Failed At**: reviewer

### Trace Summary

The redundant work does exist: enforcing Soroban invocation passes the shared module cache into the Rust host, `Host::call_contract_fn` instantiates a fresh `Vm` for each Wasm contract call, cache hits reuse an immutable `Arc<ParsedModule>`, and `Vm::instantiate_wasmi` calls `ParsedModule::check_contract_imports_match_host_protocol` before every linker instantiation. That check rebuilds a `BTreeSet` of module imports and scans `HOST_FUNCTIONS` for protocol ranges on every instantiation, even though the cached module imports and ledger protocol are unchanged during a ledger close. However, the measured target zone is only 224.0 ms across the full current soroswap diagnostic trace, below the 3% Medium objective floor even under an ideal implementation that removes it completely.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — enforcing invoke-host-function execution calls `rust_bridge::invoke_host_function` with the apply-state `SorobanModuleCache`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — the bridge dispatches to the p26 host, installs the optional `ModuleCache` on the `Host`, and enters `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls invoke `instantiate_vm`; when storage confirms the contract code exists and `ModuleCache::get_module` returns a cached parsed module, the path calls `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:830-900` — cache-miss and same-ledger-upload paths use a throwaway isolated engine and minimal linker, so any optimization must preserve validation there rather than globally removing the check.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` — every cached parsed-module instantiation charges cached-instantiation costs, calls `check_contract_imports_match_host_protocol`, then invokes `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153`, `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:212-263`, and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — `ParsedModule` stores the wasmi module, protocol, and cost inputs, but not imported symbols or per-ledger validation state; `with_import_symbols` rebuilds the import-symbol set before `check_contract_imports_match_host_protocol` scans `HOST_FUNCTIONS`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` and `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-195` — `ModuleCache` stores `Arc<ParsedModule>` values and a reusable maximal linker, so cached modules are immutable shared objects suitable for a correctness-preserving memoized validation result.
- `src/ledger/SharedModuleCacheCompiler.cpp:98-115`, `src/ledger/SharedModuleCacheCompiler.cpp:197-215`, and `src/rust/src/soroban_proto_any.rs:701-777` — the C++ compiler populates protocol-specific caches and hands shallow clones of the same underlying `ModuleCache` to apply workers.
- `ai-summary/CURRENT_STATE.md:41-64` and `ai-summary/fail/ledger/013-async-addlivebatch-overlap-in-finalize.md:52-55` — the current accepted baseline has soroswap medians around 270-276 ms, and the same current diagnostic trace reports a 296 ms apply-thread zone as only about 2.88% of the trace; the 224 ms import-check zone is necessarily smaller.

### Why It Failed

The optimization target is real but below this objective's severity threshold. The hypothesis's own evidence bounds the maximum possible saving at 224,014,414 ns over 20,389 calls, about 11 us per VM instantiation. Using the current baseline medians in `CURRENT_STATE.md`, that is roughly 1-2% of soroswap apply time depending on whether it is normalized by the non-Tracy medians or by the diagnostic-trace zone percentages. Even eliminating the check completely cannot reach the objective's required 3-10% Medium range, and a safe implementation would likely save less because it still needs protocol-sensitive validation for cache misses, uploads executed in the same ledger, and potentially ledger-protocol-dependent memoization.

### Lesson Learned

Per-instantiation VM cleanup hypotheses must be normalized against current end-to-end apply time, not against the larger `Vm::instantiate_wasmi` envelope. A redundant cached-module validation scan can be structurally correct to remove, but a 224 ms full-trace zone is sub-Medium on the current soroswap baseline and should not be promoted without evidence that it composes with a broader VM-instantiation optimization.
