# H002: Protocol-Gated AOT Backend for Soroswap Wasm Hot Path

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap apply-time reduction by replacing repeated interpreted router/pool Wasm execution with deterministic compiled execution while preserving host-call semantics
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-next ledgers, Soroban should execute the same vendored soroswap router and pool Wasm modules with identical trap behavior, fuel/budget consumption, host-call ordering, storage access, auth consumption, events, return values, and ledger writes. The observable execution must remain deterministic across nodes. The optimization should change only the execution backend used after module validation and cache lookup: the router and pool still run their original Wasm semantics, but their hot Wasm basic blocks execute through a deterministic AOT/direct-threaded backend instead of the current per-call wasmi interpreter instance.

## Mechanism

The current apply path instantiates and interprets two Wasm frames per successful soroswap swap. The current trace confirms this work is inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has **828,526,782 ns self-time over 14,040 calls**, and `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` has **12,652,494,561 ns total-time over 13,983 calls**. Host-function dispatch (`call` at `soroban-env-host/src/vm/dispatch.rs:304`) accounts for **9,356,083,872 ns** of that total and must mostly remain, leaving roughly **3.3s aggregate VM-side work** plus instantiation cost as the removable target. A protocol-gated compiled/direct-threaded backend keyed by validated `ParsedModule` can keep the same host-call trampolines and fuel accounting but avoid repeated interpreter dispatch, export lookup, and per-call instance setup for the fixed router/pool modules.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on a build where `ModuleCache::compile` builds an additional protocol-next AOT artifact for the vendored soroswap router and pool hashes, and `Vm::from_parsed_module_and_wasmi_linker` selects that backend only when:

1. ledger protocol is greater than p26,
2. the code hash matches a validated cached module,
3. the module imports exactly the supported Soroban host functions,
4. memory/table/global initialization is represented in the compiled artifact, and
5. a runtime feature flag can force fallback to the current wasmi path for A/B comparison.

The PoC should run the same generated ledger once with fallback and once with AOT enabled, then byte-compare results/meta/ledger changes. Diagnostic Tracy should show lower `Vm::instantiate_wasmi - instantiate` count/time and lower VM-side residual time under `Vm::invoke_function_raw` while `call` host-dispatch counts remain comparable.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-186` — current wasmi store/instance creation and `Vm::instantiate_wasmi - instantiate` zone.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` — `Vm::from_parsed_module_and_wasmi_linker`; add backend selection after protocol and module validation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw`; route compiled backend invocation through the same absolute/relative argument conversion contract.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:291-304` — keep host-call dispatch and fuel refill boundaries identical for compiled code imports.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs` — cache compiled backend artifacts alongside `ParsedModule`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` — attach validated module metadata needed by the compiled backend: imports, memories, tables, globals, data segments, element segments, and export signatures.

## Evidence

The trace puts the target underneath `applyLedger` rather than in tx-set construction: `invoke_host_function`, `Host::invoke_function`, `Vm::invoke_function_raw`, `call`, and `Vm::instantiate_wasmi - instantiate` all have unwrap events contained in the apply windows. After subtracting the mandatory host dispatch total from `Vm::invoke_function_raw`, the residual VM-side work is about **3.3s aggregate** across the trace; normalized over 8 workers and 71 apply windows this is about **5.8 ms/ledger**. Adding the instantiation child contributes about **1.5 ms/ledger**. A backend that removes most of those two components while preserving host-call bodies is close to or above the 3% Medium threshold on the current 250.7 ms soroswap median, and it materially restructures the dominant `parallelApply -> InvokeHostFunctionOpFrame -> Vm` phase.

## Anti-Evidence

Prior compiled-backend and superinstruction ideas were rejected when they did not name a concrete deterministic backend, did not isolate removable VM-side time from mandatory host calls, or did not specify fuel/trap equivalence. This hypothesis remains risky for the same reasons: a general JIT with platform-dependent code generation is not acceptable, and a backend that changes fuel timing, memory-growth behavior, passive segment handling, or trap ordering is consensus-unsafe. A viable PoC must start with a deliberately narrow protocol-next backend for the vendored router/pool modules, with forced fallback and byte-identical ledger/meta comparison before any benchmark claim.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `002-compiled-soroban-vm-backend.md + 002-protocol-gated-wasmtime-backend.md`
**Failed At**: reviewer

### Trace Summary

The hot path exists: Soroswap setup uploads fixed factory, pool, and router Wasms, and successful apply invokes those contracts through the normal Soroban `InvokeHostFunctionOpFrame` path. C++ apply enters the Rust bridge, dispatches to the p26/pnext host module, and the host resolves every `ContractExecutable::Wasm` call by fetching a cached `ParsedModule`, instantiating a fresh wasmi store/instance, pushing a `Frame::ContractVM`, and calling `Vm::invoke_function_raw`. However, the exact optimization family has already been retained as a failed/refinement record for the same missing backend, determinism, fuel/trap/metering, and isolated-impact requirements.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2855-2913` — the benchmark uploads the vendored Soroswap factory, pool, and router Wasms and records their code hashes.
- `src/ledger/LedgerManagerImpl.cpp:1484-1688` — `applyLedger` processes fees/sequence numbers and then calls `applyTransactions`, placing Soroban invocation under the ledger apply window.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` — `InvokeHostFunctionApplyHelper::invokeHostFunction` calls `rust_bridge::invoke_host_function` with the ledger protocol, resources, ledger entries, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` and `1328-1378` — sequential and parallel Soroban apply both delegate to the same host invocation helper for `InvokeHostFunction`.
- `src/rust/src/soroban_invoke.rs:7-24` — Rust selects a protocol-specific Soroban host module for the current ledger protocol.
- `src/rust/src/soroban_proto_all.rs:95-129` — the p26 adapter passes the shared `SorobanModuleCache` into `e2e_invoke::invoke_host_function`.
- `src/rust/src/soroban_proto_any.rs:391-448` — the protocol-agnostic bridge constructs the budget, then calls the protocol-specific host invocation with the module cache.
- `src/rust/src/soroban_proto_any.rs:700-736` — `ProtocolSpecificModuleCache` currently caches only parsed wasmi modules through `ModuleCache::parse_and_cache_module_simple`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — production `ContractExecutable::Wasm` calls instantiate a `Vm`, push `Frame::ContractVM`, and invoke the exported Wasm function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-900` — `Host::instantiate_vm` fetches cached `ParsedModule` entries when available but still creates a fresh `Vm` instance for each call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218` — `Vm::from_parsed_module_and_wasmi_linker` only constructs wasmi stores/instances; there is no compiled-backend selector or backend trait.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` performs absolute-to-relative argument conversion and then enters `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153` and `212-228` — `ParsedModule` contains `wasmi::Module`, protocol version, and cost inputs only; it has no validated compiled artifact or backend metadata.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-453` — host-function import protocol gating already occurs at instantiation time.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` and `45-83` — `ModuleCache` stores `Arc<ParsedModule>` behind a mutex and a single shared wasmi engine/linker, with no sidecar AOT artifact.

### Why It Failed

This hypothesis is substantially equivalent to the previously investigated compiled Soroban VM backend proposal recorded in `ai-summary/fail/soroban/summary.md:111`. The added Soroswap-specific hash gating narrows where a backend might be selected, but it does not resolve the retained blockers: there is still no existing compiled-execution backend, backend abstraction, deterministic artifact format, fuel/trap/memory-growth equivalence plan, or exact metering schedule. It also still projects Medium/High severity from broad `Vm::invoke_function_raw` and instantiation aggregates rather than a new isolated, cluster-normalized measurement of removable non-host-call VM work for the router/pool hashes.

### Lesson Learned

Compiled-backend Soroban proposals should not be resubmitted as review-ready until they name and justify a concrete deterministic backend and provide isolated upper-bound measurements for the removable VM-only portion. Code-hash gating and fallback are useful safety controls, but they do not by themselves solve consensus equivalence or objective-severity proof.
