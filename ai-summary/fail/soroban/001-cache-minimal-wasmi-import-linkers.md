# H001: Cache Per-Module Minimal Wasmi Import Linkers for VM Instantiation

**Date**: 2026-05-02
**Subsystem**: soroban / rust
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in repeated cached-contract VM instantiation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a cached `ParsedModule`, each contract invocation should create a fresh `wasmi::Store` and fresh `wasmi::Instance`, but it should not repeat avoidable import-resolution work against an oversized all-host-functions linker. The module's imported host-function symbols are immutable after parsing, so the cache-hit path should instantiate using a per-module minimal linker or pre-resolved import binding set that contains exactly the functions the module imports, while preserving the same missing-definition and protocol-gating errors.

## Mechanism

The current cache-hit path in `Host::instantiate_vm` uses `cache.wasmi_linker`, a single maximal linker containing every host function registered by `Host::make_maximal_wasmi_linker`. `ParsedModule` already computes its imported function symbol set in `with_import_symbols` and can build a minimal linker with `make_wasmi_linker`, but the normal module-cache path does not use that per-module information at instantiation time. On soroswap this repeats inside the apply window: the Tracy zone `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` accounts for 985,885,364 ns inside `applyLedger` across 15,312 events, so removing a material fraction of linker import lookup and binding work is plausibly a Medium-tier apply-time win without reusing `Store`, `Instance`, or `InstancePre`.

## Trigger

Run the current soroswap apply-load benchmark with the diagnostic trace from `ai-summary/CURRENT_STATE.md`. Any swap that invokes the same router/pair contracts repeatedly through the module cache will call `Host::instantiate_vm`, find the parsed module in `ModuleCache`, and instantiate it through the maximal linker on every contract call.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit `instantiate_vm` path checks storage, loads `ParsedModule`, and calls `Vm::from_parsed_module_and_wasmi_linker` with `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,160-183` — `ModuleCache` stores one shared maximal linker plus parsed modules, but not a per-module minimal linker/import binding.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:240-269` — `ParsedModule::with_import_symbols` and `make_wasmi_linker` already know the exact imported function set and can build a minimal linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — maximal vs minimal linker construction; minimal linker filters `HOST_FUNCTIONS` by imported symbols.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi`; the hot `wasmi_linker.instantiate` call targeted by this hypothesis.

## Evidence

The current trace confirms the target is inside the benchmark window: exporting individual Tracy events shows `Vm::instantiate_wasmi - instantiate` has 15,312 of 15,374 events fully contained in `applyLedger`, totaling 985,885,364 ns inside the apply windows. The same trace reports aggregate self-time for `Vm::instantiate_wasmi - instantiate` as 990,896,401 ns at `vm.rs:171`.

Code inspection shows a clear asymmetry: `ParsedModule` computes imported symbols and can build a minimal linker, but the shared module-cache cache-hit path ignores that and always passes the maximal linker. This hypothesis is distinct from rejected `InstancePre`/`Store` reuse ideas: it still creates a fresh store and instance for every call and only removes repeated import lookup/binding overhead for immutable module imports.

## Anti-Evidence

Wasmi may already resolve only the module's imports via efficient hash lookups, so the maximal-vs-minimal linker size might be a small fraction of `Linker::instantiate`; the reviewer should isolate this with a focused trace or microbenchmark before PoC. The implementation must also preserve the exact error surface for missing imports and protocol-gated functions; `ParsedModule::check_contract_imports_match_host_protocol` and linker missing-definition behavior are consensus-replay relevant. Do not cache `InstancePre`, `Store`, or `Instance`; prior investigations found those are not reusable for this workload.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; adjacent failures cover reusable `InstancePre` and protocol import-table checks, not per-module minimal public-API linkers
**Failed At**: reviewer

### Trace Summary

The cache-hit path does exactly what the hypothesis says: C++ invoke-host-function calls pass the shared Soroban module cache into the p26 host, `Host::instantiate_vm` gets a cached `ParsedModule`, and VM construction passes the cache's maximal `wasmi::Linker<Host>` into `Vm::instantiate_wasmi`. However, wasmi's `Linker::instantiate` does not walk all linker definitions; it iterates only `module.imports()` and, for each import, performs string-interner lookups and one `BTreeMap` lookup into the linker definitions. A minimal linker would therefore only shrink the logarithmic lookup trees and interned-string tables; it would not remove fresh `Store` creation, fresh host `Func` allocation into that store, type checks, import extraction, memory/table/global allocation, data/element initialization, or the other one-instance-per-call work.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — apply invokes Rust with `*mModuleCache` for each Soroban host-function execution.
- `src/rust/src/soroban_proto_all.rs:95-129` — p26 wrapper passes `Some(module_cache.p26_cache.module_cache.clone())` to `e2e_invoke`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — constructs the `Host`, installs the cloned `ModuleCache`, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148,1186-1194` — `HostFunction::InvokeContract` enters the contract-call path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-776` — Wasm contract calls instantiate a VM before pushing the `ContractVM` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — module-cache hits use `cache.get_module(wasm_hash)` and instantiate with `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,160-183` — `ModuleCache` owns one maximal linker and cached `Arc<ParsedModule>` values; parsed modules do not store per-module linkers.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269,403-452` — imported symbols can be recomputed from `wasmi_module.imports()` and are also used by the separate protocol-gating check.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129,154-187,191-217` — maximal and minimal linkers are built from `HOST_FUNCTIONS`; instantiation creates a new store, charges instantiation, checks protocol-gated imports, calls `wasmi_linker.instantiate`, rejects start functions, and looks up memory.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:433-444,619-658,670-701` — wasmi stores linker definitions in a `BTreeMap` and instantiates by iterating module imports, resolving each import by name, type-checking it, and allocating a store-local host `Func`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78,94-158,167-247` — module instantiation still extracts imports into an instance builder and allocates functions, tables, memories, and globals regardless of linker size.
- `ai-summary/fail/soroban/summary.md:29-32,63` — prior Soroban failures reject Store/InstancePre reuse and the separate per-instantiation protocol import check, but do not duplicate this minimal-linker mechanism.

### Why It Failed

The proposed inefficiency is real only in a narrow sense: a maximal linker makes each imported-symbol lookup search a larger `BTreeMap` and string interner than a per-module minimal linker would. It is not a linear walk over all 192 host functions during `Linker::instantiate`, and it does not eliminate the dominant per-invocation work that must remain store-local and instance-local.

The impact ceiling is below the optimize-soroswap review threshold. The hypothesis cites about 0.986 s aggregate `Vm::instantiate_wasmi - instantiate` time across the trace. Because these events occur inside the 8-way parallel Soroban apply workers, even deleting the entire instantiate zone would be roughly `0.986s / 8 / 70 ~= 1.8ms` per ledger, about 2.4% of the cited ~73 ms apply window. A minimal linker can only remove a small fraction of that zone: the extra comparisons from a 192-entry `BTreeMap` versus a per-contract imported-function set, while all import iteration, type checking, store-local host-function allocation, and module instantiation remain. This is therefore below the objective's Medium floor, and Low-severity findings are not accepted for this review stage.

### Lesson Learned

Do not attribute broad `Vm::instantiate_wasmi` Tracy time to linker-definition count without reading wasmi's instantiation path. In the pinned wasmi version, public `Linker::instantiate` already iterates only the module's imports; changing maximal to minimal linkers only shrinks lookup data structures and is structurally too small to clear the optimize-soroswap Medium threshold.
