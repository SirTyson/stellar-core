# H002: Cache per-module minimal Wasmi linkers for module-cache hits

**Date**: 2026-05-21
**Subsystem**: ledger / Soroban host apply
**Severity**: Medium
**Impact**: 3-7% soroswap apply-time reduction if excess maximal-linker import resolution is a significant part of Wasmi instantiation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a cached Soroban contract module is instantiated during apply, Wasmi should resolve only the host imports that the module actually declares. Module-cache hits should avoid parsing or compiling Wasm, and should also avoid repeatedly linking against a maximal linker containing every possible host function when the parsed module already exposes its exact import set.

## Mechanism

`ModuleCache::new` currently builds one maximal `wasmi::Linker<Host>` containing all `HOST_FUNCTIONS`, and every cache hit passes that maximal linker into `Vm::from_parsed_module_and_wasmi_linker`. However `ParsedModule` already has `with_import_symbols` and `make_wasmi_linker`, which construct a minimal linker from the module's actual imports for cache-miss/isolated-engine paths. Extending `ModuleCache` to cache `(Arc<ParsedModule>, wasmi::Linker<Host>)` or an equivalent per-module minimal linker would move the import-set walk and linker construction to module-cache population and make the hot cache-hit instantiate path resolve only the imports present in the contract.

## Trigger

Run the soroswap apply-load benchmark where each successful swap repeatedly invokes the same router/pair Wasm modules from the module cache. The trigger is any module-cache hit in `Host::instantiate_vm` for a Wasm contract under `applyThread` / `parallelApply`; the current trace shows roughly three Wasmi instantiations per top-level host function invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:21-24` — `ModuleCache` stores a single shared maximal `wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:86-95` — `ModuleCache::new` calls `Host::make_maximal_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:185-195` — `ModuleCache::get_module` returns only `Arc<ParsedModule>`, so callers cannot use a cached minimal linker.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `Host::instantiate_vm` cache-hit path calls `Vm::from_parsed_module_and_wasmi_linker` with `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — existing helper functions build minimal and maximal linkers; the minimal helper is already available.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-268` — `ParsedModule::with_import_symbols` and `make_wasmi_linker` derive a minimal linker from module imports.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` performs the hot `wasmi_linker.instantiate` call.

## Evidence

Current Tracy trace:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.

- `applyLedger` total: 5,230,315,999 ns across 71 ledgers.
- `applySorobanStageClustersInParallel` is called from `LedgerManagerImpl::applySorobanStage` and is inside the measured apply path.
- `Vm::instantiate_wasmi - instantiate` (`soroban-env-host/src/vm.rs:171`): 1,315,387,452 ns self across 20,389 calls.
- `Vm::instantiate_wasmi` (`soroban-env-host/src/vm.rs:160`): 79,587,805 ns additional self across 20,389 calls.
- `invoke_host_function` count is 6,776, so cached Wasm modules are instantiated about three times per top-level host invocation.

The instantiate child zone alone is about 1.315 s aggregate worker self-time. Normalized by the observed ~3.67x worker overlap, eliminating 40-60% of linker-resolution work would save about 143-215 ms, or 2.7-4.1% of the `applyLedger` envelope; stronger wins are possible if maximal-linker import resolution dominates more of `wasmi_linker.instantiate`. This does not reuse Wasmi instances or stores, so it avoids the determinism and mutable-linear-memory problems that block pristine-instance reuse.

## Anti-Evidence

Wasmi may already index linker definitions efficiently enough that extra definitions in the maximal linker are a small fraction of `Linker::instantiate`; if so, this will fall below Medium. The prior clean-instantiation-cache angle failed because `InstancePre`/instances are not reusable across stores; this hypothesis deliberately does not depend on reusing instances, but it still needs a PoC to confirm that storing per-module linkers is `Send + Sync` compatible with the existing module cache and does not increase module-cache mutex contention or cache-population cost enough to offset apply-time savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to prior Wasmi instantiation and import-protocol-check failures, but not previously investigated as per-module minimal linker caching
**Failed At**: reviewer

### Trace Summary

The in-scope apply path reaches cached Wasm instantiation through `LedgerManagerImpl::applyLedger` -> `applyTransactions` -> `applySorobanStages` -> `applyThread` -> `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> `rust_bridge::invoke_host_function` -> p26 `e2e_invoke::invoke_host_function` -> `Host::call_contract_fn` -> `Host::instantiate_vm`. The cache-hit branch does exactly what the hypothesis says: it checks storage, loads only `Arc<ParsedModule>` from `ModuleCache`, and passes the shared maximal `cache.wasmi_linker` into `Vm::from_parsed_module_and_wasmi_linker`. However, Wasmi's `Linker::instantiate` implementation does not scan all linker definitions; it iterates only `module.imports()` and resolves each import by key lookup in a `BTreeMap`.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1457-1688` — `applyLedger` runs fee processing and then calls `applyTransactions` inside the close-ledger apply path.
- `src/ledger/LedgerManagerImpl.cpp:2483-2518` — `applyThread` calls `txBundle.getTx()->parallelApply` once per Soroban transaction in each cluster.
- `src/ledger/LedgerManagerImpl.cpp:2622-2709` — `applySorobanStage`/`applySorobanStages` run worker clusters inside the measured `applyLedger` descendant.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ invokes `rust_bridge::invoke_host_function` with the shared `SorobanModuleCache`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-448` — bridge dispatch creates the per-invocation budget and calls the selected protocol host with the module cache.
- `src/rust/src/soroban_proto_all.rs:95-125` — p26 dispatch passes `Some(module_cache.p26_cache.module_cache.clone())` into `e2e_invoke::invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-470` — p26 host invocation builds storage and host state, then executes the host function that can call Wasm contracts.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — `call_contract_fn` reaches `instantiate_vm`; on module-cache hit, `instantiate_vm` uses `cache.get_module` and the shared maximal `cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:21-24,85-95,160-195` — `ModuleCache` stores one maximal linker and a map from hash to `Arc<ParsedModule>`; cache population stores only parsed modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129,154-206` — minimal and maximal linker constructors exist, and instantiation calls `parsed_module.check_contract_imports_match_host_protocol` followed by `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-268,403-454` — import-symbol extraction can build a minimal linker, but protocol validation still rebuilds the import-symbol set on every instantiation.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:433-444,646-658,670-701` — Wasmi `Linker` stores definitions in `BTreeMap`; `instantiate` maps over `module.imports()` and each `process_import` performs keyed lookup and type checking.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78` — after import resolution, module instantiation allocates and initializes the instance, functions, tables, memories, globals, exports, table elements, and memory data.

### Why It Failed

The central Medium projection depends on a maximal linker making every cache-hit instantiation resolve against all host functions. The actual Wasmi path is already per-module-import: extra definitions in the maximal linker only make each keyed lookup occur in a larger `BTreeMap` and string interner, changing a logarithmic lookup constant rather than eliminating a full scan or moving a large import-set walk out of the hot path. Caching a minimal linker would be mechanically plausible and might save a small amount of lookup work, but it would not remove the dominant `Linker::instantiate` work, nor would it remove the separate per-instantiation `ParsedModule::check_contract_imports_match_host_protocol` import-symbol walk already rejected as below Medium. Under the optimize-soroswap objective, the remaining likely saving is below the 3% Medium threshold, so this is not viable for the pipeline.

### Lesson Learned

Do not treat the whole `Vm::instantiate_wasmi - instantiate` Tracy zone as linker-definition-resolution overhead. In this Wasmi version, linker resolution is keyed by the module's actual imports, and the broader zone also includes instance allocation, import type checks, export extraction, table/memory/global setup, and data/element initialization; minimal-linker caching only attacks a small lookup-size constant.
