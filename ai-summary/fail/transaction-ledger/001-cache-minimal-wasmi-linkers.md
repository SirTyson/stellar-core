# H001: Cache per-module minimal wasmi linkers and import-compatibility checks

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban VM instantiation
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by cutting repeated per-Wasm-call import resolution and protocol-gating work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a contract module is already in the inter-ledger `ModuleCache`, every invocation should still instantiate a fresh wasmi `Store`/`Instance` for isolation, but it should not repeatedly re-derive the module's imported host-function symbol set or instantiate through a linker containing every possible host function. The efficient cache-hit path should reuse module-specific import metadata and a minimal linker built for exactly the imported symbols, while preserving the same import/protocol validation errors and the same per-invocation `VmCachedInstantiation` / refined instantiation budget charges.

## Mechanism

`ModuleCache::new` constructs one maximal linker by wrapping all `HOST_FUNCTIONS`, and cache-hit execution in `Host::instantiate_vm` passes that maximal linker to `Vm::from_parsed_module_and_wasmi_linker`. `Vm::instantiate_wasmi` then charges instantiation, calls `ParsedModule::check_contract_imports_match_host_protocol`, and invokes `wasmi_linker.instantiate`. `check_contract_imports_match_host_protocol` rebuilds a `BTreeSet` of imports from `wasmi_module.imports()` on every instantiation via `with_import_symbols`, then scans all `HOST_FUNCTIONS` for min/max protocol gates.

For soroswap, the same router/pool modules are invoked thousands of times from the cache during parallel apply. The current trace's longest `applyLedger` window shows `Vm::instantiate_wasmi - instantiate` at **300.240 ms worker time** over 4,569 calls, with the critical worker spending **58.311 ms**, and `ParsedModule::check_contract_imports_match_host_protocol` at **52.882 ms worker time** / **10.483 ms critical-worker time**. Caching a per-`ParsedModule` minimal linker plus a precomputed import-compatibility representation keyed by module protocol would remove the repeated symbol-set construction and may reduce wasmi's import-resolution work during `instantiate` without attempting to cache the non-reusable `InstancePre`.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=4000, T=8`) using the trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. In the longest `applyLedger` interval (`ledger/LedgerManagerImpl.cpp:1484`, 1,711.471 ms), filter `Vm::instantiate_wasmi - instantiate` and `ParsedModule::check_contract_imports_match_host_protocol`. The triggering condition is a cache-hit module that is instantiated repeatedly in one ledger and imports only a small subset of the maximal host-function table.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-96` — `ModuleCache::new` builds a single maximal linker today.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` — `parse_and_cache_module` creates `ParsedModule` entries; this is the natural point to compute module-specific import metadata and minimal linker state once.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:189-195` — cache-hit lookup returns only `Arc<ParsedModule>` today.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit `instantiate_vm` checks module presence then calls `Vm::from_parsed_module_and_wasmi_linker` with `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` charges and instantiates with the provided linker, then extracts memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269` — `with_import_symbols` and `make_wasmi_linker` already provide the per-module symbol path, but it is rebuilt on demand rather than cached for normal cache hits.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — `check_contract_imports_match_host_protocol` rebuilds/import-scans on every instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — minimal and maximal linker builders show the difference between wrapping only imported functions and wrapping all host functions.

## Evidence

- Tracy scope check: both cited zones are inside the longest `applyLedger` window and underneath `applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply -> invoke_host_function`, so they are measured close-ledger apply work, not TX-set construction.
- The source performs repeated import-symbol work per invocation: `instantiate_wasmi` calls `check_contract_imports_match_host_protocol`, which calls `with_import_symbols`, which builds a new `BTreeSet` from `wasmi_module.imports()` and charges a vector initialization every time.
- The source already has a minimal-linker constructor for a module's imported symbols, but normal inter-ledger cache hits use the cache-wide maximal linker. If wasmi's `Linker::instantiate` consults the linker definition table during import resolution, shrinking that table to the module's actual imports should reduce the hot `Vm::instantiate_wasmi - instantiate` span.
- This is not the rejected `InstancePre` caching idea. It still creates a fresh `Store` and `Instance` per call, avoiding store-bound/single-use `InstancePre` reuse, and only caches immutable linker/import metadata tied to the parsed module and engine.
- The critical-worker bound is large enough for Medium severity if a minimal linker plus cached import validation removes a meaningful fraction of the **58.311 ms** instantiation tail and **10.483 ms** import-check tail in the representative long apply interval.

## Anti-Evidence

- The wasmi `instantiate` span may be dominated by module-defined memory/table/global initialization rather than linker lookup. If so, a minimal linker will reduce only the 52.882 ms import-check worker total and a small fraction of the 300.240 ms instantiate total, likely below Medium.
- `wasmi::Linker<Host>` must be safe to store alongside cached modules and share across the same engine/threading pattern as the current cache-wide linker. If the linker is not cheaply cloneable/shareable, the design may need a compact imported-function descriptor rather than cached linker objects.
- Protocol compatibility depends on both module interface protocol and current ledger protocol. A cached pass/fail result must be keyed or structured so replay under older ledgers still returns the same errors described in `check_contract_imports_match_host_protocol`.
- The existing maximal linker is simple and built once per module cache; replacing it with per-module minimal linkers increases cache memory and construction work during module-cache setup. The PoC must show the apply-time win exceeds setup/cache-size costs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban path invokes `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge, installs the shared `ModuleCache` on a fresh host, and calls the contract. On a cache hit, `Host::instantiate_vm` does use `cache.wasmi_linker`, and `Vm::instantiate_wasmi` rebuilds the imported-symbol set and scans the host-function table before every `wasmi_linker.instantiate`. However, wasmi's `Linker::instantiate` already iterates only the module's actual imports and performs keyed lookups into the linker; it does not scan all maximal-linker definitions. Therefore the confirmed removable work is mostly the 10.483 ms critical-worker import-compatibility check, while the 58.311 ms `instantiate` tail is dominated by per-import function allocation/type checks and module instantiation work that a minimal linker would not remove.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` calls `rust_bridge::invoke_host_function` with the module cache during apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — sequential Soroban apply performs footprint loading, host invocation, storage-change recording, event collection, and refund accounting.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — parallel Soroban apply enters the same invocation helper inside `InvokeHostFunctionOpFrame doParallelApply`.
- `src/rust/src/soroban_proto_any.rs:391-448` — the bridge builds the per-invocation budget and passes the shared module cache into `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — each invocation constructs a fresh host, installs the provided `ModuleCache`, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls instantiate a VM; cache hits verify storage presence, fetch `Arc<ParsedModule>`, and instantiate using `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-900` — recording/miss paths build isolated parsed modules and minimal linkers, but normal inter-ledger cache hits do not.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-96` — `ModuleCache::new` builds one maximal linker over all host functions.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-195` — cached entries contain only `Arc<ParsedModule>`, so no per-module linker or precomputed import-gate state is stored.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — minimal and maximal linker builders differ only in which `HOST_FUNCTIONS` entries are wrapped.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — VM instantiation creates a fresh store, charges instantiation, runs the protocol import check, invokes the linker, ensures no start function, and extracts memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:246-257` — isolated non-cache construction already uses `ParsedModule::make_wasmi_linker`, confirming the minimal-linker path exists but is not the hot cache-hit path.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269` — `with_import_symbols` rebuilds a `BTreeSet` from `wasmi_module.imports()` and `make_wasmi_linker` uses that set to build a minimal linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — `check_contract_imports_match_host_protocol` calls `with_import_symbols` and scans `HOST_FUNCTIONS` for min/max protocol gates on every instantiation.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:619-633` — linker lookup interns the requested import strings and performs a `BTreeMap` lookup; table size affects only lookup depth.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:646-658` — `Linker::instantiate` maps over `module.imports()`, not over all linker definitions.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:670-701` — each actual import still performs definition lookup, type validation, and `as_func`.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:326-370` — `Definition::as_func` allocates a fresh store-local `Func` for linker-defined host functions; a minimal linker does not avoid this per-actual-import cost.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/mod.rs:49-78` — after import resolution, wasmi still allocates/extracts functions, tables, memories, globals, exports, and initializes elements/data.

### Why It Failed

The inefficiency is real and hot, but the proposed optimization cannot plausibly meet the optimize-soroswap Medium threshold. The objective requires at least a 3% apply-time reduction, which is about 51.3 ms in the cited 1,711.471 ms `applyLedger` interval. Caching the import-compatibility result can recover the measured 10.483 ms critical-worker check, only about 0.61% of apply time. The soroswap Wasm files import only 20-28 host functions versus 192 total host functions, but wasmi already processes only those actual imports during `Linker::instantiate`; reducing the linker's `BTreeMap` from 192 definitions to ~20-28 definitions only reduces lookup depth by a few integer/string-intern comparisons per actual import. It does not remove the per-import store-local `Func` allocation or module instantiation work, so it cannot recover the bulk of the 58.311 ms instantiate span needed to cross 3%.

### Lesson Learned

Do not treat maximal linker size as equivalent to per-instantiation work: in this wasmi version, the linker is queried by the module's actual import list rather than scanned. A viable VM-instantiation optimization needs to attack store-local import materialization or the module instantiation/allocation path itself, not just cache minimal linkers and import-gate metadata.
