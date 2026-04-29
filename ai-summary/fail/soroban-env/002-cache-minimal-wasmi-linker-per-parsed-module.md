# H002: Cache per-module minimal wasmi linkers for cached contract instantiation

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated wasmi linker work during cached VM instantiation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Cached contract execution should instantiate a VM using import definitions for exactly the host functions imported by that contract module. It should preserve all protocol-gating checks and instantiation budget charges, but it should not make every cached module instantiate against a maximal linker containing all host functions when the module's import set is immutable and much smaller than the full `HOST_FUNCTIONS` table.

## Mechanism

`ModuleCache::new` builds one maximal `wasmi::Linker<Host>` containing every host function, and the cache-hit path in `Host::instantiate_vm` passes that linker to `Vm::from_parsed_module_and_wasmi_linker` on every invocation. The `ParsedModule` already exposes `make_wasmi_linker`, which can build a minimal linker from the module's own import symbols, but the cached path does not retain or reuse such a per-module linker. Storing a prebuilt minimal linker alongside each cached `ParsedModule` would keep the immutable module/linker data reusable while reducing the per-instantiation work inside `wasmi_linker.instantiate`.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md` and inspect VM-instantiation zones. The reference trace reports `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` with 676.355 ms self-time over 10,061 calls; an unwrap timestamp check showed all 10,061 events and 678.102 ms total execution time fall inside `applyLedger` windows. The cache-hit path at `host/frame.rs:789-801` is used for these repeated contract invocations and always passes `&cache.wasmi_linker`, the maximal linker built at module-cache construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:20-25` — `ModuleCache` currently stores one shared maximal `wasmi_linker` plus a map of `Arc<ParsedModule>`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-96` — `ModuleCache::new` builds the maximal linker by wrapping every `HOST_FUNCTIONS` entry.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` — `parse_and_cache_module` parses a module but stores only the `ParsedModule`; this is the natural point to build and store a per-module minimal linker.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit `instantiate_vm` retrieves the parsed module and instantiates it with the maximal cache linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269` — `with_import_symbols` and `make_wasmi_linker` already know how to construct a minimal linker from a module's import set.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` — `Vm::instantiate_wasmi` spends the hot `wasmi_linker.instantiate` time using the supplied linker.

## Evidence

- Tracy scope check: all `Vm::instantiate_wasmi - instantiate` events occur inside `applyLedger`, so the target is in the measured close-ledger apply path and not TX-set construction.
- The source shows two linker modes already exist: a maximal linker for the long-lived module cache, and a minimal linker for throwaway/cache-miss modules via `ParsedModule::make_wasmi_linker`. The cached execution path chooses maximal linker reuse over per-module minimality even though the module import set is immutable after parsing.
- The target zone is large enough to justify PoC work. `wasmi_linker.instantiate` alone accounts for ~676 ms self-time in the traced apply windows; a per-module linker that trims definition lookup/validation work by even 25-30% would plausibly clear the 3% Medium floor.
- This is distinct from the failed `InstancePre` hypothesis. It does not try to reuse store-local `InstancePre`, `Instance`, `Func`, memory, globals, or any mutable per-invocation state. It only reuses immutable linker definitions built against the same shared `wasmi::Engine` and static host-function wrappers.

## Anti-Evidence

- `wasmi::Linker::instantiate` may already perform near-O(number-of-module-imports) lookup into the maximal linker, in which case trimming extra definitions will not materially reduce the 676 ms zone. The PoC must compare maximal vs minimal linker instantiation in non-Tracy apply-load runs or a targeted wasmi microbenchmark.
- Any per-module linker stored in `ModuleCache` must be `Send + Sync` compatible with the existing shared module cache. If `wasmi::Linker<Host>` cannot be safely shared across worker threads in this form, the design may need `Arc` wrapping or per-worker clones, which could reduce the benefit.
- Protocol gating must remain identical. `check_contract_imports_match_host_protocol` still has to reject imports outside the current ledger protocol; storing a minimal linker cannot replace that check unless the cached linker/result is keyed by ledger protocol and preserves current error behavior.
- Building a minimal linker per module increases module-cache memory and compile-time work. This is acceptable only if the apply-time win on repeated soroswap invocations outweighs the cache construction cost and memory growth.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to the failed `InstancePre` cache hypothesis, but not a duplicate; no fail/success record covers caching per-module minimal `wasmi::Linker` definitions
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the Rust bridge, installs the protocol-specific `ModuleCache`, then `Host::instantiate_vm` takes the cache-hit path and calls `Vm::from_parsed_module_and_wasmi_linker` with the cache-wide maximal linker. The source-level inefficiency is real: p26 has 192 host-function definitions in `HOST_FUNCTIONS`, `ModuleCache::new` wraps all of them into one linker, while `ParsedModule::make_wasmi_linker` can build a linker containing only the module's imported functions. However, `soroban-wasmi::Linker::instantiate` does not iterate over all definitions in the linker; it iterates the module's imports and performs keyed BTreeMap lookups, then allocates per-store host `Func` handles and calls `Module::instantiate`. A minimal cached linker would only shrink the BTreeMap/string-interner lookup depth for each imported symbol, leaving the number of imports, host-function allocations, type checks, protocol-gating pass, store creation, and module instantiation work unchanged.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1495` — `applyLedger` is the measured close-ledger apply entry point.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — Soroban operation application calls `rust_bridge::invoke_host_function` with the shared module cache.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge wrapper constructs the budget and calls protocol-specific host invocation with the provided `SorobanModuleCache`.
- `src/rust/src/soroban_proto_any.rs:701-776` — `ProtocolSpecificModuleCache` owns the p26 `ModuleCache`; shallow clones share the same underlying cache across C++ worker threads.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:20-25,85-96` — `ModuleCache` stores one `wasmi_engine`, one maximal `wasmi_linker`, and a map of cached `Arc<ParsedModule>`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` — `parse_and_cache_module` parses and stores only the `ParsedModule`, so no per-module linker is retained.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit VM instantiation checks storage liveness, retrieves the cached module, and passes `&cache.wasmi_linker` to VM construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:839-900` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:246-256` — recording/cache-miss paths already build a throwaway minimal linker from the parsed module's imports.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — maximal linker wraps every host function; minimal linker iterates the same `HOST_FUNCTIONS` table but only inserts symbols present in the module import set.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269,403-454` — import symbols are derived from `wasmi_module.imports()`; protocol gating still rebuilds that import-symbol set and scans `HOST_FUNCTIONS` on every instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh store, charges cached-instantiation budget, checks protocol-gated imports, and calls `wasmi_linker.instantiate`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/crates/wasmi/src/linker.rs:432-445,646-658,670-701` — the linker stores definitions in a `BTreeMap`; `instantiate` maps over `module.imports()` and `process_import` resolves each import by name, type-checks it, and allocates a per-store host `Func`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/crates/wasmi/src/module/instantiate/mod.rs:49-78,94-159` — `Module::instantiate` consumes the resolved external list and performs the real instance allocation/import extraction/function/table/memory/global/export/data initialization work.
- `ai-summary/fail/soroban-env/summary.md:9-18,22-33` and `ai-summary/fail/soroban-env/011-eliminate-is-clean-fuel-check.md:100-124` — prior failures do not duplicate this hypothesis and reinforce that broad Tracy self-time zones must be reduced to the actually removable production work.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:44-53,88-97` — the accepted broader storage-map fast path measured only Low severity, illustrating the objective's 3% Medium floor.

### Why It Failed

The proposed optimization is correct in principle but below this objective's accepted severity threshold. A per-module minimal linker would not reduce the 10,061 store creations, cached-instantiation budget charges, protocol-gating import scans, module import count, host `Func` allocations, type checks, or `Module::instantiate` allocation/initialization work. The only direct saving inside `Linker::instantiate` is that `get_definition` searches smaller `StringInterner` and definition `BTreeMap`s: from a cache-wide linker containing 192 host functions to a linker containing just that module's imported symbols.

That is much smaller than the cited 676 ms Tracy zone. Wasmi already does near-O(number-of-module-imports) work; extra maximal-linker entries only add a few BTreeMap comparison steps per imported symbol. Even if every one of the ~10k instantiations imports many host functions, the removable lookup-depth delta is micro-optimization-scale compared with the remaining per-import `Definition::as_func` store allocations and the subsequent module instantiation work. The hypothesis therefore cannot credibly project a reproducible 3-10% soroswap apply-time reduction, so it is rejected as below the optimize-soroswap Medium threshold.

### Lesson Learned

For wasmi linker hypotheses, distinguish "definitions stored in the linker" from "imports resolved during instantiation." The p26 maximal linker contains all host functions, but `Linker::instantiate` resolves only the module's declared imports by keyed lookup; trimming the definition set can reduce lookup depth but does not remove per-import host-function allocation, type checking, protocol-gating, or module instantiation costs.
