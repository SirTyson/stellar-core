# H002: Cache Minimal Wasmi Linkers Per Parsed Module

**Date**: 2026-05-04
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated cached-contract Wasm instantiation work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Cached Wasm contract invocations during soroswap apply should instantiate contracts with the same accepted imports, protocol checks, store limiter, instantiation-cost charging, and fresh per-invocation store/memory semantics as today. The module cache should remain deterministic across worker threads: every node should use the same parsed module and linker definitions for a given contract code hash, and no mutable Wasm instance, store, memory, globals, or fuel state should be reused across transactions.

## Mechanism

The inter-ledger `ModuleCache` stores each `ParsedModule`, but it stores a single maximal `wasmi::Linker<Host>` containing every host function and passes that maximal linker into every cached instantiation. `ParsedModule::make_wasmi_linker` already knows how to construct a minimal linker from the module's actual import set, but the cached fast path does not retain or use such per-module linkers. Storing a deterministic minimal linker alongside each cached `ParsedModule` should reduce repeated import-resolution work inside `wasmi_linker.instantiate` without relying on unsafe `InstancePre`, `Store`, or `Instance` reuse.

## Trigger

Run the current soroswap apply-load benchmark with the accepted module cache enabled. Each soroswap ledger repeatedly invokes the same small set of router/pool Wasm contracts; the current trace shows 20,389 cached `Vm::instantiate_wasmi` calls inside `applyLedger`, each using the shared maximal linker on the cache-hit path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` stores a shared `wasmi_engine`, one maximal `wasmi_linker`, and a map from code hash to `Arc<ParsedModule>`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-96` — cache construction builds the maximal linker for all host functions.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-195` — `parse_and_cache_module` and `get_module` cache and retrieve only `ParsedModule`, not a module-specific linker.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-803` — cached VM instantiation looks up the parsed module and passes `&cache.wasmi_linker` into `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:265-269` — `ParsedModule::make_wasmi_linker` builds a minimal linker from the module's import symbols.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` charges instantiation, checks imports, and calls `wasmi_linker.instantiate`.

## Evidence

The current accepted soroswap Tracy trace has `applyLedger` total time of 5,230,315,999 ns; a 3% Medium win is 156,909,480 ns. Timestamp-filtered apply descendants show `Vm::instantiate` at 1,655,685,114 ns, `Vm::instantiate_wasmi` at 1,648,211,481 ns, and the nested `Vm::instantiate_wasmi - instantiate` region at 1,317,542,205 ns across 20,389 calls. Dividing the worker aggregate by T=8 leaves about 206,026,435 ns for `Vm::instantiate_wasmi` and 164,692,776 ns for the `instantiate` subzone, enough to clear the Medium threshold if most linker-resolution overhead is removed.

This hypothesis differs from rejected `InstancePre` caching: it does not cache any per-store or single-use instantiation artifact. It also differs from caching the import-protocol check alone: the target is the linker used by `wasmi_linker.instantiate`, while the existing `ParsedModule::make_wasmi_linker` minimal-linker path demonstrates that module-specific linker construction is already supported for uncached/one-off instantiation.

## Anti-Evidence

Wasmi instantiation also allocates fresh instance state and may spend most of the subzone outside linker import resolution, so a minimal linker may not recover enough of the 164-206 ms critical-path bound. The implementation must also avoid adding per-invocation mutex contention or expensive linker clones that offset the win. A PoC should measure the `Vm::instantiate_wasmi - instantiate` subzone directly and verify that fresh store/memory/fuel semantics remain unchanged.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The cached Soroban VM path does exactly what the hypothesis describes: `Host::instantiate_vm` retrieves an `Arc<ParsedModule>` from `ModuleCache` and instantiates it with the cache-wide maximal linker. The one-off fallback path builds a module-specific minimal linker from the parsed module's import symbols, and the linker itself does not carry per-transaction `Store`, `Instance`, memory, globals, or fuel state, so the proposed artifact is plausibly safe to cache. However, the measurable target is too narrow for this objective: the entire nested `wasmi_linker.instantiate` subzone is only about 164.7 ms of critical-path time against a 156.9 ms Medium floor, and changing linker cardinality can only affect import-definition resolution, not the required fresh instance allocation/setup work inside that same subzone.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:21-24,85-95` — `ModuleCache` owns one shared `wasmi::Engine`, one cache-wide maximal `wasmi::Linker<Host>`, and the cached module map.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-195` — cache population parses and stores only `Arc<ParsedModule>` values keyed by contract hash; cache hits return only the parsed module.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-803` — cached contract execution first confirms the contract code exists in storage, then calls `Vm::from_parsed_module_and_wasmi_linker` with `&cache.wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:839-900` — recording-mode and cache-miss fallbacks build throwaway parsed modules and minimal linkers, then instantiate fresh VMs.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-269` — `with_import_symbols` enumerates the module's function imports and `make_wasmi_linker` builds a linker restricted to those symbols.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-128` — minimal and maximal linker construction both wrap host functions into a `wasmi::Linker<Host>`; the maximal constructor adds every host function.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,191-217` — every VM instantiation still creates a fresh `wasmi::Store<Host>`, charges instantiation, installs the store limiter, checks host import protocol compatibility, calls `wasmi_linker.instantiate`, runs `ensure_no_start`, extracts memory, and stores the resulting fresh `Instance`/`Store` in a new `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — protocol compatibility scanning of module imports is separate from linker selection and would remain on the hot path unless addressed by a different optimization.
- `src/rust/src/soroban_proto_any.rs:713-737` — protocol-specific cache compilation uses a throwaway `CoreCompilationContext` and calls `parse_and_cache_module_simple`, so a cached per-module linker would be created at compile/cache-population time rather than per transaction.
- `src/rust/src/soroban_module_cache.rs:22-60` — C++ sees a multi-protocol `SorobanModuleCache`; each protocol cache is shallow-cloned for shared ownership across threads.

### Why It Failed

This is a real but sub-threshold optimization. The hypothesis's own trace math leaves only about 7.8 ms of headroom between the entire nested `Vm::instantiate_wasmi - instantiate` critical-path bound and the 3% Medium floor. A minimal linker cannot remove nearly all of that subzone: `wasmi_linker.instantiate` must still create and initialize a fresh instance for a fresh store, resolve the module's actual imports, set up memory/globals/tables/data/exports, and return a not-started instance for `ensure_no_start`. At best, the change reduces the cost of looking up imported host functions in a smaller linker definition set, while leaving the mandatory fresh instantiation work, store construction, metered instantiation charges, store limiter setup, memory extraction, and separate import-protocol scan intact. Under the objective-specific rule, Low-tier or below-threshold findings must be rejected rather than downgraded and promoted.

### Lesson Learned

For VM-instantiation hypotheses, the measured `instantiate` zone is an upper bound on all safe linker improvements, not the amount recoverable by a linker-cardinality change. Because safe optimizations cannot reuse `Store`, `Instance`, memory, globals, fuel, or `InstancePre`, reviewer-stage projections need isolated evidence that the specific removable subcomponent exceeds the 3% apply-time floor; otherwise broad `Vm::instantiate_wasmi` totals overstate viability.
