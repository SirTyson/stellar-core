# H001: Reuse Wasmi Instances Across Soroswap Contract Calls

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: VM instantiation overhead in soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Wasm contract call should execute with the same isolation semantics as today: no mutable Wasm memory, globals, store state, relative-object table state, or host frame state should leak from a previous call into a later call. Successful soroswap swaps should instantiate and execute contracts deterministically with identical results and metering.

## Mechanism

The tempting optimization is to cache already-instantiated `Vm` or wasmi instance state for repeated soroswap calls, because `Vm::instantiate_wasmi - instantiate` is visible in the current apply trace. Reusing an instantiated VM would deviate from the expected behavior if mutable Wasm state survived across invocations, changing contract isolation and potentially ledger-visible behavior.

## Trigger

Run soroswap apply-load with repeated calls to the same router/pair contracts. The repeated calls trigger `Host::instantiate_vm` and `Vm::from_parsed_module_and_wasmi_linker` for cached parsed modules.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-901` — `instantiate_vm` loads a parsed module from `ModuleCache` but still creates a fresh `Vm` for each contract call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh store and instance.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` explicitly caches parsed modules, not instantiated VMs.

## Evidence

The current soroswap Tracy trace shows `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` with 676,355,499 ns self time across 10,061 calls, all on the host-invocation path. `host/frame.rs` shows cache hits return `Vm::from_parsed_module_and_wasmi_linker`, which still calls `instantiate_wasmi`.

## Anti-Evidence

`Vm` owns a `wasmi::Store<Host>`, `wasmi::Instance`, optional memory export, and execution state. Reusing this object across independent contract calls would risk preserving Wasm memory/globals and host object indirections across frames. The current `ModuleCache` design comment states it caches modules that are "parsed but not yet instantiated", and the VM construction code deliberately creates a fresh store per `Vm`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in this worktree's soroban fail/hypothesis/reviewed/poc directories

### Why It Failed

Caching and reusing fully instantiated VMs would violate the fresh-instance isolation that Soroban relies on for deterministic contract execution. The safe cache boundary in the current design is the parsed module and linker, not the mutable store/instance.

### Lesson Learned

VM-instantiation optimizations must target safe pre-instantiation artifacts or wasmi APIs that preserve fresh store/instance semantics. Do not propose reusable `Vm` objects for the apply path unless the design explicitly resets all Wasm and host-frame state.
