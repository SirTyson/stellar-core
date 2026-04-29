# H008: Cache or Avoid Repeated Wasmi VM Instantiation

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated soroswap calls to cached Wasm modules should still instantiate isolated VM stores, memory, globals, and fuel state for each contract execution, enforce host import compatibility, charge the same VM-instantiation budget, and return the same traps and outputs.

## Mechanism

The current module cache stores parsed Wasm modules and a shared wasmi linker, but every call still goes through `Vm::from_parsed_module_and_wasmi_linker` and `Vm::instantiate_wasmi`. It is tempting to cache a stronger instantiation artifact or avoid repeated import/link work for the same module and protocol.

## Trigger

Run the current soroswap diagnostic trace and timestamp-filter VM instantiation zones into `applyLedger`. The trace shows `Vm::instantiate` at `soroban-env-host/src/vm.rs:197` with 847.419524 ms across 10,061 calls, `Vm::instantiate_wasmi` at `vm.rs:160` with 843.710962 ms, and `Vm::instantiate_wasmi - instantiate` at `vm.rs:171` with 678.102145 ms.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-803` — cache hit still instantiates a fresh `Vm` from a cached `ParsedModule`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh store, charges instantiation, checks imports, and invokes the linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-195` — module cache stores parsed modules and the linker, not reusable instances.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:81-120` — instantiation budget charges are protocol-visible.

## Evidence

The VM instantiation path is in the measured apply subtree and runs about three times per soroswap transaction in the current trace. The module cache already avoids reparsing, leaving linker/store/instance creation as repeated physical work.

## Anti-Evidence

This does not clear the objective threshold as a standalone transactions hypothesis. The previously recorded Wasmi `InstancePre` finding blocks the obvious stronger cache: `InstancePre` is store-owned and one-shot, while `Vm`, `Store`, `Instance`, memory, globals, and fuel state are mutable execution state and cannot be shared across invocations. The remaining measured instantiation cost is also small enough that a safe partial cache, such as import-protocol result caching, was already recorded as Low-tier.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — this records the current trace-bound VM-instantiation angle distinct from the already-condensed `InstancePre` API blocker and import-check Low-tier fail

### Why It Failed

The code path is hot enough to notice but not hot enough, after safe-cache constraints, to justify promotion. The reusable parsed-module cache already exists, the stronger reusable-instantiation artifact is not available in wasmi, and the safely removable checks around instantiation are below the Medium floor.

### Lesson Learned

Do not repropose VM instance or `InstancePre` caching for soroswap apply. Future VM-instantiation hypotheses need a new wasmi capability or a trace showing substantially larger current-protocol overlap.
