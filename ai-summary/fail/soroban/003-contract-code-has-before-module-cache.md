# H003: Skip Contract-Code Storage `has` Before Module Cache Lookup

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: VM instantiation setup inside Soroban apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Cached Wasm module execution should avoid redundant physical storage probes when the inter-ledger module cache already contains the parsed module for a contract code hash. For ordinary cached soroswap router invocations, `Host::instantiate_vm` should be able to retrieve the `ParsedModule` and instantiate the VM without first doing an enforcing-mode `Storage::has` lookup on the `CONTRACT_CODE` ledger key.

## Mechanism

`Host::instantiate_vm` currently constructs the contract-code key, calls `storage.has(&wasm_key, ...)`, and only then calls `cache.get_module(wasm_hash)`. Since the module cache is built from the live ledger state and is immutable during parallel apply, reversing the check or storing a "live at cache build" bit could remove one host storage probe from every cached VM instantiation. This would reduce a descendant of `applyLedger` (`storage has`) without changing contract execution order or adding parallelism.

## Trigger

Run the current protocol-27 soroswap apply-load benchmark. Each non-native Wasm invocation that hits the module cache, especially the top-level router contract invocation, reaches `Host::instantiate_vm` before `Vm::from_parsed_module_and_wasmi_linker`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1395-1411` — `Host::instantiate_vm` performs `storage.has(wasm_key)` before `cache.get_module(wasm_hash)`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:527` — `Storage::has` is the measured Tracy zone for the enforcing-mode lookup.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:189-195` — `ModuleCache::get_module` returns the cached `Arc<ParsedModule>`.

## Evidence

The current diagnostic soroswap trace confirms this path is under `applyLedger`: `Vm::instantiate_wasmi` contributes 640.259 ms over 8,452 calls inside apply windows, and `storage has` contributes 38.094 ms over 16,965 calls. Source reading shows every module-cache hit pays the contract-code `has` probe before the cache lookup.

## Anti-Evidence

The absolute target is far below the objective threshold. Even deleting every in-apply `storage has` event would save only 38.094 ms of aggregate worker CPU; normalized by 8 configured clusters and 72 apply windows, that is about 0.066 ms/ledger, roughly 0.03% of the 211 ms accepted soroswap median. The code comment also documents a correctness/future-proofing reason: storage is checked before the cache so a module removed from storage cannot be executed merely because the cache still has it.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — this exact storage-`has`-before-module-cache lookup was not present in the soroban fail summary

### Why It Failed

The removable work is an enforcing storage probe that is already tiny in the current apply windows. It is also a safety check guarding cache/storage consistency, so a correct design would need replacement liveness metadata rather than simply removing the lookup.

### Lesson Learned

Per-VM-instantiation sub-zones must be sized independently from the broad `Vm::instantiate_wasmi` parent. A real redundant lookup can still be orders of magnitude below the 3% Medium floor once normalized by cluster parallelism and ledger count.
