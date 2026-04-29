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
