# H001: Cache clean Wasmi instantiation artifacts for hot Soroswap modules

**Date**: 2026-05-04
**Subsystem**: ledger / Soroban host invocation
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated Wasm instantiation on the parallel apply worker critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated calls to the same already-cached contract module during `applyLedger` should produce a fresh, deterministic VM execution context for each contract call without redoing all module/linker instantiation work from scratch. The module cache should amortize every reusable part of preparing a hot Wasm module while still creating isolated per-call mutable store, memory, and globals so contract execution semantics do not change.

## Mechanism

`ModuleCache` currently caches parsed modules and a shared `wasmi::Linker`, but `Host::instantiate_vm` still calls `Vm::from_parsed_module_and_wasmi_linker`, which creates a new `wasmi::Store` and then runs `wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` for every Wasm contract call. In the current soroswap trace, `Vm::instantiate_wasmi - instantiate` is fully inside `applyLedger` and accounts for 1,315,387,452 ns of self-time across 20,389 calls; even after normalizing across `NUM_CLUSTERS=8`, eliminating most of this repeated import/link instantiation work is a Medium-tier opportunity.

The proposed optimization is to extend the module cache with a protocol-gated clean instantiation artifact or equivalent pre-linked template keyed by Wasm hash and protocol, so `Vm::instantiate_wasmi` can cheaply create a fresh store-bound instance without repeating the full linker instantiation path. The cached artifact must not reuse mutable `Store`, memory, globals, or host state across calls; it should only reuse immutable import-resolution/module-instantiation structure.

## Trigger

Run the current soroswap apply-load workload (`soroswap, TX=2000, T=8`) with a trace from `ai-summary/CURRENT_STATE.md`. The diagnostic trace shows 20,389 `Vm::instantiate_wasmi - instantiate` events under `applyLedger`, about three Wasm instantiations per invoke-host transaction, because soroswap repeatedly calls the same hot contract modules through `Host::call_contract_fn`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a store and calls `wasmi_linker.instantiate` on every VM construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-901` — `Host::instantiate_vm` checks storage, fetches a cached parsed module, and still instantiates a new `Vm` for each call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` explicitly caches parsed-but-not-instantiated modules and the reusable linker, leaving instantiation uncached.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:185-195` — `get_module` returns only `Arc<ParsedModule>`, so callers cannot reuse any pre-instantiation artifact.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` waits on worker futures; reducing worker instantiation time reduces this measured apply critical path without changing worker count.

## Evidence

The current soroswap Tracy trace reports `applyLedger` total time of 5,230,315,999 ns. `Vm::instantiate_wasmi - instantiate` reports 1,315,387,452 ns self-time at `soroban-env-host/src/vm.rs:171` over 20,389 calls, and unwrap/timeline analysis showed 100% of those events overlap `applyLedger` windows. The source confirms the hot path uses the module cache only up to parsed module/linker lookup; the expensive `wasmi_linker.instantiate` call remains per contract call.

Soroswap is a good trigger because the benchmark repeatedly invokes the same small set of router/pair/token Wasm modules. The optimization is deterministic if it only caches immutable instantiation preparation and still constructs a fresh store-bound instance for each call.

## Anti-Evidence

Wasmi instances themselves are mutable and cannot be shared across calls without leaking memory/global state between contract invocations. Prior exploration also suggests some Wasmi pre-instantiation APIs may be per-store or single-use rather than reusable templates, so the PoC must first prove there is a safe reusable artifact to cache. If the Wasmi API cannot expose such an artifact, this hypothesis should fail rather than attempt to reuse live instances.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/ledger/summary.md`, no individual ledger/cross-subsystem fail files matched, and no ledger/cross-subsystem success files exist
**Failed At**: reviewer

### Trace Summary

The claimed hot-path inefficiency exists: parallel Soroban apply waits for worker futures, each worker calls `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge, `Host::call_contract_fn`, `Host::instantiate_vm`, and finally `Vm::instantiate_wasmi`, where even module-cache hits create a fresh `Store` and call `wasmi_linker.instantiate`. However, the proposed cacheable artifact does not exist in the pinned Wasmi API. `Linker::instantiate` resolves imports and then constructs a one-shot `InstancePre` containing a newly allocated store-owned `Instance` and `InstanceEntityBuilder`; `InstancePre::ensure_no_start(self, ...)` consumes the pre-instance and initializes that same store-owned instance. Caching `InstancePre`, `Instance`, `Memory`, `Global`, or imported host `Func` values would either be single-use, tied to the wrong `Store`, or leak mutable execution state across calls.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches cluster workers and synchronously waits on each future, so worker VM instantiation time is on the apply critical path.
- `src/ledger/LedgerManagerImpl.cpp:2623-2709` and `src/ledger/LedgerManagerImpl.cpp:2967-3029` — parallel Soroban stages build clusters, run worker apply, then merge results after workers finish.
- `src/transactions/TransactionFrame.cpp:2386-2430` and `src/transactions/OperationFrame.cpp:175-188` — worker transaction execution dispatches the single Soroban operation to operation-level parallel apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:560-584` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — invoke-host parallel apply passes the shared module cache through the C++/Rust bridge into host-function execution.
- `src/rust/src/soroban_invoke.rs:7-38`, `src/rust/src/soroban_proto_any.rs:391-448`, and `src/rust/src/soroban_proto_all.rs:95-129` — protocol dispatch routes protocol 26 invocations to `e2e_invoke::invoke_host_function` with `Some(module_cache.p26_cache.module_cache.clone())`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — each invocation builds a fresh `Host`, installs the cloned `ModuleCache`, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-901` — Wasm contract calls fetch `Arc<ParsedModule>` from the cache on hits but still call `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — every VM construction creates a new `wasmi::Store`, charges instantiation, calls `wasmi_linker.instantiate`, consumes the resulting pre-instance with `ensure_no_start`, and records the memory export.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` and `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:185-195` — `ModuleCache` intentionally caches parsed modules plus the shared engine/linker only; `get_module` exposes no reusable instantiation state.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:212-228` and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:265-287` — parsed modules are already the reusable unit; cache misses or uploads use an isolated engine and linker.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:646-659` — `Linker::instantiate` processes imports against the current store and calls `Module::instantiate`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:341-367` — each linker-defined host function import allocates a new trampoline and host `Func` in the current store.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78` — module instantiation allocates a fresh instance handle, extracts imports/functions/tables/memories/globals/exports, initializes element and data segments, and returns `InstancePre`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/pre.rs:12-80` — `InstancePre` owns the fresh `Instance` handle and builder and is consumed by `start` or `ensure_no_start`; it is not cloneable or reusable.

### Why It Failed

The Medium impact estimate depends on skipping most of `wasmi_linker.instantiate`, but the only Wasmi pre-instantiation object available at this version is not a clean reusable template. It is a partially built, store-owned, single-use instance containing mutable per-call allocations and import bindings. The remaining store-independent state is already cached as `wasmi::Module`, shared `Engine`, and shared `Linker`; avoiding the measured work would require a new Wasmi API or internal redesign that can separate immutable instantiation planning from per-store allocation and data/table/global initialization. That is outside the target-code change and cannot be safely implemented by extending Stellar Core's `ModuleCache` alone.

### Lesson Learned

For Soroban VM-cache hypotheses, distinguish parsed-module/linker reuse from Wasmi instance construction. `InstancePre` sounds like a cacheable pre-instantiation artifact, but in this pinned Wasmi it is already past store allocation and is consumed to finish one instance; caching it would break ownership and isolation rather than amortize work.
