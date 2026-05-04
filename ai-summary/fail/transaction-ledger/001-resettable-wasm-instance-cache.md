# H001: Resettable per-worker Wasm instance cache for repeated contract calls

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host VM
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding repeated wasmi instantiation for the same hot contracts inside parallel apply workers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a soroswap ledger, repeated calls to the same already-cached Wasm modules should reuse as much deterministic VM setup as possible while still presenting each contract call with a clean Wasm execution state. The apply path should not rebuild a fresh `wasmi::Store`, instantiate the same `wasmi::Module` through the same linker, and rediscover its memory export for every router/pair call if a per-worker resettable instance can restore the module to the exact post-instantiation state before each call.

## Mechanism

`Host::call_contract_fn` instantiates a new `Vm` for every Wasm contract call, even when `ModuleCache` already holds the parsed module and maximal linker. In the current soroswap trace, the seven long `applyLedger` windows contain **20,314** `Vm::instantiate_wasmi - instantiate` events totaling **1,313,693,795 ns** of worker self-time (**187.671 ms per long window aggregate; 23.459 ms after T=8 normalization**), plus the parent `Vm::instantiate_wasmi` at **52.843 ms T=8-normalized**. A per-worker cache of resettable instantiated modules would keep ledger effects deterministic by never sharing a live instance across workers or concurrent calls, resetting memory/globals/tables and replacing store host data before each use; if it removes even half of the current instantiation parent cost it clears the 3% Medium floor on the 272.896 ms soroswap baseline.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) with the diagnostic trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Each long `applyLedger` window repeatedly invokes router/pair Wasm contracts; `Host::invoke_function` occurs 6,740 times while `Vm::invoke_function_raw` and wasmi instantiation occur about 20,300 times, showing roughly three Wasm instantiations per top-level transaction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — `call_contract_fn` retrieves the contract instance and calls `instantiate_vm` for every Wasm contract call before entering the `Frame::ContractVM`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `instantiate_vm` uses the inter-ledger `ModuleCache` for parsed modules, but still constructs a fresh `Vm` through `Vm::from_parsed_module_and_wasmi_linker` on each cache hit.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a new `wasmi::Store`, charges cached-instantiation costs, checks imports, instantiates the module, ensures no start function, and looks up the memory export.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,185-195` — `ModuleCache` owns the shared engine/linker and parsed modules, but not reusable instantiated state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban cluster worker futures are joined synchronously by the apply path, so reducing worker-local instantiation shortens `applyLedger` without exceeding `NUM_CLUSTERS` parallelism.

## Evidence

- Timestamp filtering against only the seven `applyLedger` windows longer than 100 ms confirms this is inside the measured close-ledger path, not TX-set construction: `Vm::instantiate_wasmi - instantiate` totals **1,313,693,795 ns / 20,314 calls**, or **23.459 ms T=8-normalized**; the parent `Vm::instantiate_wasmi` totals **2,959,231,559 ns / 60,943 events**, or **52.843 ms T=8-normalized**.
- The trace shape is workload-amplified for soroswap: `Host::invoke_function` appears **6,740** times in the same windows, while `Vm::invoke_function_raw` appears **20,253** times, matching repeated router/pair Wasm calls per transaction.
- This is distinct from the rejected `cache-wasmi-instance-prelink` and `cache-minimal-wasmi-linkers` families. Those targeted reusable pre-link/linker artifacts; this hypothesis targets the fully instantiated VM state and proposes a per-worker reset discipline instead of relying on `InstancePre` reuse.
- Determinism can be preserved if the cache is worker-local, keyed by module hash/protocol, reset before each call, and never allows live guest memory or globals from one call to leak into another. Observable ledger writes still flow through the existing `Host` storage, frame, and budget machinery in call order.

## Anti-Evidence

- Wasm instances contain mutable memories, globals, and tables. A PoC must prove there is a complete and cheap reset mechanism for all state that guest code can observe; exported-memory hashing alone is insufficient because `vm.rs:459-461` notes that unexported tables/globals may exist.
- Budget totals are protocol-visible. If the reset path changes cached-instantiation charges, it must be protocol-gated or reproduce p26 metering exactly.
- The pinned wasmi API already invalidated `InstancePre` reuse in prior review. This hypothesis is only viable if implemented as a true resettable-instance design or supported by a wasmi-level clone/reset primitive, not by re-proposing `InstancePre` caching.
- The parent `Vm::instantiate_wasmi` total is an upper bound. Store host-data replacement, fuel limiter setup, import checks that remain required, and reset bookkeeping reduce the recoverable share.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md:59` (`016-reuse-wasmi-vm-instances-below-threshold.md`)
**Failed At**: reviewer

### Trace Summary

The traced apply path is real: C++ parallel apply runs `LedgerManagerImpl::applyThread`, `InvokeHostFunctionOpFrame::doParallelApply` calls the Rust bridge, `e2e_invoke::invoke_host_function` constructs a fresh `Host`, installs the shared `ModuleCache`, and `Host::call_contract_fn` instantiates a `Vm` for each Wasm contract call. On cache hits, `instantiate_vm` reuses `ParsedModule` and the maximal linker, but `Vm::from_parsed_module_and_wasmi_linker` still calls `instantiate_wasmi`, which creates a new `wasmi::Store`, instantiates the module, ensures no start function, and looks up the memory export. This is substantially the same hypothesis family as the prior rejected `016-reuse-wasmi-vm-instances-below-threshold.md`, and the resettable variant does not add a viable API-backed reset mechanism.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:59` — prior substantially equivalent VM-instance reuse hypothesis was already rejected; it specifically notes that a correct cross-call instance cache must solve per-call store/host isolation and that the reusable wasmi artifact is unavailable with the pinned API.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — each Soroban worker applies every transaction in its cluster and calls `parallelApply`; worker-local VM work is on the `applyLedger` critical path.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — the apply path synchronously joins all cluster futures, so worker instantiation time can matter but remains bounded by the worker critical path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017,1358-1377` — Soroban parallel apply invokes the Rust host and records resulting storage/events for each transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — the Rust bridge dispatch wraps each invocation and calls the protocol-specific host invocation with the shared `SorobanModuleCache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — each host-function invocation builds a fresh `Storage`, `Host`, auth state, source account, ledger info, PRNG seed, and optional module cache, then calls `Host::invoke_function` and consumes the host with `try_finish`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — every Wasm contract call retrieves the contract instance and calls `instantiate_vm` before entering `Frame::ContractVM`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache hits reuse the parsed module and shared linker but still construct a fresh `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,191-217` — `instantiate_wasmi` creates a fresh `Store<Host>`, installs the limiter, performs protocol import checks, calls `Linker::instantiate`, finalizes with `ensure_no_start`, and caches the exported memory handle.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:459-461` — existing diagnostic hashing explicitly notes that unexported tables/globals may exist and are not observable through exports.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,85-95,185-195` — `ModuleCache` intentionally stores parsed modules plus shared engine/linker, not instantiated state.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/module/instantiate/pre.rs:11-80` — `InstancePre` owns a builder and is consumed by `start`/`ensure_no_start`; it is not a reusable instantiation template.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/store.rs:123-154,730-758` — the store owns all funcs, memories, tables, globals, instances, data segments, element segments, extern refs, fuel, and host data; public APIs expose host data access but not a complete store reset/snapshot primitive.
- `/home/garand/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/soroban-wasmi-0.31.1-soroban.20.0.1/src/memory/mod.rs:390-465`, `/src/global.rs:150-270`, and `/src/table/mod.rs:560-645` — public APIs allow reading/writing exported memories, globals, and tables, but they do not provide a complete post-instantiation rollback of every store-owned entity, including unexported mutable state.

### Why It Failed

This hypothesis is not novel: it is a reset-focused restatement of the already-recorded `016-reuse-wasmi-vm-instances-below-threshold.md` VM-instance reuse investigation. The traced code confirms the repeated instantiation exists, but the pinned wasmi API still does not provide a correctness-preserving, cheap way to restore a fully instantiated module to its exact post-instantiation state. A manual reset through public exports would be incomplete because Wasm may contain unexported mutable globals, tables, data/element state, grown memory/table sizes, fuel/store internals, and host data tied to the fresh per-invocation `Host`; replacing only exported memory or visible globals would risk cross-call guest-state leakage, while rebuilding the full store/instance is the current instantiation path.

### Lesson Learned

Future VM-instantiation hypotheses should not re-propose cross-call `Vm` or instance reuse unless they identify a concrete pinned-wasmi primitive that can clone or reset the whole store-owned instance state, including unexported mutable entities, with preserved metering semantics. Without such an API, the only safe reset is re-instantiation, and broader VM performance work needs to target measured execution/dispatch costs rather than only instance creation.
