# H002: Resettable wasmi instance pool for eligible Soroswap contracts

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in repeated Soroban VM instantiation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every contract invocation must begin from a pristine Wasm instance state: initialized linear memory, initialized tables/globals, no residual dropped-segment state, and the current invocation's fresh `Host` in the store. For contracts whose mutable instance state can be proven resettable, stellar-core should be able to reuse a per-worker pristine instance allocation by resetting memory/tables/globals and swapping in the fresh host, instead of re-running full wasmi linker instantiation for the same parsed module on every invocation. The observable result, budget failures, events, and ledger changes should match fresh instantiation exactly.

## Mechanism

The current host caches parsed modules but still calls `wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` for every VM frame. In the accepted soroswap trace this happens 20,389 times for 6,776 host invocations, because each swap repeatedly enters the same small set of router/pool contracts across worker threads. A next-protocol resettable-instance pool, stored next to `ParsedModule` or in a per-thread module cache, could skip import resolution, instance allocation, function extraction, and initial table/global construction for modules that pass a conservative eligibility check; reset would restore only mutable runtime state and bind the new `Host`, preserving determinism while amortizing the dominant instantiation sub-zone.

## Trigger

Run the soroswap apply-load benchmark with warmed module cache. The workload repeatedly invokes the same contract code hashes across thousands of transactions in a ledger; each worker thread instantiates those modules for each transaction even though the parsed module and import layout are unchanged.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a fresh `Store`, charges instantiation, checks imports, and calls `Linker::instantiate` for every VM frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` — `Vm::from_parsed_module_and_wasmi_linker` wraps the newly-created store/instance/memory in a `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` caches parsed modules and the maximal linker, but not reusable pristine runtime instances.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:189-195` — `ModuleCache::get_module` returns only `Arc<ParsedModule>`, so every call site must instantiate from scratch.
- `src/rust/src/soroban_proto_any.rs:433-448` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:475-481` — C++ parallel apply invokes the Rust host with the shared module cache, then each invocation constructs a fresh host/VM stack.

## Evidence

The current soroswap Tracy trace's apply-window overlap shows VM instantiation is a descendant of `applyLedger`, not TX-set construction:

| Zone | Apply-window total | Calls | Mean | Source |
|---|---:|---:|---:|---|
| `Vm::instantiate` | 1,655,685,114 ns | 20,389 | 81,205 ns | `soroban-env-host/src/vm.rs:197` |
| `Vm::instantiate_wasmi` | 1,648,211,481 ns | 20,389 | 80,838 ns | `soroban-env-host/src/vm.rs:160` |
| `Vm::instantiate_wasmi - instantiate` | 1,317,542,205 ns | 20,389 | 64,620 ns | `soroban-env-host/src/vm.rs:171` |

After 8-way worker normalization, the `Vm::instantiate_wasmi - instantiate` sub-zone alone represents about 164 ms of wall time across the 5.23 s apply-window trace, slightly over the 3% Medium floor. A resettable pool that avoids most of this sub-zone for repeatedly-called eligible contracts should therefore be measurable on soroswap even if store creation and protocol checks remain per invocation.

## Anti-Evidence

This is not the previously-rejected `InstancePre` cache: `InstancePre` is store-bound and one-shot, so the design must not rely on wasmi's public `InstancePre` reuse. It is also not a naive pristine-snapshot replay: a safe implementation must explicitly prove eligibility and reset all mutable wasmi state, including linear memory contents and size, tables, globals, dropped passive segments, and any effects of `memory.grow`; contracts that cannot be proven resettable must fall back to fresh instantiation. The change is invasive because it likely requires support in the pinned `soroban-wasmi` fork, and a PoC must prove byte-for-byte ledger/meta equivalence plus repeated benchmark improvement before promotion.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-wasmi-pristine-instance-snapshots.md`
**Failed At**: reviewer

### Trace Summary

The current hot path does instantiate a fresh wasmi runtime for each Wasm contract frame: C++ parallel apply calls the Rust bridge for each Soroban transaction, `e2e_invoke` constructs a fresh `Host`, `Host::invoke_function` enters contract frames, and `Host::instantiate_vm` retrieves a cached `ParsedModule` but still calls `Vm::from_parsed_module_and_wasmi_linker`. That method creates a new `wasmi::Store`, calls `Linker::instantiate`, ensures no start function, and stores the resulting `Instance` and memory handle in a new `Vm`. However, the proposed resettable Store/Instance pool is substantially the same optimization already investigated as `001-wasmi-pristine-instance-snapshots.md`, whose retained failure record says the PoC failed because `memory.grow`, dropped element/data segments, and mutated tables cannot be safely reset through the pinned wasmi API.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2583-2620` — parallel Soroban worker threads call `TransactionFrameBase::parallelApply` for each `TxBundle`, placing host invocation on the `closeLedger` worker path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `InvokeHostFunctionOpFrame` crosses the Rust bridge with the shared module cache for each Soroban invocation.
- `src/rust/src/soroban_proto_any.rs:433-448` — the bridge dispatches to protocol-specific `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — each invocation builds enforcing storage, constructs a fresh `Host`, installs the module cache, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — top-level `InvokeContract` host functions enter `call_n_internal` and contract-call handling.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls retrieve the contract instance, look up `Arc<ParsedModule>` in `ModuleCache`, then instantiate a VM from the cached module and linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218` — `Vm::instantiate_wasmi` creates a new `Store`, charges instantiation, checks imports, calls `Linker::instantiate`, calls `ensure_no_start`, extracts memory, and returns a new `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,185-195` — `ModuleCache` caches parsed modules, the shared engine, and a maximal linker only; it does not cache resettable runtime instances.
- `src/rust/soroban/p26/Cargo.toml:46-50` and `src/rust/soroban/p26/Cargo.lock:1756-1758` — p26 uses pinned `soroban-wasmi` `0.31.1-soroban.20.0.1` at revision `0ed3f3dee30dc41ebe21972399e0a73a41944aa0`.
- `ai-summary/fail/soroban/summary.md:80` — prior investigation `001-wasmi-pristine-instance-snapshots.md` covered Store/Instance snapshot-restore for repeated invocations and failed at PoC due to unresettable wasmi mutable state through the pinned API.

### Why It Failed

This hypothesis is not novel. Its conservative eligibility language and "not InstancePre" caveat avoid the previously rejected `InstancePre` cache, but the actual mechanism is still reusing an initialized wasmi `Store`/`Instance` by restoring all mutable post-instantiation state before binding a fresh `Host`. That is substantially the same reset/snapshot problem recorded in `001-wasmi-pristine-instance-snapshots.md`, including the same correctness constraints around linear memory size/content, tables, globals, dropped passive segments, and `memory.grow`. The retained failure summary says that investigation already reached PoC and was declared infeasible against the pinned wasmi API, so promoting this duplicate would repeat a known failed path unless it first presents a new wasmi API/design that directly resolves that prior blocker.

### Lesson Learned

For VM-instantiation hypotheses, distinguish narrower linker/import-cache ideas from whole Store/Instance reset semantics. Any proposal that depends on restoring an initialized wasmi runtime to pristine state is a duplicate of the Store/Instance snapshot-restore investigation unless it supplies a concrete new wasmi capability that resets memory growth, table/global mutations, and dropped passive segments safely and deterministically.
