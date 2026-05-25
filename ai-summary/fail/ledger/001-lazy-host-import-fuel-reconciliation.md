# H001: Lazy Host-Import Fuel Reconciliation

**Date**: 2026-05-25
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by removing per-host-import Wasmi fuel reset/refill overhead from hot router execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban Wasm invocation should charge exactly the same CPU budget for executed Wasm instructions and host functions, trap at the same budget boundary, and return the same ledger state, events, and results. Crossing from Wasm into a host import should not need to reset all Wasmi fuel to zero and then refill the VM from the host budget on every import when the same accounting can be reconciled lazily at bounded points with deterministic rounding.

## Mechanism

The generated host-import thunks in `dispatch.rs` call `FuelRefillable::return_fuel_to_host` before every host function and `FuelRefillable::add_fuel_to_vm` after every host function. Those helpers query consumed fuel, bulk-charge `WasmInsnExec`, reset the Wasmi fuel counter, recompute host-budget fuel remaining, and refill the VM for hundreds of thousands of imports in the soroswap router path. A protocol-gated lazy reconciliation mode could keep a bounded fuel slice in the VM across host imports, charge host-function dispatch/work against the host budget, and reconcile consumed Wasmi fuel at VM exit plus safety checkpoints, preserving deterministic budget limits while avoiding two Wasmi fuel-meter operations per import.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the next-protocol native pool/SAC optimizations enabled. Router Wasm execution still performs many host imports (`call`, `vec_get`, `bytes_append`, `serialize_to_bytes`, `vec_len`, `obj_cmp`, etc.), and each import crosses the generated dispatch path that returns and refills fuel.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-import thunk; returns fuel at line 237 and refills fuel at lines 291-294 for every import.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — `add_fuel_to_vm` requires a clean VM fuel state and `return_fuel_to_host` bulk-charges consumed fuel then resets the store/caller.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:326-345` — outer `metered_func_call` already performs fuel refill before entering Wasm and reconciliation after the Wasm call returns.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:367-383` — conversion from remaining CPU budget to Wasmi fuel; any lazy mode must preserve this deterministic conversion and out-of-budget behavior.

## Evidence

The latest current-state soroswap trace is `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports generated dispatch self-time at `soroban-env-host/src/vm/dispatch.rs:304` summing to 2,432,950,000 ns over 767,481 calls. The hottest individual dispatch thunks are `call` with 1,303,110,709 ns self over 26,145 calls, `vec_new_from_linear_memory` with 124,567,315 ns self over 43,858 calls, `bytes_append` with 112,490,374 ns self over 52,220 calls, `vec_get` with 110,183,507 ns self over 95,647 calls, and `vec_len` with 89,014,389 ns self over 139,128 calls.

Timeline intersection confirms these are apply-path events, not TX-set construction: unwrapped `call` has 26,079 in-`applyLedger` events totaling 5,428,387,766 ns, and other generated dispatch events (`vec_new_from_linear_memory`, `bytes_append`, `serialize_to_bytes`, `vec_get`, `vec_len`, `obj_cmp`, `compute_hash_sha256`) also overwhelmingly fall inside `applyLedger`. The source shows the self-time wrapper contains mandatory argument conversion plus two fuel-reconciliation calls per import; removing only the reconciliation portion across hundreds of thousands of imports is plausibly Medium even after T=8 parallelism normalization.

## Anti-Evidence

Budget edge behavior is consensus-sensitive. The current code intentionally avoids cumulative rounding by converting fuel back to host budget at every host import, so a viable implementation must prove equivalent or protocol-gated budget semantics, especially near out-of-fuel traps. The dispatch self-time also includes argument conversion and host-dispatch charging that remain mandatory; reviewer should add dedicated spans around `return_fuel_to_host` and `add_fuel_to_vm` before treating the whole dispatch self-time as removable.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated
**Failed At**: reviewer

### Trace Summary

The apply path is `LedgerManagerImpl::applyTransactions` -> parallel Soroban apply -> `InvokeHostFunctionOpFrame::invokeHostFunction` -> Rust `e2e_invoke::invoke_host_function` -> `Host::invoke_function` -> `call_n_internal` / `call_contract_fn` -> `Vm::invoke_function_raw` / `metered_func_call`. `metered_func_call` refills wasmi fuel before entering Wasm, and every generated host-import thunk then returns consumed VM fuel to the host budget, charges dispatch/host work, calls the host function, converts the result, and refills the VM before execution resumes. The per-import fuel handoff is real and in the soroswap apply path, but it is only a subset of generated dispatch self-time, which itself is aggregate worker CPU in the 8-cluster parallel phase rather than serial apply wall time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-3030` - `applyTransactions` dispatches the soroswap phase through `applyParallelPhase` / `applySorobanStages`, so host invocation work runs in parallel Soroban workers during `closeLedger`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` - each Soroban transaction calls `rust_bridge::invoke_host_function` and records returned CPU/memory/invocation metrics.
- `src/rust/src/soroban_proto_any.rs:391-452` - the bridge constructs the transaction budget and calls the p26 `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-552` - p26 host setup builds enforcing storage, creates the `Host`, and executes `Host::invoke_function` inside the measured invocation span.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1868-1936` - `HostFunction::InvokeContract` enters a host frame, converts contract/function/args, and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1858` and `781-825` - `call_n_internal` enforces reserved-function and reentry semantics before `call_contract_fn` loads the contract instance and invokes either native fast paths or the Wasm VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` and `275-345` - `invoke_function_raw` converts host values to VM-relative `wasmi::Value`s, and `metered_func_call` refills VM fuel before `func.call` and returns consumed fuel after the call exits.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` - every generated host import clones the host, optionally traces args, returns VM fuel to the host, charges `DispatchHostFunction`, converts arguments, calls `host.$fn_id`, marshals the result, escalates errors, and refills VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` - `add_fuel_to_vm` requires the VM fuel state to be clean, converts remaining host CPU budget to wasmi fuel, and `return_fuel_to_host` bulk-charges consumed `WasmInsnExec` before resetting fuel.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:367-383` and `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:143-188` - fuel conversion deliberately avoids cumulative rounding across imports, and each budget charge updates totals and checks limits.
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/results.csv:1-3` and `logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.log` - the diagnostic run's soroswap median was 209.902840 ms and contained 201 measured `Model tx benchmark` samples.

### Why It Failed

The inefficiency exists, but the projected apply-time impact is below the objective's Medium threshold. The hypothesis's broadest removable ceiling is the entire generated dispatch self-time: 2.433 s over the diagnostic soroswap run, or about 12.1 ms of aggregate worker CPU per measured ledger before subtracting mandatory argument conversion, host dispatch charging, host function calls, result marshaling, error handling, and tracing checks. Because soroswap executes this path inside the configured 8-way parallel Soroban phase, the wall-time ceiling for eliminating the entire dispatch wrapper is roughly 1.5 ms/ledger, under 1% of the 209.9 ms median; the actual fuel reset/refill subset is smaller and still must retain exact `WasmInsnExec` charging and budget-limit checks. A lazy scheme also faces a correctness constraint: after host functions charge the shared host budget, stale fuel left in wasmi would let the VM continue executing against an obsolete allowance unless the implementation re-synchronizes or otherwise subtracts fuel, which is the same class of operation the hypothesis seeks to remove.

### Lesson Learned

For Soroban worker-thread import hotspots, divide aggregate Tracy self-time by the number of measured ledgers and by configured cluster parallelism before assigning severity. Generated dispatch self-time is an upper bound on all VM/host boundary work, not on fuel reconciliation alone; budget/fuel synchronization is consensus-sensitive and cannot be treated as removable without a dedicated timing span and a concrete semantics-preserving synchronization design.
