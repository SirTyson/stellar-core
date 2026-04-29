# H002: Coalesce VM Dispatch Fuel Refill Checks on the Non-Tracing Hot Path

**Date**: 2026-04-29
**Subsystem**: soroban-env / vm dispatch
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant wasmi fuel-meter queries around every host-function dispatch
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every VM-to-host boundary should charge identical `WasmInsnExec` budget, preserve the same host-function budget charges, trap at the same CPU limits, and resume Wasm with the same remaining fuel as today. The dispatch wrapper should not perform redundant cleanliness checks and fuel-meter queries when the immediately preceding `return_fuel_to_host` call has just reset the fuel meter and established the invariant locally.

## Mechanism

Generated dispatch functions call `FuelRefillable::return_fuel_to_host` on entry, charge `DispatchHostFunction`, run the host function, then call `FuelRefillable::add_fuel_to_vm` before returning to Wasm. `add_fuel_to_vm` first calls `is_clean`, which performs both `fuel_consumed()` and `fuel_total()` queries, even though dispatch just called `reset_fuel()` through `return_fuel_to_host` on the same `Caller`. On the non-tracing production hot path this repeats two wasmi fuel-meter reads for every host-function dispatch, in addition to recomputing the host budget's fuel allowance and adding fuel back.

A dispatch-specific helper such as `add_fuel_to_clean_vm_unchecked` or `refill_after_dispatch_return` could be used only immediately after successful `return_fuel_to_host`, skipping the redundant `is_clean` queries while preserving the external `add_fuel_to_vm` guard for all other call sites. The optimization preserves determinism because it only removes an internal invariant re-check whose truth follows from the previous successful reset; fuel amount and budget accounting remain unchanged.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and profile the p26 dispatch path. Soroswap contracts perform many VM host-function calls for map/vector/address/storage/event operations, so every swap repeatedly crosses the dispatch boundary and pays the fuel-return/refill sequence.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-function dispatch wrapper; calls `return_fuel_to_host` at line 237 and `add_fuel_to_vm` at line 294 for every VM host-function call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:18-40` — `add_fuel_to_vm` checks `is_clean`, and `is_clean` calls both `fuel_consumed` and `fuel_total` before adding fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:325-345` — direct VM function call entry/exit also uses `add_fuel_to_vm` / `return_fuel_to_host`, so the specialized helper must be limited to contexts where a preceding reset proves cleanliness.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-300` — remaining CPU budget is converted to wasmi fuel; the optimized path must keep this calculation unchanged.

## Evidence

The current soroswap Tracy trace is `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. All 19,982 generated dispatch `call` events are fully contained in `applyLedger` windows, totaling 7,730,070,231 ns; self-time export reports `call,soroban-env-host/src/vm/dispatch.rs,304,424331726,...,19982`. The same apply window contains 10,003 `Vm::invoke_function_raw` events totaling 10,208,687,303 ns, so dispatch/fuel-boundary overhead is on the measured `closeLedger` critical path and scales with soroswap host-function call count.

The existing fail summary rejects only `tracing_enabled` RefCell checks inside dispatch as below threshold. This hypothesis targets a different dispatch cost: two wasmi fuel-meter reads per host-function return path that are logically redundant after a successful `reset_fuel()`. It is narrower than changing metering semantics because `return_fuel_to_host` still charges consumed fuel and the refill still uses the same remaining-budget calculation.

## Anti-Evidence

The dispatch `call` zone includes many costs that this optimization cannot remove: VM-to-host argument marshalling, host-function work, budget charging, error augmentation, relative-object translation, and adding the final fuel amount. The removable slice is only the redundant cleanliness check on the refill side, so a PoC must measure it directly and may find it below the Medium threshold. The helper must also be carefully scoped: skipping `is_clean` is only safe immediately after a successful `return_fuel_to_host` / `reset_fuel` on the same `Caller`, not for the initial `Vm::metered_func_call` entry path or arbitrary external callers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in Soroban fail/success records; the closest dispatch failure targeted `tracing_enabled` RefCell checks, not fuel refill cleanliness queries
**Failed At**: reviewer

### Trace Summary

The Soroban apply path enters Rust contract execution through `Vm::invoke_function_raw`, transfers remaining host CPU budget into wasmi fuel with `Vm::metered_func_call`, and then every Wasm-to-host call routes through a generated dispatch wrapper. That wrapper returns consumed fuel to the host budget, executes the host function, and refills the VM through `FuelRefillable::add_fuel_to_vm`, whose first step is the claimed `is_clean` check. The redundant check exists on the successful dispatch return path, and a narrowly scoped unchecked helper would likely be correctness-preserving after a successful `return_fuel_to_host`, but the removable work is only two simple wasmi fuel-state reads per dispatch.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` converts absolute host values to relative wasmi values and calls `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:325-345` — `metered_func_call` uses the general checked `add_fuel_to_vm` before `func.call`, then always returns consumed fuel to the host after the call; this entry path cannot use a dispatch-specific unchecked refill because no immediately preceding reset proves cleanliness.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-function wrappers clone the host, optionally trace, call `return_fuel_to_host`, charge `DispatchHostFunction`, marshal arguments/results, execute `host.$fn_id`, then call `add_fuel_to_vm` before resuming Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:18-40` — `is_clean` calls `fuel_consumed()` and `fuel_total()`; `add_fuel_to_vm` uses it as a general guard before computing `get_wasmi_fuel_remaining()` and calling `add_fuel`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-302` — the refill amount is derived from remaining CPU budget and must be unchanged by any optimization.
- `src/rust/soroban/p26/soroban-env-common/src/vmcaller_env.rs:30-53` — host functions receive a `VmCaller` wrapper that only exposes the underlying wasmi `Caller` through `try_ref`/`try_mut`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:76-177` — host functions that use `VmCaller` do so for linear-memory reads/writes and separately charge host budget; these helpers do not add wasmi fuel, reset wasmi fuel, or consume Wasm instructions.

### Why It Failed

The inefficiency is real but below the optimize-soroswap objective severity threshold. A Medium hypothesis must plausibly save at least 3% of the cited 5.77 s apply-window total, roughly 173 ms across the 19,982 dispatches in the trace. That requires the two skipped fuel-state queries to cost about 8.7 us per dispatch, which is not credible for two in-process wasmi store getter calls that do not allocate, hash, serialize, lock, perform I/O, or cross FFI.

The hypothesis's broad dispatch measurements do not isolate the removable slice. The `dispatch.rs` self-time includes argument marshalling, relative-object translation, host budget charges, result conversion, error augmentation, and the host-call wrapper body; the 7.73 s total dispatch zone also includes descendant host-function work. A correct patch would still run `return_fuel_to_host`, `DispatchHostFunction` charging, all marshalling, the host function, budget-to-fuel conversion, and `add_fuel`; it only removes `fuel_consumed()` and `fuel_total()` from the final guard on successful dispatch returns. Even assigning hundreds of nanoseconds to each getter produces only low-single-digit milliseconds to tens of milliseconds across the whole trace, far below the 3% Medium floor, and Low/sub-noise findings are rejected for this objective.

### Lesson Learned

Do not infer Medium impact from the aggregate VM dispatch wrapper zone. For dispatch micro-optimizations, first isolate the exact removable operation count and per-operation cost; checks that boil down to a few wasmi store field reads per host call are structurally below the optimize-soroswap review threshold unless direct measurement shows an unexpectedly large per-call cost.
