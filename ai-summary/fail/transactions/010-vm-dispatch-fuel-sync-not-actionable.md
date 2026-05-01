# H010: Skip or Batch VM Dispatch Fuel Synchronization

**Date**: 2026-05-01
**Subsystem**: transactions, soroban-env
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every VM host-function call should continue to charge Wasm fuel into the Soroban CPU budget at the same points, enforce near-limit traps at the same boundaries, marshal arguments and return values correctly, and return control to Wasm with fuel consistent with the remaining host budget. Optimizing dispatch must not let guest Wasm execute extra instructions after host-side budget consumption has reduced the remaining CPU allowance.

## Mechanism

The generated dispatch wrapper around every host function performs fuel return, dispatch budget charging, argument conversion, host call execution, result conversion, error augmentation, and fuel refill. The current soroswap trace shows the generated `call` zone is hot, so it is tempting to batch or skip the `FuelRefillable::return_fuel_to_host` / `add_fuel_to_vm` sequence. That would be significant only if fuel synchronization itself were a large removable fraction of the dispatch wrapper.

## Trigger

Run the current soroswap diagnostic trace and inspect `call` at `soroban-env-host/src/vm/dispatch.rs:304` under `applyLedger`. The wrapper runs for each Wasm-to-host function call during SAC/router/pair execution.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` - generated wrapper returns VM fuel to the host before the host call and refills VM fuel after the host call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39` - helper reads consumed/total fuel, charges `WasmInsnExec`, resets fuel, computes remaining fuel, and adds it back.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-302,1428-1429` - remaining CPU budget is converted to Wasmi fuel.

## Evidence

The dispatch wrapper is on the measured apply path: the current trace shows `call` at `soroban-env-host/src/vm/dispatch.rs:304` with 632,325,205 ns self-time across 30,534 calls, and unwrap events for `call` overlap `applyLedger` by 8,072,233,108 ns total. This is under `Host::invoke_function` / `Vm::invoke_function_raw` reached from `InvokeHostFunctionOpFrame::doParallelApply`.

## Anti-Evidence

The trace does not isolate fuel synchronization from mandatory dispatch work. There are no separate `return_fuel_to_host` or `add_fuel_to_vm` zones, and the line-304 `call` self-time includes argument/result marshalling, protocol guards, success/error wrapping, and Tracy instrumentation. The code comments also describe a correctness requirement: fuel is returned to the host before each call so host-side budget accounting remains authoritative, and remaining host budget is supplied back to Wasm before it can execute more instructions.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS - not previously recorded as a transaction fail

### Why It Failed

Skipping or batching dispatch fuel synchronization is not a safe concrete hypothesis without a new mechanism for preserving exact near-limit CPU behavior between host calls. The measured zone is real and apply-descendant, but it is too broad to attribute Medium-tier savings to fuel synchronization specifically, and the obvious shortcut would let Wasm execute with stale fuel after host-side budget consumption.

### Lesson Learned

Treat generated VM dispatch as a composite zone. Before proposing changes to fuel synchronization, add or obtain sub-zone evidence that separates fuel API overhead from mandatory marshalling, budget charging, error handling, and Tracy wrapper cost.
