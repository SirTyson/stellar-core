# H009: Cache per-VM exported function handles to avoid repeated `get_export` lookup

**Date**: 2026-05-03
**Subsystem**: soroban-env / rust
**Severity**: Low
**Impact**: Reduce Wasm invocation wrapper overhead in the soroswap apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Wasm contract call should resolve and invoke the same exported function as today, preserve the same missing-function behavior for constructor/no-op paths, transfer fuel at the same VM/host boundaries, and return the same `Val` or `HostError`. If a `Vm` is created for a known `(contract_id, function)` frame, it should not repeatedly rebuild the symbol string and search the instance exports when that function handle could be resolved once for the instance before execution.

## Mechanism

`Host::call_contract_fn` instantiates a `Vm` and immediately calls `Vm::invoke_function_raw`; `invoke_function_raw` marshals arguments and delegates to `metered_func_call`, which converts the function `Symbol` to `SymbolStr`, calls `wasmi_instance.get_export`, checks `into_func`, and then calls the resulting `Func`. The current trace shows `Vm::invoke_function_raw` self-time of 696,879,003 ns and `call` wrapper self-time of 922,554,179 ns under `applyLedger`. A per-instance cached `Func` for the frame's target export could remove the symbol conversion and export-table lookup on the successful path without changing Wasm execution or ledger state.

## Trigger

Run the current soroswap apply-load benchmark. Each successful swap invokes multiple Wasm contract frames; the trace records 20,313 `Vm::invoke_function_raw` calls and 20,389 wasmi instantiations inside `applyLedger`, so normal soroswap execution repeatedly resolves the single function it is about to call for each newly instantiated VM.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-775` — `call_contract_fn` knows the function symbol before constructing the `Frame::ContractVM` and invoking the VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-347` — `metered_func_call` converts `func_sym`, looks up the export, validates it is a function, handles missing-function behavior, and performs the actual wasmi call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `invoke_function_raw` performs argument marshalling before entering `metered_func_call`.

## Evidence

The current diagnostic trace reports these zones as descendants of `applyLedger` by timestamp overlap: `Vm::invoke_function_raw,soroban-env-host/src/vm.rs,400,696879003 ns,20313 calls` and `call,soroban-env-host/src/vm/dispatch.rs,304,922554179 ns,40605 calls`. Source reading shows there is no field on `Vm` or `Frame::ContractVM` holding the resolved `wasmi::Func`; every call goes through `SymbolStr::try_into_val`, `Instance::get_export`, and `Extern::into_func` even though the target export is already known by `Host::call_contract_fn`.

## Anti-Evidence

This optimization does not address the dominant wasmi instantiation work, nor the actual Wasm execution and host dispatch inside `func.call`. In the soroswap trace, there is approximately one exported-function invocation per newly-created VM, so caching inside a `Vm` would not create many reuse hits unless resolution is moved into construction and replaces, rather than supplements, the current lookup. Missing-constructor/no-op behavior and store-bound `Func` lifetimes also require careful handling.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from retained Store/InstancePre reuse, minimal-linker, wasmi allocation, and arg-marshalling investigations

### Why It Failed

The removable slice is too small for the optimize-soroswap threshold. The broad `Vm::invoke_function_raw` self-time is about 697 ms of aggregate worker CPU across the whole trace; divided across the 8 balanced soroswap clusters and 71 apply windows, that is about 1.2 ms per ledger before subtracting mandatory argument translation, fuel transfer, error handling, and the actual `func.call`. The export lookup/symbol-conversion subset is only a fraction of that upper bound, so it cannot plausibly reach the required 3-10% Medium improvement.

### Lesson Learned

For wasmi invocation-wrapper ideas, separate instantiation, export lookup, argument marshalling, fuel transfer, and actual dispatch before assigning severity. A cache that has at most one use per fresh VM instance is structurally a micro-optimization, even when the parent invocation zone appears high in aggregate worker self-time.
