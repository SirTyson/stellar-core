# H005: Cache wasmi exported function handles inside `Vm`

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM invocation
**Severity**: Low
**Impact**: apply-time reduction by avoiding repeated Wasm export lookup for hot contract functions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated calls to the same Wasm contract function within a `Vm` should resolve the exported `wasmi::Func` deterministically and call the same function with the same arguments, fuel synchronization, trap handling, and return-value conversion. Missing functions should still produce `MissingValue` or `VOID` according to `treat_missing_function_as_noop`, non-function exports should still be rejected, and transaction output should not depend on worker scheduling.

## Mechanism

`Vm::metered_func_call` converts `func_sym` to a `SymbolStr` and calls `wasmi_instance.get_export` on every contract function invocation. A small `Vm`-local cache keyed by `Symbol` or `SymbolStr` could store the resolved `wasmi::Func` for repeated router, pair, or token function calls within the same instantiated VM. This would avoid repeated export-table lookup and some symbol conversion work while preserving deterministic call ordering.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The accepted trace shows repeated `Vm::invoke_function_raw` and generated dispatch calls inside `applyLedger`; a workload with repeated calls to the same Wasm exported function in one transaction would hit a `Vm`-local export cache.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-323` — `Vm::metered_func_call` converts the function symbol, calls `wasmi_instance.get_export`, checks the export type, and validates argument count on every call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` allocates/marshals arguments and delegates to `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-481` — each host invocation reaches `Host::invoke_function`, which drives the VM call path.

## Evidence

Timestamp-filtered Tracy aggregation over the accepted soroswap trace confirms the VM path is in scope: `Vm::invoke_function_raw` totals **11.517 s** over 15,229 events inside `applyLedger`, and the broad generated `call` dispatch zone totals **8.072 s** over 30,432 events. The code has a specific repeated operation: export lookup is performed in `metered_func_call` every time rather than cached on the `Vm`.

## Anti-Evidence

The removable portion is only a small subset of `Vm::invoke_function_raw` self-time. The same filtered trace reports `Vm::invoke_function_raw` self-time at **517.251 ms** across the whole trace; after dividing aggregate worker time by the configured eight clusters and 70 apply windows, even deleting the entire self-time would be roughly **0.9 ms/ledger**, well below the objective's current Medium floor. The actual export-lookup subset is smaller still, and many `Vm` instances are short-lived enough that cache hit rate may be limited.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone export-handle cache

### Why It Failed

The code path is real, but it is below the objective severity threshold. Export lookup and symbol conversion are only a fraction of `Vm::invoke_function_raw` self-time, and the entire self-time category is already sub-Medium after critical-path normalization. The broader VM zones are dominated by mandatory Wasm execution, host calls, fuel accounting, argument conversion, and trap/return handling that an export cache would not remove.

### Lesson Learned

Do not promote VM-call micro-caches unless narrow measurement shows the exact removable sub-step exceeds the current ~8.4 ms/ledger Medium floor. Broad inclusive VM zones must be decomposed before attributing their time to a small lookup inside `metered_func_call`.
