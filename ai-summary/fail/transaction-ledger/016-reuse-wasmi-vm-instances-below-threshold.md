# H016: Reuse wasmi VM instances for repeated soroswap contract calls

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban VM invocation
**Severity**: Low
**Impact**: Reduce per-call Wasm instantiation overhead in soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated soroswap calls to the same Wasm code should ideally avoid rebuilding avoidable VM instantiation state while preserving per-transaction `Host`, `Budget`, storage, fuel, and frame isolation. Any cache must produce identical Wasm globals/memory state, import validation, fuel accounting, and error behavior for each contract invocation.

## Mechanism

`call_contract_fn` instantiates a fresh `Vm` for each `ContractExecutable::Wasm` call, and `Vm::instantiate_wasmi - instantiate` is visible in the current apply trace. A tempting optimization is to reuse instances or pre-instantiated wasmi state across calls to the router/pair contracts.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md`; every invoke-host-function transaction calls Wasm router/pair code and reaches `Host::instantiate_vm` before `Vm::invoke_function_raw`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:763-775` - Wasm calls instantiate a `Vm` before invoking the function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-900` - `instantiate_vm` loads from the module cache and creates a fresh VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` - `instantiate_wasmi` creates a new store and instance.

## Evidence

The current soroswap trace shows `Vm::instantiate_wasmi - instantiate` inside `applyLedger` 10,059 times, totaling 678.102 ms aggregate across workers. Timestamp filtering confirms the events are in the parallel apply window.

## Anti-Evidence

The summed per-window critical-worker time for `Vm::instantiate_wasmi - instantiate` is only 103.820 ms across 5,774.332 ms of `applyLedger` windows, or 1.8% of apply time even if the entire zone disappeared. Reusing wasmi instances is also constrained by store ownership: each instance is tied to a `Store<Host>` containing per-transaction host, budget, fuel, and storage state, and prior investigation confirmed `InstancePre` is store-bound and single-use in the pinned wasmi version.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — current-trace VM instance reuse was rechecked against the latest baseline

### Why It Failed

The current apply-window critical-path share is below the objective's Medium threshold, and the plausible reusable wasmi artifact is not available with the pinned API. Even a perfect removal of the measured instantiation zone would be a Low-severity improvement, while a correct cross-call instance cache would have to solve per-call store/host isolation.

### Lesson Learned

VM instantiation remains visible but not dominant in the current soroswap baseline. Future VM hypotheses need to target a broader part of the Wasm execution path than `instantiate_wasmi` alone, or provide a protocol-safe design that reduces actual guest/host call work rather than only instance creation.
