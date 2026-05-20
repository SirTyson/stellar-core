# H001: Protocol-gated VM fuel settlement to reduce wasmi budget synchronization

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban VM execution
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by restructuring deterministic Wasm instruction metering in the dominant `InvokeHostFunction` worker path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban Wasm execution should enforce deterministic CPU instruction limits, stop before applying host-side ledger effects after the budget is exhausted, and produce the same ledger changes, events, authorization decisions, and traps for every node. On a next-protocol path, the host should be able to settle Wasm fuel consumption into the Soroban `Budget` at coarser, deterministic boundaries while preserving a fuel check before each host import and before returning from VM execution.

## Mechanism

The current VM path repeatedly moves budget state between the host `Budget` and wasmi fuel: `Vm::metered_func_call` adds fuel before every function call and returns remaining fuel afterward, while every generated import wrapper returns fuel to the host, charges `DispatchHostFunction`, executes the host call, and refills VM fuel before resuming. This keeps p26 metering exact but creates frequent host-budget synchronization on the hottest soroswap path. A protocol-gated settlement mode could keep wasmi's deterministic block fuel checks active, but replace per-boundary full budget synchronization with a VM-local fuel window and explicit settlement/checkpoints at VM-call entry, host-import entry, host-import return, and VM-call return, reducing synchronization and budget-borrow overhead without increasing parallelism or reordering effects.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
Each successful swap applies through `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> TransactionFrame::parallelApply -> InvokeHostFunctionOpFrame::doParallelApply -> rust_bridge::invoke_host_function -> Vm::invoke_function_raw`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-345` — `Vm::metered_func_call` charges `InvokeVmFunction`, resolves the export, refills wasmi fuel before `func.call`, and returns fuel to the host after the call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:205-296` — generated host-import wrappers return VM fuel, charge `DispatchHostFunction`, marshal arguments, execute the host call, marshal results, and refill fuel for every imported host function.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-580` — accepted baseline invokes the host function inside the apply path, then finalizes storage/events and ledger changes after VM execution.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` and `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — C++ apply helper calls Rust and only commits ledger effects after Rust returns success, providing a deterministic failure boundary for resource-limit errors.

## Evidence

- The current self-time CSV reports apply-descendant VM zones: `Vm::invoke_function_raw,soroban-env-host/src/vm.rs:400` at **696,879,003 ns self-time** over **20,313** calls, generated host-import `call,soroban-env-host/src/vm/dispatch.rs:304` at **922,554,179 ns self-time** over **40,605** calls, and `charge,soroban-env-host/src/budget/dimension.rs:176` at **1,758,199,707 ns self-time**. The inclusive `Vm::invoke_function_raw` total is **12,842,366,133 ns**, and the inclusive generated `call` total is **9,353,235,883 ns**.
- Prior failures ruled out the existing `FuelConsumptionMode::Lazy` knob and narrow import-boundary fuel batching. This hypothesis is different: it proposes a protocol-gated metering-mode redesign that keeps deterministic wasmi fuel checks but changes when host budget state is synchronized, not merely replacing an unavailable config option or deleting one refill call.
- The target is inside `applyLedger`, not TX-set construction: the Rust VM call is reached only from `InvokeHostFunctionOpFrame::doParallelApply` in the parallel Soroban apply workers.

## Anti-Evidence

- Per-import fuel drain/refill alone was previously judged too small; the PoC must instrument the exact time spent in `add_fuel_to_vm`, `return_fuel_to_host`, `Budget::charge`, and `RefCell` budget borrows before claiming the inclusive VM/import totals.
- Changing CPU metering is protocol-visible. A viable design must be next-protocol-only, update budget observations deliberately, and preserve deterministic failure before any host import whose execution would not have occurred under the old exhausted-fuel state.
- The implementation may require changes in the pinned wasmi fork rather than only stellar-core wrapper code. If wasmi cannot expose a safe settlement/checkpoint API, the hypothesis fails as a design-integration problem rather than a local optimization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-batched-vm-host-fuel-synchronization`
**Failed At**: reviewer

### Trace Summary

The apply path reaches this code through `LedgerManagerImpl::applyThread`, `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, `InvokeHostFunctionParallelApplyHelper::invokeHostFunction`, `rust_bridge::invoke_host_function`, `Host::invoke_function`, `Host::call_n_internal`, and `Vm::invoke_function_raw`. The VM wrapper supplies fuel to wasmi before exported-function execution and returns consumed fuel to the host afterward; every generated host-import wrapper does the same return/charge/refill sequence around the imported host function. This is the same mechanism already failed as `002-batched-vm-host-fuel-synchronization`: batching or protocol-gating the per-import fuel drain/refill targets only cheap bookkeeping while mandatory dispatch charging, argument conversion, host execution, result/trap handling, and object translation remain.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — parallel Soroban worker invokes `parallelApply` for each transaction in the cluster.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` — C++ helper calls `rust_bridge::invoke_host_function` and treats unsuccessful Rust output as resource-limit/trap failure before recording any storage changes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — ledger effects, events, refundable resources, and success finalization occur only after Rust invocation succeeds.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ parallel apply constructs the helper that reaches the Rust host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — enforcing-mode invocation builds the host, calls `Host::invoke_function`, then only extracts storage/events after execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `HostFunction::InvokeContract` enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-987` and `1113-1121` — contract call path enforces reserved-function/reentry checks before dispatching to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — Wasm contracts instantiate a VM and execute `Vm::invoke_function_raw` inside a contract VM frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-345` — `metered_func_call` adds fuel before `func.call` and returns consumed fuel to the host after the call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:205-296` — each generated host-import wrapper returns VM fuel, charges `DispatchHostFunction`, marshals args/results, calls the host function, handles traps, and refills fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39` — `add_fuel_to_vm` reads remaining host CPU budget and `return_fuel_to_host` performs `bulk_charge(WasmInsnExec)` plus `reset_fuel`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-303` — `BudgetImpl::charge` updates trackers, dimensions, and limits; `get_wasmi_fuel_remaining` converts remaining CPU budget to fuel.
- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-139` — wasmi is configured with fuel consumption enabled and `FuelConsumptionMode::Eager`.

### Why It Failed

This hypothesis is substantially equivalent to the prior failed `002-batched-vm-host-fuel-synchronization` record: both propose reducing the per-import `return_fuel_to_host` / `add_fuel_to_vm` round trips while preserving host-call order and deterministic metering. The new wording adds protocol gating and a VM-local settlement window, but the target and removable work are the same import-boundary fuel bookkeeping already judged below the optimize-soroswap Medium threshold. The traced code confirms the broad `vm/dispatch.rs` and `Vm::invoke_function_raw` timings include mandatory host-call work that this design cannot remove.

### Lesson Learned

Protocol-gating can make metering changes consensus-safe, but it does not change the performance ceiling of a micro-slice. Future VM metering hypotheses need narrow measurements showing removable fuel/budget bookkeeping alone clears the 3% apply-time floor, or they must target a larger mandatory-cost reducer than import-boundary fuel synchronization.
