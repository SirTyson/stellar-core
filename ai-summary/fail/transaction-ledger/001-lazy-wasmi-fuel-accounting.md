# H001: Protocol-gate lazy wasmi fuel accounting for Soroban apply

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM execution
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing per-instruction fuel-accounting overhead in the dominant Wasm execution path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a successful Soroban invocation, the host should charge the same deterministic `WasmInsnExec` CPU amount for executed Wasm code, enforce the same transaction CPU limit under the selected protocol, and return the same ledger changes, events, diagnostics, and result values. If exact trap-at-instruction behavior cannot be preserved, the optimization should be protocol-gated so the new protocol deliberately defines the lazy fuel semantics and updates exact budget expectations accordingly. No worker scheduling or node-local timing should affect the amount charged or the point at which resource exhaustion is reported.

## Mechanism

The p26 host configures wasmi with `FuelConsumptionMode::Eager`, so the interpreter participates in fuel accounting on every metered instruction. Every VM call also shuttles all remaining fuel from host budget into wasmi before execution, then returns consumed fuel to the host after the call or at every VM-to-host import boundary. Switching the protocol to a lazy/block fuel-consumption mode, or adding a calibrated lazy mode in the pinned wasmi fork, should reduce interpreter-side accounting overhead across all router/pair Wasm execution while still charging deterministic `WasmInsnExec` totals at safe synchronization points.

This targets actual guest execution rather than the already-rejected host-dispatch micro-optimizations. The accepted trace shows the dominant apply-path work is the VM/Soroban worker envelope: `Vm::invoke_function_raw` totals 11,517,335,816 ns over 15,229 events inside `applyLedger`, `call` totals 8,072,233,108 ns over 30,432 events, and `InvokeHostFunctionOpFrame doParallelApply` totals 10,995,577,903 ns over 5,077 events in the timestamp-filtered apply windows. Even a moderate reduction in the Wasm interpreter/fuel-accounting share of this envelope can clear the current ~8.4 ms/ledger Medium floor after dividing aggregate worker time by the configured eight clusters.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and compare the accepted trace against a protocol-gated build using lazy wasmi fuel accounting. The trigger is any router/pair Wasm execution that performs many interpreted Wasm instructions and host calls during `InvokeHostFunctionOpFrame::doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` — `get_wasmi_config` enables fuel consumption and hard-codes `FuelConsumptionMode::Eager`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39` — `add_fuel_to_vm` and `return_fuel_to_host` synchronize host CPU budget with wasmi fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every VM-to-host import returns fuel to the host, charges dispatch, invokes the host function, then refills wasmi fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:327-345` — `Vm::metered_func_call` refills fuel before `func.call` and returns consumed fuel after the call.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-303` — `get_wasmi_fuel_remaining` converts remaining CPU budget into wasmi fuel for each refill.

## Evidence

- Timestamp filtering against the 70 `applyLedger` windows in the accepted soroswap trace confirmed the target zones are in scope: `Vm::invoke_function_raw` totals **11.517 s** aggregate worker time, `call` totals **8.072 s**, and the full `InvokeHostFunctionOpFrame doParallelApply` path totals **10.996 s** inside `applyLedger`.
- The source explicitly selects eager fuel mode in the p26 wasmi config; no prior transaction-ledger fail or success record mentions `FuelConsumptionMode`, lazy fuel, or a block-level fuel-accounting redesign.
- This is broader than the rejected zero-memory-budget and dispatch-trampoline hypotheses. Those targeted small host-side call-wrapper slices; this targets the interpreter's instruction-level fuel accounting across the whole router/pair Wasm workload.

## Anti-Evidence

- Fuel accounting is protocol-visible. If lazy mode reports out-of-fuel at a different instruction or rounds fuel differently, the change must be protocol-gated and tests with hardcoded budget numbers must be updated only to the new measured costs.
- The trace does not isolate eager-fuel overhead from useful Wasm interpretation. A PoC needs either wasmi-side instrumentation or an A/B build with lazy mode to prove the removable portion exceeds the Medium threshold.
- Host import boundaries still need deterministic synchronization before host functions run, so the optimization cannot simply skip `return_fuel_to_host` / `add_fuel_to_vm` without proving budget-limit behavior remains correct.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record investigates `FuelConsumptionMode`, lazy wasmi fuel, or this exact fuel-mode mechanism
**Failed At**: reviewer

### Trace Summary

The apply path is real: parallel Soroban apply enters `InvokeHostFunctionOpFrame::doParallelApply`, bridges into p26 `invoke_host_function`, calls `Host::invoke_function`, instantiates/calls a `Vm`, refills wasmi fuel before `func.call`, returns consumed fuel afterward, and repeats fuel handoff around every VM-to-host import. However, the pinned wasmi fork does not use `FuelConsumptionMode::Eager` for ordinary instruction-by-instruction accounting. Regular Wasm instruction costs are already accumulated into `ConsumeFuel` bytecode for control/basic-block regions, while `FuelConsumptionMode::{Lazy,Eager}` only changes when fuel is charged for bulk memory/table operations and only changes consumed fuel on failing bulk operations.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ Soroban apply helper calls `rust_bridge::invoke_host_function` and records returned CPU/memory metrics.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — v23+ parallel Soroban apply runs the invoke helper inside the `InvokeHostFunctionOpFrame doParallelApply` zone.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust bridge dispatches to the protocol-specific p26 host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` — p26 `invoke_host_function` builds storage/host state, calls `host.invoke_function`, then extracts ledger changes/events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-775` — Wasm contract calls instantiate a `Vm`, push a `ContractVM` frame, and call `vm.invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — `metered_func_call` resolves the export, transfers host budget into wasmi fuel, performs `func.call`, then returns consumed fuel to the host budget.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every host-function import returns VM fuel to host budget before host execution and refills VM fuel before returning to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` — p26 config enables fuel metering and explicitly selects `FuelConsumptionMode::Eager`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39` — fuel refill/return converts remaining CPU budget to wasmi fuel and bulk-charges consumed `WasmInsnExec`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/config.rs:44-89` — wasmi documents `FuelConsumptionMode` as affecting only bulk operations: memory/table grow/copy/fill and data/element init.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/translator.rs:204-219` and `:236-247` — regular metering creates/bump-adjusts `ConsumeFuel` instructions for blocks when fuel metering is enabled.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:845-850` — regular `ConsumeFuel` bytecode unconditionally consumes accumulated block fuel.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:703-739` and `:753-786` — `Lazy` vs `Eager` is only used by `consume_fuel_with`, selecting charge-before vs check-before/charge-after for wrapped bulk operations.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/tests/e2e/v1/fuel_consumption_mode.rs:55-93` — wasmi's own mode test demonstrates different consumed fuel for a failing `memory.grow`, not a reduced ordinary-instruction overhead path.

### Why It Failed

The proposed switch to wasmi `FuelConsumptionMode::Lazy` would not remove the claimed hot interpreter-side per-instruction fuel overhead. Ordinary instruction fuel is already block-aggregated through inserted `ConsumeFuel` instructions and is unaffected by `FuelConsumptionMode`; the mode only controls whether bulk-operation fuel is consumed before execution or after successful execution. For successful bulk operations it still performs fuel checking/charging, and for failed bulk operations it changes protocol-visible `WasmInsnExec` consumption and out-of-fuel behavior rather than optimizing the successful soroswap path. A broader custom wasmi redesign to coarsen or defer `ConsumeFuel` checks would be a different, unproven mechanism requiring new calibration and safety analysis, so this hypothesis as written cannot support the objective's Medium apply-time threshold.

### Lesson Learned

Do not treat `FuelConsumptionMode::Lazy` as a general lazy/block fuel-accounting mode. In the pinned soroban-wasmi fork, normal Wasm instruction metering is already represented by block-level `ConsumeFuel` bytecode; the `Lazy`/`Eager` setting is a narrow bulk-operation failure-accounting semantic knob, not a hot-path interpreter metering optimization.
