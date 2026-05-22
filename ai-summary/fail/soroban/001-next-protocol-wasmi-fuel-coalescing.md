# H001: Next-Protocol wasmi Fuel Coalescing for Soroswap Wasm Execution

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce apply-time VM interpreter overhead for Soroswap router/pool execution by coarsening wasmi fuel bookkeeping
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For successful next-protocol Soroswap transactions, Wasm execution should consume a deterministic CPU budget total for the same router and pool instruction stream, return the same values, produce the same ledger writes/events, and trap before any host-observable boundary if fuel is exhausted. p26 must keep its existing eager wasmi fuel schedule; a new protocol may define an equivalent coarser schedule that charges larger basic-block totals rather than mutating wasmi fuel counters around many individual load/store/call/entity operations.

## Mechanism

`get_wasmi_config` currently enables `FuelConsumptionMode::Eager`, and the wasmi executor calls `consume_fuel_with` or executes `ConsumeFuel` instructions inside the hot interpreter loop. For Soroswap's fixed router/pool Wasm, this means tens of thousands of VM invocations repeatedly pay fuel-counter reads/writes in `Executor::execute` even though the benchmark runs with ample fuel and successful execution reaches normal host/VM boundaries. A next-protocol translator mode could fold statically-known per-op fuel for non-growing loads/stores/calls/entities into the existing `BlockFuel` records and check/consume at `ConsumeFuel` boundaries, leaving `memory.grow`, `table.grow`, host-function dispatch fuel transfer, and resource-limiter paths exact; this reduces physical interpreter overhead without changing observable ledger state.

## Trigger

Run the current next-protocol soroswap apply-load scenario (`TX=2000, T=8`). Every successful swap invokes the Soroswap router and pool Wasms through `Host::call_contract_fn`, and the accepted diagnostic trace shows all VM execution zones for this path are descendants of `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` - current wasmi config enables eager fuel and installs calibrated per-op fuel costs.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:228-444` - hot interpreter dispatch loop that executes `ConsumeFuel` and fuel-wrapped memory/table/call operations.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:689-849` - eager/lazy fuel helpers and `visit_consume_fuel`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/translator.rs:144-154` - function-body block setup where wasmi already emits block fuel instructions.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` - Soroban host entry to raw VM function invocation.

## Evidence

Current accepted trace: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `Vm::invoke_function_raw` at 12,842,366,133 ns across 20,313 calls, `call` at 9,353,235,883 ns across 40,605 host-call dispatches, and `Vm::instantiate_wasmi - instantiate` at 1,317,542,205 ns across 20,389 calls; unwrap containment confirmed all of these events fall inside the 71 `applyLedger` windows. The failed-hypothesis record has already exhausted many host-side micro paths, but it does not record a proposal that changes wasmi's internal fuel granularity for a new protocol while preserving p26 exact metering.

The structural target is broad enough for Medium if fuel bookkeeping is a meaningful fraction of the remaining VM interpreter time: the current executor performs fuel-mode lookups and fuel counter mutations in the same loop that executes every translated instruction between host calls. Unlike host `BudgetImpl::charge` accumulators, this candidate targets wasmi fuel operations before conversion back to the host budget at VM/host boundaries.

## Anti-Evidence

wasmi's default lazy mode is not automatically a win: it checks fuel before and consumes after fallible instructions, so a naive switch from eager to lazy may add work. The PoC must add direct sub-zones or counters around wasmi fuel paths to prove the removable subset is large enough. Coarser charging also changes out-of-fuel trap timing, so this can only be next-protocol behavior and must define mandatory flush/check boundaries before host calls, returns, traps that expose diagnostics, and resource growth. If dynamic loads/stores/calls are not a large share of the Soroswap interpreter loop, the idea should be rejected below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The Soroswap apply path reaches Rust through `InvokeHostFunctionOpFrame::doParallelApply`, `rust_bridge::invoke_host_function`, `soroban_proto_any::invoke_host_function_or_maybe_panic`, and `e2e_invoke::invoke_host_function`, then calls `Host::invoke_function`, `Host::call_contract_fn`, `Vm::instantiate_vm`, and `Vm::invoke_function_raw`. The VM path is hot and wasmi fuel is transferred at host/VM boundaries, but the claimed per-load/store/call/entity eager fuel-counter mutation does not occur in the executor. In the pinned wasmi translator, those statically-known costs are already accumulated into block `ConsumeFuel` records via `bump_fuel_consumption`; `FuelConsumptionMode::{Lazy,Eager}` only selects charging behavior for bulk operations such as memory/table grow/fill/copy/init.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` — parallel Soroban apply invokes the Rust bridge with resources, ledger entries, auth, ledger info, and the shared module cache.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-450` — dispatches to the protocol-specific host module, constructs the budget, and calls protocol-agnostic e2e invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — builds host storage/auth/ledger context and executes `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-805,1124-1194` — resolves Wasm contracts, instantiates `Vm`, enters a contract frame, and calls `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218,393-411` — creates a fresh wasmi store/instance, then transfers arguments to wasmi and invokes the raw exported function.
- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` — enables fuel metering and selects `FuelConsumptionMode::Eager`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — transfers remaining host CPU budget into wasmi fuel before VM entry and charges consumed fuel back as `WasmInsnExec` after VM exit/host dispatch.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/config.rs:50-89` — documents that eager/lazy mode applies to bulk operations, not every normal instruction.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/translator.rs:144-154,217-248,491-539,1212-1320,1419-1668` — emits block `ConsumeFuel` instructions and already folds load, store, call, global, memory, table, and other entity costs into the current block fuel.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:228-444,689-849,1098-1355` — the interpreter executes `ConsumeFuel` at block boundaries; `consume_fuel_with` is used for dynamic bulk operations (`memory.grow`, fill/copy/init, table grow/fill/copy/init), not simple loads/stores/calls.

### Why It Failed

The proposed optimization target is already implemented in the pinned wasmi translator. `translate_load`, `translate_store`, `visit_call`, `visit_call_indirect`, `visit_global_get`, `visit_global_set`, `visit_memory_size`, and related entity translators all call `bump_fuel_consumption`, which adds their calibrated fuel to the current block's `ConsumeFuel` record. Therefore there are no per-operation fuel-counter reads/writes around the ordinary loads/stores/calls/entities that dominate router/pool Wasm execution for a new translator mode to remove. The remaining fuel-counter work is block-boundary `ConsumeFuel` plus dynamic bulk-operation charging, which is a different hypothesis and lacks evidence for the Medium objective threshold.

### Lesson Learned

Before proposing wasmi fuel-granularity changes, distinguish translated block fuel from eager/lazy bulk-operation charging. In this wasmi version, eager mode does not imply per-instruction fuel mutation for normal Wasm operations; the translator already coalesces static instruction costs into block fuel.
