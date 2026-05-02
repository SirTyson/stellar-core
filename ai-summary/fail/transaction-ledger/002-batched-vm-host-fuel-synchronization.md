# H002: Batch VM-host fuel synchronization at wasmi import boundaries

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM dispatch and budget accounting
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing per-host-import fuel shuttle overhead in router and pair Wasm execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When guest Wasm calls a host function during Soroban apply, Core should charge deterministic `WasmInsnExec`, `DispatchHostFunction`, and host-function-specific CPU/memory costs, enforce the same resource limits under the selected protocol, and return the same result or trap. Successful host calls should not need to reset and refill the entire wasmi fuel reservoir on every import if an equivalent budget state can be maintained. Any change to exact out-of-fuel timing or residual-fuel rounding must be protocol-gated and reflected in budget expectation tests.

## Mechanism

The generated wasmi dispatch shim returns all consumed VM fuel to the host before every host import, charges dispatch, executes the host function, then refills the VM with all remaining host budget before returning to Wasm. That means every router/pair host call pays two fuel synchronization operations, multiple `RefCell`/store accesses, fuel-to-budget conversion, a full `Budget::bulk_charge(WasmInsnExec, fuel)`, a store reset, and a refill based on `get_wasmi_fuel_remaining`.

Introduce a protocol-gated import-boundary budget mode that keeps VM fuel and host budget synchronized incrementally instead of doing a full drain/reset/refill on every import. For example, the dispatcher could charge only the delta fuel consumed since the previous import, leave unconsumed fuel in the wasmi store, and refill only when host-side budget changes reduce the permitted remaining fuel below the store's current fuel, or at frame exit/trap boundaries. This preserves deterministic single-threaded execution within each cluster and does not add workers; it reduces repeated boundary bookkeeping on the hottest router/pair Wasm path.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark from `ai-summary/CURRENT_STATE.md` and inspect the accepted trace:

`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`

Every successful swap invokes router and pair Wasm that repeatedly call host imports such as `call`, storage access, vector/map helpers, object comparisons, and SAC calls. The proposed mode should be active only while executing a VM frame under a protocol that defines the batched fuel semantics; all other paths should continue using the current full synchronization.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every generated VM-to-host import currently calls `return_fuel_to_host`, charges dispatch, runs the host function, and calls `add_fuel_to_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — `add_fuel_to_vm` requires a clean store and refills all remaining fuel; `return_fuel_to_host` bulk-charges consumed fuel then resets the store.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:327-345` — top-level `metered_func_call` performs the same full refill/return sequence around `func.call`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-303` — `get_wasmi_fuel_remaining` recomputes remaining fuel from host CPU budget at each refill and documents residual rounding behavior.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-187` — budget charge updates total CPU counts; a batched mode must still call this deterministically for `WasmInsnExec` deltas.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban transactions execute this VM path inside `InvokeHostFunctionOpFrame::doParallelApply`.

## Evidence

- Timestamp filtering confirms the dispatch target is inside `applyLedger`: generated `call,soroban-env-host/src/vm/dispatch.rs:304` totals **8,093,455,003 ns** over **30,534** in-window events, and `Vm::invoke_function_raw` totals **11,517,335,816 ns** over **15,229** events. The full Soroban operation envelope `InvokeHostFunctionOpFrame doParallelApply` totals **11,026,377,370 ns** inside the same apply windows.
- The current source performs full fuel handoff at every import. `FuelRefillable::return_fuel_to_host` calls `fuel_consumed`, `Budget::bulk_charge(WasmInsnExec, fuel)`, and `reset_fuel`; `FuelRefillable::add_fuel_to_vm` asserts the store is clean, recomputes remaining fuel from the host budget, and adds that full amount back.
- This is not the previously failed `FuelConsumptionMode::Lazy` hypothesis. That failure showed wasmi's `Lazy` mode only changes bulk memory/table operation semantics; this hypothesis targets the explicit Soroban fuel shuttle around host imports in `vm/dispatch.rs` and `fuel_refillable.rs`.
- It is also broader than rejected dispatch-trampoline and protocol-bound-check micro-optimizations. The target is the repeated budget/fuel synchronization around every import, not just generated argument marshalling or a single branch.

## Anti-Evidence

- Fuel synchronization is consensus-sensitive. The current full handoff guarantees the host sees all consumed Wasm fuel before executing any host function; a batched mode must preserve resource-limit failures or be deliberately protocol-gated.
- The broad `call` dispatch zone includes mandatory work: argument validation, relative/absolute handle translation, dispatch budget charging, host function execution, result conversion, error augmentation, and trap construction. A PoC needs narrower instrumentation for fuel-return/refill time and must show that reducing it clears the ~8.4 ms soroswap Medium floor.
- Some host calls mutate storage, emit events, or call other contracts. The first implementation should keep synchronization exact at frame boundaries, before nested VM calls, and on errors, then measure whether successful hot imports can safely use the cheaper incremental path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior fail/success records cover lazy wasmi fuel mode, export caching, compiled/AOT execution, native precompile ideas, and broader frame/argument pipeline redesigns, but not this exact import-boundary fuel drain/refill batching mechanism
**Failed At**: reviewer

### Trace Summary

The close-ledger path is real: protocol 23+ Soroban apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge into the p26 host, constructs an enforcing `Host`, enters `Host::invoke_function`, and executes Wasm contracts through `Vm::invoke_function_raw` / `metered_func_call`. At the top-level VM call, Stellar supplies all remaining host CPU budget to wasmi as fuel, calls the export, then returns consumed fuel to `Budget::bulk_charge(WasmInsnExec)`. Every generated VM-to-host import repeats a full VM-to-host return, host-function dispatch and execution, and host-to-VM refill before guest execution resumes. The bookkeeping exists on the soroswap apply path, but it is a narrow sub-slice of the broad `call` dispatch zone and cannot plausibly clear the objective's Medium threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply helper serializes invoke inputs and calls `rust_bridge::invoke_host_function`, recording returned CPU/memory/time metrics.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban operations execute through `InvokeHostFunctionOpFrame::doParallelApply` in the parallel apply phase.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-485` — p26 invocation builds enforcing storage/host state, installs auth/ledger/module-cache state, calls `Host::invoke_function`, then finishes the host.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-775` — production Wasm contract calls instantiate a `Vm`, push a `ContractVM` frame, and call `vm.invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — `metered_func_call` charges `InvokeVmFunction`, resolves the export, fills the wasmi store with remaining host budget, calls wasmi, and returns consumed fuel to the host budget.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `invoke_function_raw` allocates/marshals relative `wasmi::Value` arguments before entering the metered call path.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-297` — every generated host import clones the host from the `Caller`, checks protocol bounds, traces if enabled, calls `FuelRefillable::return_fuel_to_host`, charges `DispatchHostFunction`, marshals args, invokes the host function, marshals the result, and calls `FuelRefillable::add_fuel_to_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — `add_fuel_to_vm` requires a clean fuel store and adds `Budget::get_wasmi_fuel_remaining`; `return_fuel_to_host` charges all `fuel_consumed` as `WasmInsnExec` and resets the wasmi store.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-303,1307-1325,1428-1430` — remaining CPU budget is converted to wasmi fuel at each refill; bulk charge mutates the budget and performs limit checking.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:124-129,163-187` — budget dimensions track total consumed CPU/memory and remaining limits, and each charge updates the total count deterministically.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/store.rs:208-264,835-893` — the pinned wasmi store tracks only total and remaining fuel; `add_fuel` increases both total and remaining, `consume_fuel` decreases remaining, and `reset_fuel` zeros both.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/func/caller.rs:52-101` — host imports can inspect/add/consume/reset caller fuel, but there is no public API to set a lower remaining-fuel cap without also increasing consumed fuel.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:845-850` — normal Wasm instruction blocks consume fuel from the store's remaining counter before reaching import boundaries.

### Why It Failed

The claimed redundant handoff exists, but the projected Medium impact does not. The accepted trace has about 30.5k in-window import dispatches; clearing the objective's stated ~8.4 ms/ledger Medium floor would require roughly 4.7 s of aggregate worker-time reduction across 70 ledgers and eight clusters, or about 154 us saved per import. That would require removing more than half of the entire inclusive `call` dispatch zone, but the proposed change only targets a handful of cheap bookkeeping operations around each import: fuel counter reads, one `Budget::bulk_charge` for `WasmInsnExec`, `reset_fuel`, remaining-budget conversion, and `add_fuel`. The rest of the zone is mandatory host-function work: dispatch charging, argument validation, relative/absolute object translation, storage/SAC/vector/map operations, result conversion, tracing/error branches, and trap construction.

The proposed incremental mode also is not a simple local change. The current code deliberately resets wasmi fuel at each boundary so the host budget is authoritative before a host function runs and so host-side budget consumption reduces the next VM fuel allowance. Leaving unconsumed fuel in the store would require persistent per-frame fuel-accounting state and either a new wasmi fuel API or careful synthetic `consume_fuel` bookkeeping so host-side budget reductions are not later misreported as `WasmInsnExec`. That may be protocol-design work, but for this objective it is disproportionate to the small removable slice and remains below the Medium severity threshold.

### Lesson Learned

Broad VM import zones must be decomposed before attributing their inclusive time to fuel synchronization. In the current p26 path, import-boundary fuel drain/refill is real and consensus-sensitive, but it is a micro-slice of generated host dispatch; a viable soroswap optimization must remove a much larger portion of the VM/host execution envelope or provide narrow measurements showing fuel synchronization alone exceeds the Medium floor.
