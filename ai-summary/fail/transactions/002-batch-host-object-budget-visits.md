# H002: Batch Soroban host object visit budget charging in soroswap map-heavy calls

**Date**: 2026-04-27
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction from lowering per-object host overhead in `InvokeHostFunction` execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap contract execution should charge the same protocol budget and perform the same object handle validation, but it should not pay avoidable Rust host overhead for millions of tiny object visits when the same operation can pre-charge or batch an equivalent number of visits. Map/vector-heavy host calls should preserve deterministic budget failure behavior and return identical results while reducing repeated `Host::visit_obj_untyped` and `Budget::charge` call overhead inside `applyLedger`.

## Mechanism

`InvokeHostFunctionOpFrame::doParallelApply` enters the Rust host through `InvokeHostFunctionApplyHelper::invokeHostFunction` at `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584`, which dispatches to `src/rust/src/soroban_invoke.rs:7-38` and protocol-specific `soroban_proto_any::invoke_host_function` at `src/rust/src/soroban_proto_any.rs:310-340`. Inside the host, map/vector operations repeatedly call `Host::visit_obj_untyped` (`soroban-env-host/src/host_object.rs:460-485`), and each visit independently charges `ContractCostType::VisitObject`; map lookup also performs binary search and comparison at `soroban-env-host/src/host/metered_map.rs:168-185`. A targeted optimization that batches `VisitObject` charges in map/vector loops, or adds a checked fast path that validates object handles once and accumulates an equivalent budget charge, should reduce soroswap apply time without changing metering totals or deterministic ledger output.

## Trigger

Run the baseline soroswap workload (`soroswap, TX=4000, T=8`) and capture Tracy. Focus on successful swap invocations that exercise host maps, vectors, and SAC calls. A PoC can start by optimizing a narrow path such as `metered_map::find`/comparison or host object accessors used by map/vector dispatch, then compare `visit host object`, `charge`, and `map lookup` zones plus the top-line soroswap median apply time over repeated runs.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply path bridge into Rust host invocation.
- `src/rust/src/soroban_invoke.rs:7-38` — bridge wrapper that calls the protocol-specific host module with module cache and encoded inputs.
- `src/rust/src/soroban_proto_any.rs:310-340` and `src/rust/src/soroban_proto_any.rs:440-488` — protocol-agnostic wrapper around `e2e_invoke::invoke_host_function`, budget accounting, and result extraction.
- `soroban-env-host/src/host_object.rs:460-485` — `Host::visit_obj_untyped` charges and resolves a host object for every visit.
- `soroban-env-host/src/host/metered_map.rs:168-185` — `MeteredMap::find` performs charged binary-search lookup and repeated comparisons that drive object visits in map-heavy contract code.
- `soroban-env-host/src/budget/dimension.rs:176` — `BudgetDimension::charge` is the hot budget-charge site reached by each visit.

## Evidence

The current soroswap trace has `invoke_host_function` under `applyLedger`: unwrap verification found `1494` events inside `applyLedger` with `4614.564 ms` cumulative threaded time. In those same `applyLedger` windows, `visit host object` accounts for `1104.961 ms` across `1,190,561` calls, `charge` accounts for `795.018 ms` across `8,299,120` calls, and `map lookup` accounts for `619.797 ms` across `334,490` calls. The self-time export also ranks these Soroban host zones among the top apply-relevant hotspots: `visit host object` at `641.141 ms` self, `map lookup` at `403.316 ms` self, and `charge` at `826.793 ms` self across the full trace. This is a soroswap-specific profile shape: swaps are map/vector/object heavy and repeatedly traverse host objects inside contract execution, so reducing per-visit overhead has a plausible 3-10% top-line apply-time impact.

## Anti-Evidence

Budget exhaustion timing is consensus-observable through transaction success/failure, so batching cannot simply defer charges past side effects or alter the exact total cost. Any fast path must either pre-charge before performing the batch or prove that the intermediate operations cannot produce observable side effects before the next budget check. The hot host source is vendored through `rs-soroban-env`, so the implementation may require a dependency patch or upstreamable change rather than a small stellar-core-only edit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban apply path reaches the claimed target through `InvokeHostFunctionOpFrame::doParallelApply`, which constructs an `InvokeHostFunctionParallelApplyHelper`, calls its common `apply()` helper, and crosses the C++/Rust bridge into the protocol-selected Soroban host. The host invocation creates a budget, runs `e2e_invoke::invoke_host_function`, and reports consumed CPU/memory back to Core, so `visit_obj_untyped` and map/vector host functions are directly inside the apply critical path. The per-visit charge is real: every `visit_obj_untyped` charges `VisitObject` before borrowing and validating the object table, and map/vector env functions call it for each map, vector, or object comparison. However, batching those charges generally would change the ordering between budget exhaustion and object-handle/type validation, while the narrow cases that can be batched safely are too small and scattered to satisfy this objective's Medium severity threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — `InvokeHostFunctionApplyHelper::doApply` runs footprint loading, host invocation, storage change recording, event collection, refundable-resource consumption, and success finalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` is the v23+ parallel Soroban apply entry point used by soroswap transactions.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `InvokeHostFunctionApplyHelper::invokeHostFunction` serializes auth/resources/ledger inputs and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` — the bridge selects the protocol-specific host module and dispatches to its `invoke_host_function` function.
- `src/rust/src/soroban_proto_any.rs:391-488` — protocol wrapper constructs `Budget`, executes `e2e_invoke::invoke_host_function`, then reads consumed CPU/memory and extracts results/events/ledger changes.
- `rs-soroban-env@e527f43/soroban-env-host/src/host_object.rs:460-505` — `visit_obj_untyped` charges `VisitObject` before borrowing the object table, rejecting relative/unknown handles, and invoking the caller closure.
- `rs-soroban-env@e527f43/soroban-env-host/src/host_object.rs:507-528` — typed `visit_obj` delegates to `visit_obj_untyped` and additionally rejects mismatched object tags.
- `rs-soroban-env@e527f43/soroban-env-host/src/host.rs:1625-1733` — map host functions visit the map object, then perform `HostMap` get/insert/remove/scan operations.
- `rs-soroban-env@e527f43/soroban-env-host/src/host.rs:1860-2051` — vector host functions visit the vector object, then perform vector access/mutation/search operations.
- `rs-soroban-env@e527f43/soroban-env-host/src/host/metered_map.rs:168-194` — `find` charges binary-search memory access and compares probe keys with the lookup key.
- `rs-soroban-env@e527f43/soroban-env-common/src/compare.rs:127-145` and `rs-soroban-env@e527f43/soroban-env-host/src/host.rs:1231-1289` — `Compare<Val>` delegates object comparisons to `obj_cmp`, which visits one or two objects.
- `rs-soroban-env@e527f43/soroban-env-host/src/budget.rs:1292-1316` and `src/budget.rs:234-282` — bulk charging exists, but it charges/checks the whole batch at one point rather than preserving each individual charge/check boundary.

### Why It Failed

The inefficiency exists, but the proposed fix is not viable at the required objective severity. A general "batch `VisitObject` charges" optimization would have to charge before validating all objects in the batch or validate objects before charging them; either ordering differs from the current `visit_obj_untyped` contract, which charges first and only then reports relative, unknown, or mistagged object errors. Preserving exact failure order forces either the existing per-object charge sequence or a very narrow helper for cases where no observable validation/error can occur between visits.

Those narrow helpers do not project to a Medium-tier soroswap apply-time improvement. Most map/vector env calls in the hot path perform a single object visit for the container, so there is no intra-call batch to form; two-object opportunities such as `obj_cmp` and `vec_append` can at best collapse one `VisitObject` budget call while still resolving both handles and running the comparison. The trace's cumulative `visit host object`/`charge` totals are real hot-path cost, but this specific batching mechanism cannot remove most of that work without weakening budget/error ordering, and the safe remainder is below the 3-10% apply-time floor.

### Lesson Learned

For Soroban host metering, a hot `charge` or `visit_obj_untyped` zone is not automatically batchable: the point at which the host charges budget is part of the deterministic failure path for invalid handles and exhausted budgets. Future hypotheses should target a concrete operation that can pre-prove object validity and absence of intervening observable failures, or optimize the implementation cost of a single charge/visit without changing where checks occur.
