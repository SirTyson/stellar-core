# H002: Use a Single Object-Table Borrow for `obj_cmp` Object-Object Comparisons

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in VM object comparison and host map lookup
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When Wasm calls the host `obj_cmp` function with two object values, the host should charge exactly the same `VisitObject` budget and return the same ordering as today, but it should not borrow and validate the immutable host object table twice through nested `visit_obj_untyped` calls. Object-object comparison should load both handles under one object-table borrow, validate both handles, then compare the referenced `HostObject`s.

## Mechanism

`Host::obj_cmp` currently compares two object values by nesting `visit_obj_untyped`: first for `a`, then again for `b` (`host.rs:1224-1231`). Each `visit_obj_untyped` charges `VisitObject`, borrows the `objects` `RefCell`, translates the handle, checks bounds, and invokes a closure (`host_object.rs:460-490`). For object-object comparisons this does two independent `RefCell` borrows and repeats the handle validation path even though `Host.objects` is immutable after insertion except for append, and comparison only needs shared access to two existing objects. A specialized helper can charge two visits, borrow the object vector once, validate both handles, handle same-handle equality safely, and call `Host::compare(&HostObject, &HostObject)` without changing ordering or determinism.

## Trigger

Run the current soroswap apply-load benchmark. Soroswap contracts perform frequent map/vector lookups and comparisons over object-valued keys such as symbols, addresses, vectors, and maps. The current soroswap Tracy trace shows apply-contained `obj_cmp` zones totaling **839.771 ms** (`663.841 ms` from the Env wrapper and `175.930 ms` in VM dispatch), `visit host object` totaling **2372.465 ms** across **2,689,616** calls, and `map lookup` totaling **1321.581 ms** across **754,812** calls. The `obj_cmp` object-object path is a direct descendant of `applyLedger` through VM dispatch during `InvokeHostFunctionOpFrame::doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1231` — `obj_cmp` performs nested object visits for object-object comparison.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-490` — `visit_obj_untyped` charges, borrows the object table, validates the absolute handle, and indexes one object.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` performs the actual content ordering once both objects are available.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — map binary search repeatedly invokes host comparison logic for object-valued keys.

## Evidence

The structural inefficiency is explicit in the code: object-object `obj_cmp` is the only branch that must visit two objects, but it does so by recursively entering the one-object helper twice. The object table is a `Vec<HostObject>` behind a `RefCell`; objects are immutable once inserted, so a shared borrow of the vector can safely read both entries in deterministic handle order without changing the observed object contents. Preserving the two `VisitObject` charges before returning keeps the budget-visible behavior aligned with the current "metered by visit" contract.

The trace supports a measurable ceiling. `obj_cmp` plus `visit host object` is several seconds of aggregate apply-contained worker time in the current soroswap trace, and `map lookup`/`Compare<HostObject>` sit directly underneath the same comparison-heavy path. This is not a TX-set-construction zone: it is reached from `Vm::invoke_function_raw` -> dispatch `call` -> `obj_cmp` while `applyLedger` is active.

## Anti-Evidence

Only a subset of `visit host object` calls come from object-object comparisons; many visits are ordinary bytes/string/vector/address accesses and would not benefit. The optimization also cannot skip `VisitObject` charges or invalid-handle errors, so the PoC must preserve the current side-effect ordering: two visits are charged, relative handles still fail as internal errors, missing handles still produce the same invalid-input error shape, and content comparison still uses `Compare<HostObject>` with depth limiting. If object-object `obj_cmp` is a small minority of the 2.69M visits, the top-line improvement may fall below the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in Soroban fail/success records
**Failed At**: reviewer

### Trace Summary

The object-object path exists as described: `obj_cmp` nests two `visit_obj_untyped` calls, each of which charges `VisitObject`, borrows `HostImpl.objects`, rejects relative handles, bounds-checks the absolute handle, and then calls the comparison closure. The path is in scope for soroswap apply because VM dispatch reaches `Host::obj_cmp` from `InvokeHostFunctionOpFrame::doParallelApply` inside `LedgerManagerImpl::applyThread`. However, a correctness-preserving specialization cannot remove the expensive budget charges, handle validation, recursive `Compare<HostObject>` work, VM dispatch, or map binary-search work; it can only collapse two immutable object-table borrows into one for the subset of `obj_cmp` calls where both arguments are objects.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2484-2563` — Soroban clusters are applied on worker threads; each tx calls `parallelApply` inside the apply stage and the main thread waits on the futures.
- `src/transactions/TransactionFrame.cpp:2386-2430` — parallel apply dispatches the single Soroban operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — invoke-host operations enter `InvokeHostFunctionParallelApplyHelper` during Soroban parallel apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the helper crosses the C++/Rust bridge via `rust_bridge::invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — Rust constructs enforcing storage and a `Host`, then invokes the host function / contract.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-253` — VM-to-host dispatch returns fuel, charges `DispatchHostFunction`, marshals relative object values to host values, and calls the host function implementation.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — `Compare<Val>` delegates any object-valued comparison to `Env::obj_cmp`, while exact same-payload values already fast-path to equality before calling `obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1281` — `obj_cmp` performs nested `visit_obj_untyped` calls for object-object comparisons and then converts the resulting `Ordering` to `-1/0/1`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-504` — every untyped object visit charges `VisitObject`, borrows `objects`, rejects relative handles, bounds-checks the absolute handle, and produces the current error shape for unknown objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` performs the real content comparison under the depth limiter and recurses into vector/map/object comparisons when needed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — map lookup binary search invokes `Compare` for each probe; this is a caller of the object-comparison path but is not itself reduced by changing object-table borrow count.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1323-1325` — `Budget::charge` mutates tracker and CPU/memory dimensions; preserving the two `VisitObject` charges keeps this cost intact.
- `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs:237-267` — existing metering tests explicitly count the two `obj_cmp` visits during lookup plus the two visits for the actual object-object comparison.

### Why It Failed

The inefficiency is real but below the objective severity threshold. For valid object-object comparisons, the safe optimized shape is still: charge the first visit, validate the first handle, charge the second visit, validate the second handle, and run the same `Compare<HostObject>` content comparison with the same depth-limit behavior. That preserves consensus-visible budget/resource behavior, but it means the only removed steady-state work is one successful immutable `RefCell::try_borrow` of `HostImpl.objects` per object-object comparison.

The trace figures cited by the hypothesis are therefore not the removable cost. `visit host object` includes the two mandatory `VisitObject` budget charges and all non-`obj_cmp` object accesses; `obj_cmp` includes VM dispatch, result conversion, recursive content comparison, and small/object type handling; `map lookup` includes binary search and comparison work that remains. Even an optimistic projection that every object-object comparison saved one object-table borrow lands well below a reproducible 3% soroswap apply-time reduction, so this cannot clear the Medium floor required by the optimize-soroswap objective.

### Lesson Learned

For Soroban host micro-optimizations, separate broad Tracy zone totals from the protocol-preserving removable slice. If the visible hotspot is dominated by metering charges and recursive comparison work that must remain unchanged, eliminating one `RefCell` borrow on a subset of calls is a Low/sub-noise cleanup rather than a Medium apply-time finding.
