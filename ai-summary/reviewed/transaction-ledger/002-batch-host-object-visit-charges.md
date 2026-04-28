# H002: Batch host-object visit charges during recursive Val/ScVal conversions

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host object conversion
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing per-object metering and object-table borrow overhead in hot contracttype conversions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Recursive conversions between host `Val` objects and typed Rust / XDR values should charge the same deterministic `ContractCostType::VisitObject` budget totals they charge today, but they should not re-enter `Host::visit_obj_untyped`, borrow the host object table, update the budget tracker, and emit a Tracy `visit host object` span for every nested object leaf when the whole conversion is already walking a known immutable object graph. For soroswap, generated contracttype conversions and generic storage/event conversions should produce identical values, errors, and budget totals with fewer repeated metering calls.

## Mechanism

`Host::visit_obj_untyped` (`src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489`) charges `VisitObject`, borrows the host object table, decodes the object handle, and invokes a closure on every object visit. Recursive conversion code such as `Host::from_host_obj` (`src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-485`) calls this for maps, vectors, and nested objects, while generated `#[contracttype]` implementations build and unpack maps/vectors through `map_new_from_slices`, `map_unpack_to_slice`, and `Vec::try_from_val` (`src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80,171-203`). This creates a high-frequency fixed overhead independent of the useful conversion work.

A conversion-local visitor can first charge the exact number of `VisitObject` events it will perform, or accumulate a counter and flush exact repeated-single charges at conversion boundaries, then walk the object graph while holding a single immutable object-table borrow and using unchecked/internal object access for handles it has already validated. This is analogous to the reviewed `ValSer` batching hypothesis but targets `VisitObject` and object-table lookup overhead rather than XDR write chunks. It should complement, not duplicate, the SAC-specific typed balance helpers already under review: those remove one source of object visits, while this reduces the overhead of remaining generic conversions in router, pool, event, storage, and contracttype paths.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md`. In the longest `applyLedger` window, `visit host object` (`soroban-env-host/src/host_object.rs:468`) occurs **1,226,322** times for **1,074.468 ms** of worker time. Grouped by worker, the critical worker thread 4132 alone spends **212.653 ms** over 249,762 visits, while other workers spend ~119-126 ms. The trigger is any soroswap swap that converts generated contracttype values or storage/event payloads through host objects during `Host::invoke_function` and SAC/router/pool subcalls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489` - `visit_obj_untyped` charges and borrows per object visit.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` - `to_host_val` enters recursive `ScVal` -> `Val` conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-485` - `from_host_obj` recursively visits host vectors/maps and converts nested values back to `ScVal`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80` - generated struct contracttype conversions unpack/pack host maps.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:171-203` - generated enum contracttype conversions unpack/pack host vectors.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-97` - SAC balance helpers are one hot caller family that currently routes through generated host-object conversions.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242,2292-2318` - generic contract-data reads/writes reconstruct keys and values through host-object conversion paths.

## Evidence

- Tracy scope check: the cited `visit host object` events occur inside the longest `applyLedger` window and share the same worker threads as `InvokeHostFunctionOpFrame doParallelApply`, `Host::invoke_function`, and `SAC transfer`, so they are descendants of the measured parallel apply path rather than TX-set construction.
- `visit_obj_untyped` performs budget charging and object-table borrowing per visit; the comment at `host_object.rs:469-474` explicitly says each visit is small but ubiquitous, matching the trace's high call count.
- Generated contracttype code repeatedly converts maps/vectors for SAC balance keys/values and other Soroswap contract arguments. This path remains hot even after SAC-specific duplicate-read or typed-balance hypotheses, because user Wasm router/pool calls and event/storage materialization still use generic host-object conversions.
- The critical worker's `visit host object` time is ~213 ms. A batched visitor that removes even 20% of per-visit fixed overhead on that worker would save ~40 ms of apply critical-path time, enough for Medium severity on the 596 ms soroswap median.
- Determinism does not require one budget-tracker update per object handle. It requires the same total budget consumption, same object validation, same conversion result, and same error behavior. Exact repeated-single charging or chunked charging before each bounded traversal can preserve those properties.

## Anti-Evidence

- Some `visit host object` time is useful work in conversion closures, not just budget/object-table overhead. The PoC needs narrower spans or counters to isolate the removable fixed overhead.
- Budget errors are observable. A fully deferred charge could change the point at which an out-of-budget error is raised relative to a conversion error; the safer design is chunked exact charging before each bounded traversal segment or an internal visitor that preserves current error precedence.
- Holding the object table borrow across recursive conversion must not conflict with conversions that allocate new host objects or otherwise require mutable object access. The first safe target is read-only `Val` -> typed / `Val` -> `ScVal` traversal, not object-producing conversions.
- The reviewed SAC typed-balance and duplicate-read hypotheses may remove part of the same trace family. This hypothesis must show additional wins after those narrower changes or focus on non-SAC generic conversions under router/pool/event paths.
- Tracy instrumentation inflates every per-visit span in Tracy-enabled builds. Repeated non-Tracy benchmark runs must show that reducing budget bookkeeping and borrow overhead moves top-line apply time, not just profiler self-time.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated

### Trace Summary

The soroswap apply path reaches this code through `InvokeHostFunctionOpFrame::doParallelApply`, which constructs the Rust host invocation and calls `Host::invoke_function` from `e2e_invoke`. `Host::invoke_function` converts invocation arguments to host `Val`s before VM/SAC execution and converts the returned `Val` back to `ScVal`; storage host functions also reconstruct contract-data ledger keys via `storage_key_from_val`, which routes through `from_host_val_for_storage`. Those `Val` -> `ScVal` and generated contracttype conversions repeatedly call `visit_obj_untyped`, so the claimed per-object budget charge, object-table borrow, and Tracy span are on the measured closeLedger/parallel-apply path.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` - parallel apply invokes `rust_bridge::invoke_host_function` inside `InvokeHostFunctionOpFrame doParallelApply`, so the Rust host work is part of the apply critical path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-481` - constructs `Host` with enforcing storage and budget, decodes inputs, then calls `Host::invoke_function` under the `Host::invoke_function` span.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` - `InvokeContract` converts XDR args through `scvals_to_val_vec`, calls the contract, then externalizes the return value with `from_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166,407-443,463-540` - storage-key and return-value conversion enter `ScVal::try_from_val`; each object reaches `from_host_obj`, which immediately calls `visit_obj_untyped` and recurses through vectors/maps.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:266-288` - host maps are converted by iterating keys/values and recursively converting each `Val`, causing nested object visits for map entries.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` - every object visit opens a Tracy span, charges `VisitObject`, borrows the object table, validates the absolute handle, and then calls the closure.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1295-1325` - single charges update tracker state and check CPU/memory limits each time; `bulk_charge` already exists and preserves total iterations/cost for identical constant-cost visits.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-80,171-203` - generated `#[contracttype]` conversions unpack maps/vectors and then convert each field, so SAC and contract storage values route through this object-visit machinery.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-97,121-125,175-180` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/storage_types.rs:23-35` - SAC balance reads/writes convert `DataKey::Balance` and `BalanceValue` via generated contracttype implementations.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1018-1083,1096-1113,2211-2242,2292-2318` - slice-based map/vector unpack helpers and contract-data host functions use `visit_obj` and `storage_key_from_val`, confirming generic storage and contracttype paths are affected.

### Findings

The inefficiency exists. `visit_obj_untyped` performs a full budget charge and object-table `RefCell` borrow for every object node, and recursive conversion paths immediately re-enter it for every nested vector, map, address, symbol, bytes, and large integer object. The budget layer has `Budget::bulk_charge`, which evaluates identical constant-cost charges in one call while preserving the `CostTracker.iterations`, CPU, and memory totals; therefore the metered totals can be kept deterministic.

The path is hot for the objective. The traced entry is inside parallel Soroban `closeLedger`, not transaction-set construction, and SAC balance/storage helpers plus generated contracttype conversions are exercised by soroswap swaps. The aggregate `visit host object` count is large enough that even a partial reduction in budget-call and object-table-borrow overhead can plausibly clear the 3% Medium floor, provided the PoC focuses on the conversion-heavy subset and measures non-Tracy apply time.

The safe implementation scope is narrower than "change all visits globally". Object-producing `ScVal` -> `Val` conversion (`to_host_val` / `to_host_obj`) allocates host objects and should not hold a long immutable object-table borrow. The first viable target is read-only `Val` -> `ScVal` / `Val` -> typed conversion, including storage-key conversion, map/vector externalization, and generated contracttype unpacking. A global change to `visit_obj_untyped` would be risky because many host map/vector/bytes functions mutate or allocate after visiting.

Budget-error ordering is the main correctness constraint. A PoC must not simply precharge an entire unvalidated object graph if that can report budget exhaustion before an error that currently appears earlier, or vice versa. It should either batch only bounded sequences whose handles and traversal order have already been validated, or implement an internal visitor that preserves the existing charge-before-lookup semantics while reducing repeated object-table borrow/span overhead and using `bulk_charge` where the current traversal would perform a contiguous run of identical `VisitObject` charges.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs` (`from_host_val`, `from_host_val_for_storage`, `from_host_obj`, `host_map_to_scmap`, `instance_storage_map_to_scmap`) and supporting helpers in `src/rust/soroban/p26/soroban-env-host/src/host_object.rs` / `budget.rs` if needed. Consider `host.rs:map_unpack_to_slice` and `vec_unpack_to_slice` only after the read-only conversion visitor is correct.
- **Change description**: Add a private read-only conversion visitor that borrows the object table once for a conversion traversal, performs direct absolute-handle lookup for nested objects, and batches `ContractCostType::VisitObject` with `Budget::bulk_charge` only where doing so preserves current validation and error ordering. Do not change object-producing `to_host_obj` first.
- **Correctness check**: Existing conversion, storage, SAC, and budget-metering tests should continue to see identical `VisitObject` tracker iterations and identical CPU/memory budget totals. Add or run focused tests for invalid handles, wrong object tags, muxed-address storage-key rejection, and budget-exceeded precedence if the PoC changes charge timing.
- **Benchmark focus**: Measure `scripts/run_apply_load_matrix.py` soroswap apply time in non-Tracy builds before/after, with additional counters or narrow spans for `from_host_val` / storage-key conversion visit counts. The expected signal is reduced wall time in `Host::invoke_function`/parallel apply and a top-line apply-time improvement in the 3-10% range; if only Tracy span time improves, the finding should not advance.
