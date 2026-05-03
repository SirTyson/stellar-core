# H002: Host Transient Allocation Arena for Soroban Invocation Objects

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing allocation and copy churn in host object/map/value construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban host invocation should expose the same immutable object handles, storage values, return values, events, and budget totals as the current baseline. Host objects and `MeteredOrdMap` values must remain valid for the lifetime of the host invocation, and all state must be cleared before the next transaction so no cross-transaction data can be observed. Any allocator or arena reuse must preserve deterministic execution and must not reduce protocol-visible metering unless gated to a new protocol.

## Mechanism

The current host constructs fresh allocation-backed containers for every invocation: `Host::with_storage_and_budget` starts with an empty object table, `Host::add_host_object` pushes nearly one million objects across the trace, and `MeteredOrdMap::from_exact_iter` collects new vectors for maps built during value conversion and guest linear-memory imports. The current soroswap trace reports in-scope self-time for `ScVal to Val` (429,988,065 ns / 691,521 calls), `new map` (331,023,872 ns / 170,072 calls), `add host object` (270,971,092 ns / 935,719 calls), and `Val to ScVal` (245,978,039 ns / 446,612 calls); all of these events fall inside `applyLedger`. A host-scoped transient arena or thread-local reusable host allocation bundle could keep capacity for object tables, small map backing vectors, relative-object tables, and conversion scratch buffers across invocations while still charging the same metered clone/allocation costs logically.

## Trigger

Run the current soroswap apply-load benchmark with the accepted next-protocol baseline. Normal swap execution repeatedly converts XDR `ScVal` storage/event/argument values into host objects, builds small host maps and vectors, crosses VM linear memory for host calls, and drops all physical allocations at the end of each host invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-107,351-366` — `HostImpl` owns the per-invocation object table and `Host::with_storage_and_budget` constructs it empty for every transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:443-457` — `Host::add_host_object` appends every newly converted object to the per-host object vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:140-160` — `MeteredOrdMap::from_exact_iter` collects a fresh `Vec<(K,V)>` and charges the clone before validating map order.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — `from_host_val` and `to_host_val` drive the hot `Val`/`ScVal` conversion paths that allocate host objects and maps.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:46-65` — `InstanceStorageMap::from_instance_xdr` converts instance-storage maps into host `Val` maps using the same allocation-heavy conversion surface when instance storage is first accessed.

## Evidence

The current diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `ScVal to Val` at 429,988,065 ns self-time, `new map` at 331,023,872 ns, `add host object` at 270,971,092 ns, and `Val to ScVal` at 245,978,039 ns. Unwrap overlap checks showed these zones are entirely inside `applyLedger`, not TX-set construction. The structural pattern is allocation churn rather than consensus-required semantics: physical `Vec` capacity and scratch storage are discarded at host teardown even though the next transaction on the same worker thread repeats the same object/map shapes.

## Anti-Evidence

The visible Tracy zones include real conversion, comparison, and metering work, not only allocator overhead; an arena must be measured end-to-end rather than claiming the whole aggregate is removable. Reusing host allocation storage is also safety-critical because object handles, relative handles, events, auth state, and storage maps must never leak across transactions. The safest PoC should start with capacity reuse for strictly host-private buffers while preserving all logical metering calls; if capacity reuse alone is below Medium, broader arena work should be rejected rather than expanded into a risky semantic refactor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`
**Failed At**: reviewer

### Trace Summary

The apply path reaches the target through `LedgerManagerImpl::applyTransactions`, the parallel Soroban phase, `InvokeHostFunctionOpFrame::doParallelApply`, the C++/Rust bridge, `soroban_proto_any::invoke_host_function_or_maybe_panic`, and p26 `e2e_invoke::invoke_host_function`. The claimed allocation surfaces are real: each host invocation constructs a fresh `HostImpl` with an empty `objects` vector, object-valued `ScVal` conversions push into that vector, and map/vector builders allocate backing `Vec`s. However, the cited Tracy zones are broad host conversion/building zones, not isolated allocator cost: preserving deterministic behavior and logical metering leaves most of their work in place.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` loads Soroban config, builds parallel stages, and calls `applySorobanStages` from the measured close-ledger apply path.
- `src/ledger/LedgerManagerImpl.cpp:2483-2574` — worker threads call each Soroban transaction's `parallelApply` and the apply thread waits on the resulting futures.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018,1358-1378` — parallel invoke-host apply loads the footprint, invokes the Rust host, records returned storage changes, consumes refundable resources, and finalizes the result.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ serializes auth/resources/source/ledger-entry inputs and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-61` — bridge entry dispatches to the protocol-specific host module.
- `src/rust/src/soroban_proto_any.rs:391-490` — protocol wrapper builds the `Budget`, calls p26 host invocation, then reads consumed CPU/memory and serializes output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — p26 host invocation decodes resources, builds footprint/storage maps, constructs `Host::with_storage_and_budget`, invokes the host function, finishes the host, and computes ledger changes/events.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-107,351-366` — `HostImpl` owns `objects: RefCell<Vec<HostObject>>`, and every new `Host` starts that vector with default empty capacity.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:443-457` — `add_host_object` computes a handle, performs the logical heap-allocation budget charge, injects the typed object, and pushes into the host object vector.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:308-338,361-438` — relative-object handles deliberately isolate each VM frame; relative tables are per-frame and cannot be reused without clearing all observable handles.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443,463-657` — `from_host_val`/`to_host_val` perform recursive conversions; object-valued `ScVal`s still require cloning/converting substructure and calling `add_host_object`.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:419-613` and `src/rust/soroban/p26/soroban-env-common/src/object.rs:124-199` — only object-classified `ScVal` values cross into host object allocation; small values bypass it.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,196-224,357-365` — `MeteredOrdMap` is backed by a `Vec`, but construction still charges scan/clone costs and validates sorted unique keys; insert/replace rebuilds are logical immutable-map behavior, not just capacity churn.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:110-132,397-407` — `with_metered_capacity` and `Vec` clone charging intentionally charge heap allocation and shallow copy independent of physical allocator reuse.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-65,230-238` — storage and instance storage use `MeteredOrdMap`; instance storage conversion walks XDR map entries and converts each key/value into `Val`s before building the host map.

### Why It Failed

The inefficiency exists, but the accepted objective requires a Medium-or-better apply-time reduction and the trace does not support that once the removable slice is isolated. `add_host_object` self-time is only about 271 ms across 935,719 calls in the supplied aggregate trace, and capacity reuse would remove at most physical `Vec` growth/allocation/free work; it would not remove handle calculation, object injection, `RefCell` borrows, the push itself, or the required `charge_heap_alloc` logical metering. Similarly, `ScVal to Val`, `Val to ScVal`, and `new map` include recursive conversion, XDR/value cloning, metered charges, binary ordering checks, map scans, and immutable-map rebuild semantics; those must remain unless the protocol-visible metering and host object model are redesigned.

The proposed arena also lacks a correctness-preserving narrow implementation that can plausibly clear 3%. Host object handles are absolute indices into a per-invocation table, relative object tables intentionally isolate VM frames, and map/vector buffers are owned by immutable `HostObject` values until `Host::try_finish` consumes the host. Reusing only top-level capacities is a low-level allocator cleanup; reusing nested `HostMap`, `HostVec`, `ScBytes`, `ScString`, and relative-object storage would require invasive custom storage/drop semantics and must still zero or overwrite all cross-transaction state while replaying the same logical metering. That combination makes the safe, measurable subset below the optimize-soroswap Medium threshold, while the broader arena refactor is too speculative for this hypothesis.

### Lesson Learned

Do not project arena wins from whole conversion-zone self-time. For Soroban host allocation hypotheses, first separate allocator capacity growth/free from conversion, metering, comparison, immutable-container rebuild, and handle-isolation work; capacity reuse by itself must clear the objective threshold before considering a risky host-object storage redesign.
