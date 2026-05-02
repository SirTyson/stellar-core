# H002: Immutable Host Object Read Arena for Hot `visit_obj` Paths

**Date**: 2026-05-02
**Subsystem**: soroban / rust
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in high-frequency host object reads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Reading a host object by an absolute handle should preserve the current semantics exactly: charge `VisitObject`, reject relative or out-of-range handles with the same errors, return the same immutable `HostObject`, and keep object handles deterministic. It should not require a fresh fallible `RefCell<Vec<HostObject>>::try_borrow` for every read when host objects are append-only and immutable after insertion.

## Mechanism

`HostImpl.objects` is a `RefCell<Vec<HostObject>>`, and every `visit_obj_untyped` call charges `VisitObject`, borrows the entire object vector, checks the handle, indexes the vector, and runs the caller closure. Soroswap executes millions of these reads inside the apply window, many from native SAC address conversion, event construction/externalization, host vector/map conversion, and object comparison. Replacing the object table with an append-only read arena, or adding a scoped read-access API that validates many handles under one immutable borrow, can preserve all metering and handle checks while removing repeated `RefCell` borrow machinery and improving locality on the hottest object-access paths.

## Trigger

Run the current soroswap apply-load benchmark with the Tracy trace from `ai-summary/CURRENT_STATE.md`. Each SAC transfer and Wasm host function dispatch repeatedly calls conversion helpers such as `scaddress_from_address`, `vecobject_to_scval_vec`, `from_host_val`, and comparison helpers, all of which funnel through `Host::visit_obj` / `visit_obj_untyped`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-99,228-233` — `HostImpl.objects` is stored as `RefCell<Vec<HostObject>>`, and generated borrow helpers expose one fallible borrow per access.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` — `add_host_object` appends immutable objects, but takes separate immutable and mutable borrows to compute length and push.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-490` — `visit_obj_untyped` charges `VisitObject` and then borrows/indexes the object vector for every single object read.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256,266-270` — address and vector conversion helpers repeatedly visit objects during SAC balance logic and event externalization.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:363-379` — built-in `Address::to_sc_address` and `require_auth` are representative high-frequency SAC callers of host object access.

## Evidence

The current trace confirms that this is an apply-path hotspot, not a TX-set-construction artifact. An unwrap containment check found `visit host object` totaling 2,728,946,416 ns inside the 70 `applyLedger` windows, with 3,478,780 contained visits. The aggregate self-time export also places `visit host object` among the largest non-validation zones (`host_object.rs:468`, 3,491,848 calls), and the zone body is the central object read wrapper rather than a subsystem-specific timer.

The source shows object reads are structurally read-only: `add_host_object` appends `HostObject` values and returns handles, while existing objects are not mutated in place. That makes the per-read dynamic borrow check a synchronization/safety mechanism rather than useful business logic. A safe implementation could keep deterministic handles by continuing to append in order, while exposing APIs such as `with_objects(|objects| ...)`, `visit_objs2/visit_objsN`, or an append-only arena with immutable read access so conversion-heavy paths validate multiple handles without reacquiring the `RefCell` for each handle.

## Anti-Evidence

The reviewer should not confuse this with the rejected `002-single-borrow-object-comparison.md`: that prior failure only removed one borrow in `obj_cmp` object-object comparisons and left most object visits untouched. This hypothesis must demonstrate a broad reduction in visits or borrow acquisitions across SAC conversion/event paths and generic host conversion, while still charging `VisitObject` per logical visit. The closure passed to `visit_obj_untyped` sometimes performs real conversion/comparison work, so a PoC must isolate the borrow/index portion and show that the removable slice, not the caller closure, clears the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a broad host-object read-arena change; prior Soroban records only cover narrower object-comparison, SAC address/metadata, and budget-charge slices
**Failed At**: reviewer

### Trace Summary

The hot path exists: p26 stores host objects in `RefCell<Vec<HostObject>>`, `visit_obj_untyped` is called millions of times in the soroswap apply trace, and each visit charges `VisitObject` before borrowing and indexing the object table. However, a correctness-preserving read arena or scoped borrow cannot remove most of the cited `visit host object` zone: the per-visit budget charge, relative-handle rejection, bounds/type checks, typed extraction, metered clones, recursive `Val`/`ScVal` conversion, and object comparison work must remain. After subtracting those mandatory components and Tracy-only span overhead, the removable physical work is only a cheap non-atomic `RefCell` borrow plus vector indexing plumbing, which is below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-99,188-233` — `HostImpl.objects` is a `RefCell<Vec<HostObject>>`, and generated helpers expose fallible immutable/mutable borrows for the object table.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:308-359,361-438` — handles encode absolute vs relative object-table indexes; VM boundary translation and deterministic relative-handle creation must still validate tags, bounds, and handle flavor.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-490` — `add_host_object` appends new immutable objects; `visit_obj_untyped` creates the `visit host object` Tracy span, charges `VisitObject`, borrows objects, rejects relative handles, performs bounds lookup, and invokes the caller closure.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:507-528` — typed `visit_obj` adds the required `HostObjectType::try_extract` tag check before running the caller closure.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` and `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `VisitObject` charging goes through the normal budget path and must remain per logical object visit; prior review showed the `charge` Tracy span itself is CPU-dimension instrumentation, not removable object-table borrowing.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-270,407-419,463-540` — hot address/map/value conversion paths visit objects, then perform metered clones or recursive conversion work that is part of the closure and cannot be removed by changing the object-table storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:363-379` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-180` — SAC balance and transfer paths repeatedly call `Address::to_sc_address`, which funnels through `scaddress_from_address` and `visit_obj`, but the resulting `ScAddress` classification, storage keys, authorization, and balance semantics remain required.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1282` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `obj_cmp` can nest object visits, but both logical visits, depth limiting, and `Compare<HostObject>` content comparison remain mandatory; the retained fail summary already judged a single-borrow comparison variant below threshold.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-26` — `tracy_span!` compiles to real instrumentation only with the Tracy feature, so the non-Tracy benchmark cannot count instrumentation overhead from the cited per-visit span as production savings.
- `ai-summary/fail/soroban/summary.md:44` — prior `002-single-borrow-object-comparison.md` rejected the narrower one-borrow comparison fast path as below threshold after preserving both visits and comparison work.
- `ai-summary/fail/soroban/002-zero-memory-budget-charge-fast-path.md:49-75` — prior review of the same `VisitObject`-heavy trace showed mandatory budget-charge work is a major non-removable component around host-object visits.

### Why It Failed

The hypothesis is directionally correct that existing host objects are append-only and that every `visit_obj_untyped` performs a fresh `RefCell` immutable borrow. It fails the performance objective because the proposed change does not remove whole object visits; it only removes the dynamic borrow acquisition from each visit, and perhaps one redundant borrow in `add_host_object`. To preserve p26 semantics, every logical read must still charge `ContractCostType::VisitObject`, reject relative handles, convert the handle to an index, bounds-check the object vector, verify the typed wrapper, and run the existing closure.

The cited 2.73s `visit host object` total is therefore an unsafe upper bound. It includes the required `VisitObject` budget path, closure work such as `ScAddress::metered_clone`, recursive `from_host_val` conversion for vectors/maps, `Compare<HostObject>` content comparison, and Tracy span overhead that is absent from non-Tracy headline benchmark runs. Clearing the 3% Medium floor would require recovering on the order of hundreds of milliseconds of wall time across the trace; a non-atomic `RefCell::try_borrow` plus vector lookup over roughly 3.5M visits is structurally far smaller, especially after dividing parallel-worker CPU by `NUM_CLUSTERS`. Even an aggressive 100ns saved per visit would remain below 1% wall-time improvement, and the actual removable borrow/index slice is likely lower.

The scoped-borrow variant also has limited reach. Many hot callers perform one object visit followed by real conversion, metered cloning, storage-key construction, authorization, or event work. Holding one borrow across multiple reads helps only clustered multi-handle callers, and those still need per-handle metering and validation. This makes the idea a valid micro-optimization class, but not a Medium-severity optimize-soroswap finding.

### Lesson Learned

For Soroban host-object optimizations, do not project from the full `visit host object` Tracy zone. First subtract per-visit budget charging, handle/type validation, closure conversion/comparison work, and Tracy-only instrumentation; an arena or scoped-borrow API that preserves protocol behavior can only recover the remaining physical object-table borrow/index cost, which is below the objective threshold on this workload.
