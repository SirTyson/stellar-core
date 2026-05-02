# H001: Protocol-gated host-object traversal cursor for comparison and conversion loops

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban host object execution
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by hoisting repeated host-object borrows, handle checks, and visit accounting out of recursive comparison/conversion loops
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Soroban transaction compares host objects, converts host objects to `ScVal`, or converts `ScVal` containers to host objects during `closeLedger`, the host should produce exactly the same ordering, converted values, storage keys, ledger changes, events, diagnostics, and errors as the current per-object visitor path. Under a protocol gate, the cost model may deliberately charge a new batched traversal cost, but every node must charge the same deterministic amount for the same object graph and must still reject invalid handles, mismatched tags, excessive depth, malformed maps, unsupported storage keys, and budget exhaustion deterministically.

## Mechanism

The current object-heavy hot path enters `Host::visit_obj_untyped` separately for each object node or map/vector layer. Each visit emits a `visit host object` zone, charges `VisitObject`, borrows the host object array through a `RefCell`, decodes and range-checks the handle, and then returns one object to a closure; recursive callers such as object comparison and `Val`/`ScVal` conversion repeat this for every nested object. A protocol-gated traversal cursor could borrow the object slab once for the duration of a known recursive traversal, validate handles/tags through a small cursor API, batch or explicitly redefine the visit charge for that traversal, and keep the same recursive comparison/conversion semantics.

This differs from the previously rejected standalone "batch host-object visit charges" idea: the target is not merely deleting `VisitObject` charges. The target is a combined traversal primitive for specific loops that currently pay repeated `RefCell` borrow, handle decode, object extraction, depth-check, and visitor closure overhead while walking the same object graph.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark using the Tracy trace recorded in `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`

The trigger is the steady-state router/pair Wasm execution path that performs many SDK map/vector comparisons, host-object conversions, SAC calls, storage-key conversions, event construction, and return-value conversions inside `InvokeHostFunctionOpFrame::doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` — `Host::visit_obj_untyped` performs the per-object borrow, handle validation, `VisitObject` charge, and closure dispatch repeated by every recursive traversal.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1281` — `obj_cmp` visits one or two objects and delegates recursive ordering to `Host::compare`.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` recursively compares object variants and re-enters vector/map comparison.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — `from_host_val`, `from_host_val_for_storage`, and `to_host_val` are depth-limited conversion entry points.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-540` — `from_host_obj` recursively converts host objects to XDR `ScVal`s, re-visiting nested objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-650` — `to_host_obj` recursively converts `ScVal` containers to host vectors/maps.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:302-315` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:318-346` — map iteration and `from_map_with_host` are common conversion/comparison clients.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:335-390` — vector comparison does bulk charges but still delegates per-element comparison recursively.

## Evidence

- Tracy self-time in the current soroswap trace shows `visit host object,soroban-env-host/src/host_object.rs:468` at **1,432,652,085 ns self-time** over **3,491,848 calls**. Timestamp filtering against the 70 `applyLedger` windows found **3,478,780** `visit host object` events inside `applyLedger`, so this is apply-path work rather than transaction-set construction.
- The same applyLedger timestamp filter found object-heavy descendant event totals of **1,080,609,916 ns** over **366,361** `obj_cmp` events, **726,501,061 ns** over **519,027** `ScVal to Val` events, **636,488,924 ns** over **377,067** `map lookup` events, and **386,587,986 ns** over **584,355** `map lookup indexed` events. The corresponding self-time table includes `ScVal to Val` at **293,123,796 ns**, `map lookup indexed` at **278,355,333 ns**, and `Compare<HostObject>` at **116,661,134 ns**.
- The source shows the repeated mechanism directly: `visit_obj_untyped` borrows the object array and decodes one handle per call; `obj_cmp`, `from_host_obj`, `to_host_obj`, `host_map_to_scmap`, `MeteredOrdMap` iteration, and `MeteredVector` comparison then compose many of these single-object visits inside recursive loops.
- The full filtered `applyLedger` wall-time total in the trace is **5,092,107,609 ns**. Even after normalizing aggregate worker time by the configured eight clusters, removing a moderate fraction of the object traversal overhead is plausibly above the current Medium floor (~3% of the 278.74 ms soroswap median, about 8.4 ms/ledger).

## Anti-Evidence

- Object traversal is protocol-visible through budget metering. A PoC must either preserve old `VisitObject`, `MemCpy`, `MemCmp`, and conversion charges exactly or deliberately introduce a protocol-gated cost-model change with updated resource-limit expectations.
- The broad `visit host object` zone includes many clients. The first PoC should add narrower spans or counters for the targeted recursive comparison/conversion clients; a generic cursor may not help if most visits are isolated one-off operations.
- Holding a single borrow of the host object slab across a traversal must not conflict with operations that allocate new host objects or mutate host state. The cursor should be limited to read-only traversals such as comparison and conversion-to-XDR, while `to_host_obj` construction may need a separate two-phase plan.
- This is not safe if it weakens validation. Forged handles, relative handles that should have been translated, mismatched object tags, unsupported muxed-address storage keys, malformed maps, and depth-limit failures must still be detected at the same logical boundary.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated as this combined cursor, though narrower object-comparison and visit-charge variants were already rejected
**Failed At**: reviewer

### Trace Summary

The claimed execution path exists: `Compare<Val>` delegates object comparisons to `Host::obj_cmp`, `obj_cmp` enters `visit_obj_untyped`, and recursive `HostObject::Vec`/`Map` comparison re-enters `Compare<Val>` for nested object handles. Host-object-to-XDR conversion also enters `visit_obj_untyped` through `from_host_obj` and recursively converts nested `Val`s, but `ScVal`-to-host conversion (`to_host_obj`) mostly allocates new host objects via `add_host_object` rather than repeatedly visiting existing host objects. The optimization target is therefore a real read-only traversal micro-optimization, but the measured opportunity is far below the objective's Medium threshold after cluster and ledger normalization, and most per-node work must remain for deterministic validation and metering.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` - `visit_obj_untyped` charges `VisitObject`, immutably borrows `HostImpl.objects`, rejects relative handles, range-checks the absolute handle, and only then exposes one `HostObject` to the caller.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` - `add_host_object` separately borrows and mutably appends to the object slab; this is the dominant object-slab operation in `to_host_obj`, so a read-only traversal cursor does not cover that conversion direction.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-99` - `HostImpl.objects` is a `RefCell<Vec<HostObject>>`; objects are immutable after insertion, but object addition requires a mutable borrow and cannot coexist with a long immutable traversal borrow.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1281` - `obj_cmp` visits one or two objects, then delegates real recursive ordering to `Host::compare`.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` - `Compare<Val>` fast-paths identical payloads but delegates any comparison with an object tag back to `Env::obj_cmp`, explaining recursive re-entry for vectors/maps containing object handles.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` - `Compare<HostObject>` preserves the Val comparison depth-limit checkpoint, then compares object variants or delegates vector/map recursion.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:335-390` - vector comparison already bulk-charges memory access and dispatch-like comparison overhead, then compares elements recursively; a cursor would not remove these bulk charges.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:368-418` - map comparison similarly bulk-charges entry memory access and then compares the backing vector of key/value pairs recursively.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` - Val/ScVal conversion entry points enforce depth limits; object metering is deliberately pushed into object conversion helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-540` - `from_host_obj` visits an object and recursively converts nested host values to `ScVal`, while still performing allocation, clone, storage-key muxed-address rejection, and conversion-specific charging.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-650` - `to_host_obj` recursively walks XDR values and creates new host objects, so it cannot be optimized by only holding an immutable borrow of the existing object slab.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-26` - `tracy_span!` expands to `()` without the `tracy` feature, so profiler-visible span cost in `visit_obj_untyped` is not production apply-path work.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:365-368,719-721` - `VisitObject` has a non-zero CPU cost and zero memory cost; preserving old semantics requires per-object accounting unless a protocol-gated metering change is intentionally introduced.
- `ai-summary/CURRENT_STATE.md:39-78` - the authoritative baseline is the three non-Tracy soroswap medians averaging 278.740030 ms; the Tracy trace is diagnostic attribution only.
- `ai-summary/fail/transaction-ledger/summary.md:40-52` - prior related failures establish that object-comparison single-borrowing is sub-threshold and that host-object visit-charge batching is constrained by Soroban metering semantics.

### Why It Failed

The hypothesis overstates the measurable apply-time opportunity. Its strongest number, `visit host object` self-time, is 1.432652085 s over 70 apply windows; divided across the configured eight Soroban clusters, even deleting the entire visitor span would be about 2.6 ms per ledger, below the ~8.4 ms/ledger Medium floor from the 278.74 ms baseline. The proposed cursor can only remove a subset of that already-sub-threshold number: the Tracy span disappears in non-Tracy builds, `VisitObject` accounting/handle validation/range checks must remain or be explicitly protocol-changed, vector/map bulk charges remain, `from_host_obj` still performs real cloning/allocation/conversion work, and `to_host_obj` is mostly object creation rather than object visitation. This makes the finding below the optimize-soroswap severity threshold even though the local inefficiency is real.

### Lesson Learned

For Soroban host-object traversal hypotheses, aggregate Tracy visitor counts must be normalized by both ledger count and configured cluster parallelism before projecting top-line apply-time savings. A broad profiler span around a ubiquitous helper is not enough: the removable non-Tracy work must be isolated from protocol-visible budget charges, validation, recursive comparison/conversion work, and object creation paths.
