# H002: Fast-path object-object comparison with a single host-object table borrow

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host object comparison
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing repeated visit/borrow overhead in hot `obj_cmp` calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Comparing two host-object `Val`s during soroswap apply should produce the same ordering, object-handle validation errors, depth-limit behavior, and `VisitObject` budget totals as today. The common object-object path should not need to enter `visit_obj_untyped` twice, borrow the host object table twice, and nest two closure calls just to obtain two immutable `HostObject` references for one comparison.

## Mechanism

`Host::obj_cmp` handles the two-object case by calling `visit_obj_untyped(a, ...)` and then, inside that closure, calling `visit_obj_untyped(b, ...)` before `self.compare(&ao, &bo)`. Each visit opens the `visit host object` zone, charges `ContractCostType::VisitObject`, borrows the object table, validates one handle, and runs a closure. A private object-object comparison helper can preserve the same charge-before-lookup sequence for the first and second handles, but borrow the object table once and then compare both retrieved references directly, removing one borrow and nested visitor layer from every valid object-object comparison while keeping ordering and parallelism unchanged.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. Within `applyLedger` windows, `obj_cmp` occurs 293,762 times for 839.771 ms contained event time, with the hottest worker spending 57.588 ms in the zone; `Compare<HostObject>` occurs 203,774 times for 131.569 ms; and `visit host object` occurs 2,689,616 times for 2.372 s. The trigger is any soroswap swap that compares host objects while building/searching maps, checking generated contracttype values, or executing guest `obj_cmp`/map operations.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1231` — `obj_cmp` object-object branch nests two `visit_obj_untyped` calls before `Host::compare`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1233-1244` — object-small branches should remain on the existing single-object visitor path; the hypothesis is scoped to the two-object hot path.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489` — `visit_obj_untyped` charges, borrows the object table, validates one absolute handle, and calls the closure.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:130-145` — `Compare<Val>` delegates any object-involved comparison to `Env::obj_cmp`, making this branch hot under map/vector and contracttype comparisons.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` performs the actual typed comparison and depth-limit checkpoint after objects have been visited.

## Evidence

The trace scope is the measured close-ledger apply path: timestamp filtering found all cited `obj_cmp`, `Compare<HostObject>`, and `visit host object` events contained in the current trace's `applyLedger` intervals. The source shows a precise duplicated fixed overhead on the common two-object path: two immutable lookups into the same object table are performed through two separate `RefCell` borrows and nested visitor closures even though the comparison only needs both references at the same time. The hottest worker spends 57.6 ms in `obj_cmp`; if a single-borrow helper removes roughly 20% of that fixed overhead on the critical worker, the expected wall-time reduction is around the 3% Medium floor for the current soroswap median.

This is distinct from the reviewed `batch-host-object-visit-charges` hypothesis. That record targets recursive `Val` -> typed / `Val` -> `ScVal` conversion and broader `VisitObject` charge batching; this hypothesis targets the VM/environment comparison entry point itself and can preserve the exact two `VisitObject` charges while reducing object-table borrow and visitor dispatch overhead for comparisons that remain after conversion-specific optimizations.

## Anti-Evidence

Some `obj_cmp` time is real comparison work, including depth-limit checks, recursive vector/map comparison, byte/string/symbol memcmp, and budget charges that must remain. A helper that bulk-charges both visits could change budget-exhaustion versus invalid-handle error precedence, so the safer implementation should initially keep two logical charges and only collapse the object-table borrow/lookup path after preserving the current first-handle-then-second-handle validation order. The PoC must also prove that holding one immutable object-table borrow while running `Compare<HostObject>` does not conflict with any comparison branch that can allocate or mutably borrow host objects.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

`Compare<Val>` delegates any comparison involving an object to `Host::obj_cmp`, and the two-object branch in `Host::obj_cmp` currently performs two nested `visit_obj_untyped` calls before entering `Compare<HostObject>`. `visit_obj_untyped` charges `VisitObject`, borrows `HostImpl.objects`, validates the absolute handle, and then calls the closure. `Compare<HostObject>` then performs the real typed comparison, including depth-limit accounting and recursive vector/map comparison through `Compare<Val>`.

The inefficiency exists, but the proposed fast path cannot remove the expensive parts while preserving behavior. To keep current budget totals and error precedence, it must still perform two `ContractCostType::VisitObject` charges and validate both handles in order; the only non-Tracy work it removes is one immutable object-table `RefCell` borrow and one visitor/closure layer per object-object comparison.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:130-145` — exact-payload equality is already fast-pathed; any remaining object-involved comparison calls `Env::obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1281` — `obj_cmp` uses nested `visit_obj_untyped` calls for the object-object branch, retains single-visit object/small branches, and converts the final `Ordering` to the host ABI integer.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` — each visit opens the Tracy span, charges `VisitObject`, borrows the object table, rejects relative handles, checks the handle index, and only then calls the closure.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-96,188-233` — the object table is a `RefCell<Vec<HostObject>>`; the removable borrow is a cheap immutable `try_borrow` wrapper, not an allocation, copy, lock, syscall, or ledger access.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1301-1325` — each preserved `VisitObject` charge mutably borrows budget state, updates trackers, evaluates CPU/memory cost models, and checks limits.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — actual object comparison remains unchanged and covers typed comparisons, recursive map/vector comparison, byte/string/symbol memcmp, address comparison, and the depth-limit checkpoint.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:366-389` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:368-390` — vector/map object comparison recursively compares contained `Val`s and charges memory-comparison costs, so much of `obj_cmp` time is useful comparison work rather than visitor dispatch.
- `ai-summary/CURRENT_STATE.md:18-30` — current authoritative soroswap medians are about 297-313 ms, so the objective's 3% Medium floor requires roughly a 9 ms top-line improvement.

### Why It Failed

This is below the objective severity threshold. The trace attributes only 57.588 ms of Tracy-enabled critical-worker time to all `obj_cmp` work, and the hypothesis would need to remove around 16% of that entire zone to clear the current ~9 ms Medium floor. The traced code shows that the fix must preserve both `VisitObject` budget charges, both handle validations, the depth-limit checkpoint, and the full recursive comparison; it removes only one immutable `RefCell` borrow and visitor layer per two-object comparison. In non-Tracy builds, the `visit host object` span overhead disappears, and the remaining removable operation is too small to credibly produce a 3-10% apply-time reduction.

### Lesson Learned

For Soroban host comparison hypotheses, separate profiler-visible visitor spans from work that remains in production non-Tracy builds. A single-borrow helper may be a valid cleanup or micro-optimization, but it is not a Medium soroswap apply-time optimization unless it also reduces budget charging, recursive comparison, or another measured dominant cost without changing deterministic metering or error ordering.
