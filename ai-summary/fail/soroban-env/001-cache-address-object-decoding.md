# H001: Cache Immutable AddressObject Decodes in Hot SAC Paths

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated host-object table visits and address clones in SAC transfer/auth/storage/event code while preserving explicit metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC transfer, balance, authorization, and event code should resolve every `AddressObject` to the same `ScAddress` as today, emit the same events, update the same ledger entries, and report the same budget counters. Repeated reads of an immutable address object during a single host invocation should not repeatedly borrow the host object table and re-run the same type extraction when the object handle and decoded `ScAddress` cannot change.

## Mechanism

`Address` currently stores only a `Host` clone plus an `AddressObject` handle, and `Address::to_sc_address()` calls `Host::scaddress_from_address()` every time (`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-379`). That conversion goes through `Host::visit_obj(address, |addr: &ScAddress| addr.metered_clone(self))`, which charges `VisitObject`, borrows the object table, decodes the handle, checks the object variant, and clones the same immutable `ScAddress` (`src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256`; `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528`). The SAC transfer path repeatedly asks for the same addresses while authorizing, checking balances, updating balances, classifying issuer transfers, and constructing transfer events (`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225`; `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-229,233-246`; `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62`).

The optimization would add a per-host cache keyed by absolute `AddressObject` handle for decoded `ScAddress` values, or an equivalent lazy cache in the SAC `Address` wrapper. Cache hits would still explicitly charge the same `VisitObject` and `ScAddress::metered_clone` budget as the current path, but would skip the physical object-table borrow, handle-to-index lookup, enum extraction, and repeated full object visit. Because host objects are immutable for the host lifetime, the cached decode is deterministic and cannot change ledger output or authorization behavior.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and inspect the SAC-heavy invoke path. A PoC should cache decoded address objects for the duration of one `Host`, keep exact budget tracker output for representative SAC transfers, and confirm that median non-Tracy soroswap apply time falls by at least 3% across repeated runs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — generic object visit path whose self-time is dominated by repeated physical handle lookup/type extraction.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — `scaddress_from_address` always visits the object table and clones the stored address.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-379` — `Address` stores only the object handle, so repeated `to_sc_address` calls cannot reuse a prior decode.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:475-499` — `MuxedAddress::address()` and `MuxedAddress::id()` add more repeated address-object work on transfer arguments.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — hot SAC transfer entrypoint.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-229,233-246` — balance and authorization helpers repeatedly decode the same `Address`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62` — transfer event classification compares issuer addresses after more address decoding.

## Evidence

The current reference soroswap trace is `/mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `visit host object,soroban-env-host/src/host_object.rs,468,1339666074,...,2415043,...` and timestamp intersection shows 2,355,082 of 2,415,043 `visit host object` events, totaling 2.316 s of event duration, inside `applyLedger` windows. The same trace reports `SAC transfer,soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs,212,215397936,...,5971,...`, with 5,826 SAC transfer events inside `applyLedger`, confirming this is not TX-set construction. The code shows that SAC transfer invokes multiple helper layers that repeatedly call `Address::to_sc_address()` or address comparison on immutable handles.

## Anti-Evidence

The cache must not suppress `VisitObject` or clone metering: the PoC needs exact budget-counter equivalence, likely by charging the same costs on cache hits before returning a clone of the cached address. The projected win also depends on a high address-cache hit rate; if most `visit host object` self-time in soroswap comes from vectors, maps, byte strings, or non-address values, this optimization may fall below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; the prior soroban-env fail records cover Tracy-only overhead, wasmi instantiation, TTL extension, XDR metering/serialization, parallel-apply setup, budget templates, bridge XDR roundtrips, and output-buffer preallocation, not address-object decode caching
**Failed At**: reviewer

### Trace Summary

The repeated address decode path exists: SAC `transfer` converts the muxed recipient to an `Address`, then `spend_balance`, `receive_balance`, and `is_authorized` call `Address::to_sc_address()` on the same logical handles. `to_sc_address()` delegates to `Host::scaddress_from_address()`, which calls `visit_obj` and clones the stored `ScAddress`. However, an exact-budget cache must still perform the `VisitObject` charge and the `ScAddress::metered_clone` charge, and the cited `visit host object` Tracy zone covers all object types plus the closure body and profiling instrumentation, not just address-table lookup. The removable work is only a `RefCell` borrow, handle/index check, vector access, and enum match, likely replaced by an equivalent cache lookup, so it does not support a Medium objective projection.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-385` — `Address` contains only `Host` plus `AddressObject`; `to_sc_address()` always calls `Host::scaddress_from_address`, while `MeteredClone for Address` is charged as a shallow 16-byte clone.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — `scaddress_from_address` is exactly `visit_obj(address, |addr: &ScAddress| addr.metered_clone(self))`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — `visit_obj_untyped` emits the Tracy span, charges `ContractCostType::VisitObject`, borrows `objects`, validates absolute handle/index, and then runs the typed extraction/closure.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-280,365-368,1323-1325` — every preserved `VisitObject` charge mutably updates budget trackers and CPU/memory dimensions; the default CPU const term is 61 and must remain visible.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:190-255,331` and `src/rust/soroban/p26/soroban-env-host/src/host/declared_size.rs:155` — `ScAddress::metered_clone` charges `MemCpy` for a declared 48-byte shallow copy before cloning; cache hits cannot skip this without changing reported budget.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer calls `to_mux.address()`, `from.require_auth()`, `spend_balance`, `receive_balance`, and transfer-event classification.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-246` — balance and authorization helpers decode `Address` to branch on account vs contract, so repeated calls are real, but they also perform storage, authorization, and balance work around the decode.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1282` — issuer/event comparisons visit objects through `obj_cmp`, but they do not benefit from caching `scaddress_from_address` results because they compare host objects directly.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-26` — `tracy_span!` is compiled out without the Tracy feature, so event-duration evidence from `visit host object` must not be treated as directly removable production work.

### Why It Failed

The hypothesis confirms a small repeated operation, but it does not clear the optimize-soroswap Medium severity floor. To preserve exact Soroban metering, a cache hit must still execute the dominant protocol-visible costs on this path: `Budget::charge(VisitObject, None)` and `ScAddress::metered_clone`, including the `MemCpy` charge. It can only skip the physical object-table borrow/index/type extraction, and a per-host cache would introduce its own borrow and lookup while a lazy `Address` cache would enlarge an internal type currently metered as a 16-byte shallow clone. The profiling evidence is also too broad: `visit host object` includes non-address objects, object comparisons, closure work, budget charges, and Tracy instrumentation that is absent in production builds. This makes any realistic saving far below the 3% apply-time threshold; under the objective rule, Low/sub-threshold optimizations are NOT_VIABLE.

### Lesson Learned

For Soroban object-visit optimizations, first subtract mandatory metering, clone charges, closure work, non-target object types, and Tracy-only instrumentation before projecting impact. A cache that preserves budget equivalence can only remove unmetered physical lookup work, which is usually too small to justify promotion unless instrumentation isolates that exact subcomponent above the objective threshold.
