# H002: Specialize hot Val-key MeteredOrdMap lookups after the LedgerKey fast path

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic fallible-search overhead from host maps and instance-storage maps without changing comparison order or metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`MeteredOrdMap<Val, V, Host>` lookups should remain sorted, deterministic, rollback-safe, and budget-identical to the current generic lookup path. For validated host maps and instance-storage maps, lookup should avoid the generic `Borrow<Q>` / `Option<HostError>` side channel / repeated safe indexing machinery that was originally written for arbitrary fallible comparators, while preserving the exact sequence of `MemCpy`, `MemCmp`, and `VisitObject` charges and the same `Compare<Val>` ordering.

## Mechanism

After the accepted `LedgerKey` storage-map fast path, the current soroswap trace still reports a large `map lookup` aggregate under apply. `InstanceStorageMap` and contract-visible host maps are keyed by `Val` and still use the generic `MeteredOrdMap::find` closure, which charges binary-search access, stores comparator errors in an outer `Option`, returns `Ordering::Equal` to terminate after errors, then rechecks the result and indexes the vector again in `get`/`contains_key`. A `MeteredOrdMap<Val, V, Host>` fast path can use the same pre-Rust-1.82 binary-search order and call the same `Host::compare(&Val, &Val)` at each probe, but remove the generic error side channel and duplicated vector access for the common validated-map case.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) using the diagnostic trace from `ai-summary/CURRENT_STATE.md`. The trace reports `map lookup` at `soroban-env-host/src/host/metered_map.rs` with 754,812 total events, and a timestamp check showed all 754,812 events fall inside `applyLedger` windows. Soroswap drives many SAC instance-storage reads (`AssetInfo`, `METADATA`) and guest map/vector operations, leaving `Val`-key map lookup hot even after the broader `LedgerKey` storage lookup fast path landed.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — generic `find` uses a fallible closure with an outer `Option<HostError>` and generic `Borrow<Q>` abstraction for every binary-search probe.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:227-300` — `get` and `contains_key` call generic `find` and then perform another safe vector access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap` stores contract instance storage as `MeteredOrdMap<Val, Val, Host>`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2264` — instance `put_contract_data`, `has_contract_data`, and `get_contract_data` exercise `Val`-key map insert/get paths in hot SAC and Wasm contract execution.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — `Compare<Val>` already has an exact-payload fast path and delegates object comparisons to `obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1282` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — object-valued `Val` comparisons charge and visit host objects; the fast path must preserve these calls when comparisons require them.

## Evidence

- Tracy scope check: `csvexport-release -u -f "map lookup"` plus `applyLedger` window matching showed `map lookup,total=754812,in_apply=754812`, so the cited map work is in the measured apply path rather than TX-set construction.
- The accepted storage-map lookup optimization improved the validated `LedgerKey` path but was measured as Low; the current trace still has `map lookup` at 732.363 ms self-time for one line and 47.262 ms for another, indicating significant non-`LedgerKey` map work remains.
- Related comparison zones are also visible under apply: `obj_cmp` has 247,110 direct-env calls and 46,652 Wasm-dispatch calls, `Compare<HostObject>` has 77.158 ms self-time over 203,774 calls, and `visit host object` has 1.226 s self-time over 2,689,616 calls. These are consistent with `Val` map lookups comparing object-valued keys and values.
- The proposed fast path follows the same pattern as the accepted `LedgerKey` specialization: it does not change map order or skip comparator metering; it removes physical generic-search overhead around a comparator whose inputs are already host-valid in internal maps.
- Soroswap SAC event and metadata paths repeatedly read instance-storage keys such as `AssetInfo` and `METADATA`, and guest contract calls use host maps/vectors heavily (`map_new_from_linear_memory`, `vec_new_from_linear_memory`, `vec_get`, and `vec_len` are all visible in the same trace).

## Anti-Evidence

- A fast path that compares raw `Val` payloads for all cases would be wrong: object-vs-small numeric comparisons, address comparisons, and host-object ordering must still go through `Compare<Val>` / `obj_cmp` and pay the same `VisitObject` / `MemCmp` charges.
- Not all `map lookup` time is necessarily from `MeteredOrdMap<Val, V, Host>`; some comes from other key types and construction-time maps. The PoC should add focused instrumentation or compare before/after Tracy self-time to isolate the Val-key subset.
- The previous validated `LedgerKey` fast path measured only a 2.17% average soroswap median improvement despite targeting broad storage, footprint, TTL, and restored-key maps. This hypothesis clears the Medium threshold only if the remaining Val-key map subset is large enough and the generic-search overhead fraction is comparable or larger.
- Exact-budget tests may observe comparison charge counts. The implementation must preserve the binary-search probe order and call the same comparator for each probe, including error propagation behavior for invalid object handles.
