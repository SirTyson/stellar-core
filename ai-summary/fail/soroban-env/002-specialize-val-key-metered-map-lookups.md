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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to the confirmed `LedgerKey` lookup fast path, but not a duplicate; no prior fail/success record covers a `Val`-key `MeteredOrdMap` lookup specialization
**Failed At**: reviewer

### Trace Summary

The generic `Val`-key lookup path exists as described: `HostMap` and `InstanceStorageMap` are `MeteredOrdMap<Val, Val, Host>`, and map/instance-storage reads call `get` or `contains_key`, which route through the generic fallible `find` loop. Soroswap SAC code reads `AssetInfo` and `METADATA` from instance storage, and SAC event code constructs host maps with `map_put`, so these paths are plausibly in the apply window. However, a correct specialization must still pay `charge_binsearch`, preserve the same binary-search probe order, call `Compare<Val>` at each probe, and retain all `obj_cmp`, `VisitObject`, and `MemCmp` effects for object-valued comparisons. The safely removable work is therefore only the unmetered generic wrapper/error-side-channel/safe-indexing overhead, not the dominant metered comparison and object-visit work in the cited trace.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — `find` charges the binary-search access cost, then uses the generic `binary_search_by_pre_rust_182` closure with an outer `Option<HostError>` to propagate fallible comparator errors.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — `insert` also calls `find`; specializing only `get`/`contains_key` would miss `map_put` and instance-storage writes, while specializing insert still leaves the broader map rebuild work covered by a separate failed hypothesis.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:227-300` — `get` and `contains_key` route through `find`; `get` then charges found-entry access and safely indexes the vector.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:19` — `HostMap` is exactly `MeteredOrdMap<Val, Val, Host>`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap` wraps `MeteredOrdMap<Val, Val, Host>` and is populated from contract-instance XDR using host-validated `Val` keys and values.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1697-1755` — public `map_put`, `map_get`, and `map_has` operate on `HostMap` and call `insert`, `get`, and `contains_key`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2264` — instance `put_contract_data`, `has_contract_data`, and `get_contract_data` use `s.map.insert` and `s.map.get` for `StorageType::Instance`.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — `Compare<Val>` has an exact-payload fast path but must delegate any object comparison to `Env::obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1282` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `obj_cmp` visits host objects and `Compare<HostObject>` performs metered recursive/vector/map/address/string comparisons that the proposed fast path cannot skip.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-33` and `metadata.rs:192-205` — SAC reads instance keys such as `AssetInfo` and `METADATA`, feeding the instance-storage `Val` map lookup path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:75-87` — SAC event construction uses `map_put`, exercising `HostMap` insertion and therefore `find`.
- `ai-summary/fail/soroban-env/summary.md:9-18` and `ai-summary/fail/soroban-env/001-single-lookup-sac-try-get.md:56-83` — related failures are not duplicates and reinforce that budget-visible conversion/search/comparison work cannot be treated as removable.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:9-26,44-53,88-97` — the prior validated `LedgerKey` fast path is related but distinct and measured as only a Low-severity 2.17% median soroswap improvement.

### Why It Failed

The source-level inefficiency exists, but the Medium-impact claim does not survive the code trace. The `map lookup` Tracy span includes mandatory `MemCpy` binary-search charging and all comparator work; for `Val` keys, comparator work includes the exact-payload fast path for common small symbols and full `obj_cmp` / host-object visits for object values. A specialized `MeteredOrdMap<Val, V, Host>` lookup can remove the outer `Option<HostError>`, some generic `Borrow<Q>` machinery, and a redundant safe index, but it cannot remove `charge_binsearch`, `charge_access`, `Compare<Val>`, `obj_cmp`, or the path-dependent `MemCmp` / `VisitObject` charges without changing protocol-visible behavior.

That removable subset is too small for the objective's accepted severity floor. The broader confirmed `LedgerKey` specialization affected storage, footprint, TTL, restored-key, and ledger-change maps and also skipped repeated validated-key handling, yet measured only a 2.17% average soroswap median improvement, which is Low. This hypothesis targets a narrower residual map subset and removes less per-probe work than that prior optimization. Without isolated evidence that the unmetered wrapper overhead alone exceeds the 3% Medium threshold, this is rejected as below the objective severity threshold.

### Lesson Learned

For Soroban `MeteredOrdMap` hypotheses, the `map lookup` aggregate is mostly an upper bound that includes protocol-visible metering and comparator effects. Future `Val`-map optimization hypotheses should first isolate the `MeteredOrdMap<Val, _, Host>` subset and separately measure unmetered search-wrapper overhead after subtracting mandatory `charge_binsearch`, `Compare<Val>`, `obj_cmp`, and `VisitObject` work.
