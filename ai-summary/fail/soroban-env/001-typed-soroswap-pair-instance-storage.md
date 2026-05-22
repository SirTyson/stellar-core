# H001: Typed Soroswap Pair Instance-Storage Fast Path

**Date**: 2026-05-21
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding generic `InstanceStorageMap` conversion, lookup, insert, and full-map reserialization for the hot pair instance
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the allowlisted Soroswap pair contract instances used by the apply-load benchmark, instance-storage reads and writes should produce the same `Val` results, missing-key errors, final `ScContractInstance.storage` map, events, and budget totals selected for the next protocol as the generic `MeteredOrdMap<Val, Val, Host>` path. The implementation should detect the known pair-instance storage layout at frame initialization, serve the known keys through a typed sidecar, fall back to the generic map for any unexpected key or contract hash, and materialize the canonical sorted `ScMap` only when the frame persists modified instance storage.

## Mechanism

Today every pair invocation that touches instance storage pays the generic path: `InstanceStorageMap::from_instance_xdr` converts every `ScMapEntry` key/value through `to_valid_host_val`, `get_contract_data(StorageType::Instance)` and `has_contract_data(StorageType::Instance)` perform generic `Val`-key map lookups, `put_contract_data(StorageType::Instance)` rebuilds a `MeteredOrdMap` through `insert`, and `persist_instance_storage` converts the entire map back to `ScMap`. Soroswap's fixed swap workload marks the pair instance read-write and modifies it on every transaction, so the generic representation is used in the hot path even though the pair storage shape is stable and small. A next-protocol typed sidecar for the known pair code hash can preserve observable storage semantics while removing the physical map rebuild/conversion work for reserve/token fields; this targets several current apply-contained zones together rather than a single sub-threshold micro-path.

## Trigger

Run `scripts/run_apply_load_matrix.py` in the current next-protocol configuration and inspect the `soroswap, TX=2000, T=8` case. `ApplyLoad::generateSoroswapSwaps` builds a fixed two-token swap, includes the pair contract instance in the read-write footprint, and alternates swap direction against the same Soroswap pair layout. The pool Wasm exports `token_0`, `token_1`, `swap`, `get_reserves`, and `k_last`, so the same instance-storage keys are exercised repeatedly by the router/pool path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:39-65` — `InstanceStorageMap::from_instance_xdr` eagerly converts the whole instance `ScMap` into generic `Val` keys and values.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2214-2283` — instance-storage `put`, `has`, and `get` route through `MeteredOrdMap<Val, Val, Host>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1210` — lazy frame initialization of instance storage from the frame's `ScContractInstance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1258-1274` — modified instance storage is persisted back into the contract instance on frame pop.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:278-288` — `instance_storage_map_to_scmap` converts every key/value back to XDR form.

## Evidence

Current accepted trace: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports apply-contained generic storage/conversion hotspots that this mechanism attacks in combination: `ScVal to Val` 429,988,065 ns / 691,521 calls, `Val to ScVal` 245,978,039 ns / 446,612 calls, `new map` 331,023,872 ns / 170,072 calls, `map lookup` 345,449,339 ns / 502,648 calls, `map lookup indexed` 408,451,716 ns / 779,242 calls, `get_contract_data` wrapper self-time 86,400,163 ns / 67,724 calls, and `put_contract_data` wrapper self-time 20,394,597 ns / 13,623 calls. Unwrap containment against the 71 `applyLedger` windows confirmed the relevant Soroban execution zones are inside the measured apply window.

This is narrower than the previously rejected "reuse initialized instance storage maps" idea: it does not cache arbitrary `InstanceStorageMap`s across frames, and it does not claim SAC balance/allowance data lives in instance storage. It targets the read-write Soroswap pair instance specifically, where the benchmark source confirms the instance is modified on every swap and must be persisted.

## Anti-Evidence

The pair storage schema must be proven exactly from the vendored pool contract or upstream source; guessing key names or value types would make this non-viable. The generic path's metering is currently protocol-visible, so the optimization must either preserve the existing charge totals/order or be explicitly next-protocol-gated with a new metering schedule. Prior storage-specialization attempts have regressed when extra cache/sidecar bookkeeping outweighed saved lookups, so the PoC must isolate the pair-instance subset before relying on the broad `ScVal to Val`, `Val to ScVal`, and `new map` aggregates.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate, but bounded by prior failed instance-storage and Val-map lookup investigations
**Failed At**: reviewer

### Trace Summary

The traced path confirms that instance storage is lazily converted from `ScContractInstance.storage` into a generic `MeteredOrdMap<Val, Val, Host>` on first frame access, then instance `get`/`has`/`put` operate through generic Val-key lookups and copy-on-write map rebuilds. On successful frame exit, any mutable instance access marks the storage modified and forces full `Val` to `ScVal` materialization before storing the updated contract instance. The Soroswap benchmark does place the pair instance in the swap transaction's read-write footprint, but the pair-instance subset is much narrower than the broad conversion, map-construction, and lookup Tracy aggregates cited by the hypothesis, and the prior accepted/fail records show those aggregates are mostly mandatory metering or unrelated call sites.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap` is a generic `MeteredOrdMap<Val, Val, Host>` plus `is_modified`; `from_instance_xdr` converts every instance `ScMapEntry` key/value through `to_valid_host_val` before `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:29-72` — `with_instance_storage` and `with_mut_instance_storage` lazily call `maybe_init_instance_storage`; any mutable access sets `is_modified = true`, so even budget-compatible typed mutation would still need to preserve persistence behavior.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2289` — instance `put`, `has`, `get`, and `del` are generic `MeteredOrdMap` operations, with `put` and `del` replacing the whole map value returned by `insert`/`remove`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,196-241` — map construction validates sorted order and charges scan/copy work; `insert` performs a metered binary search then rebuilds the vector via `from_exact_iter`; `get` performs a metered lookup and access charge.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:522-545,1196-1274` — successful frame exit persists modified instance storage, and reentrant parent frames are reloaded after persistence.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:276-288` — `instance_storage_map_to_scmap` iterates the full host map, converts keys with storage-key conversion, converts every value to `ScVal`, and emits canonical `ScMap` order.
- `src/simulation/ApplyLoad.cpp:3382-3505` — `generateSoroswapSwaps` creates `swap_exact_tokens_for_tokens` calls, marks router/token instances read-only, marks the pair contract instance read-write, and includes only two SAC balance entries plus the pair instance as the pair-specific mutable Soroban state.
- `ai-summary/fail/soroban-env/summary.md:31,43,64` — prior reviews rejected broad Val-key map and instance-storage cache projections because the cited map/conversion zones include many unrelated sites and mandatory protocol-visible metering; the objective requires Medium-or-higher projected apply-time impact.

### Why It Failed

The inefficiency is real, but the projected Medium impact is not supported. The cited `ScVal to Val`, `Val to ScVal`, `new map`, and `map lookup` totals are broad apply-contained aggregates across storage-map construction, ledger-change extraction, SAC/token/router frames, host object conversions, and generic Val maps; the Soroswap pair instance contributes only one small frame-local map per swap plus a limited number of reserve/token lookups and updates. Prior fail entries already bound the closest broader targets — all instance-storage map reuse and all Val-key map lookup specialization — below the objective's Medium threshold after isolating mandatory metering and unrelated call sites, so this narrower pair-only sidecar cannot credibly reach 3-10% apply-time reduction.

A correct sidecar would also need to preserve or intentionally recalibrate protocol-visible budget charge order for conversion, map lookup, map rebuild, and final XDR materialization. If it preserves those charges, most of the current cost remains; if it changes them, it becomes a next-protocol cost-model change coupled to a benchmark-specific contract hash and storage schema, which is not a clean general optimization. This falls below the objective severity threshold, so it is not viable for PoC.

### Lesson Learned

Contract-specific instance-storage specialization must be justified from an isolated per-contract/frame count, not from global Soroban conversion and map Tracy totals. For soroswap, the pair instance is hot enough to be visible but too narrow to beat the Medium floor once mandatory metering, full-frame persistence semantics, and prior broader storage/Val-map failures are accounted for.
