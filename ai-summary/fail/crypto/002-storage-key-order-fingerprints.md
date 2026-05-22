# H002: Order-Preserving Storage-Key Fingerprints for Soroban Map Lookups

**Date**: 2026-05-21
**Subsystem**: crypto / Soroban storage key comparison / Rust host maps
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated deep `LedgerKey`/`ScVal`/`HostObject` comparisons in hot Soroban storage maps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban enforcing storage, footprint, TTL, restored-key, instance-storage, and contract-object maps should retain exactly the same deterministic ordering, lookup results, metering outcomes, and error behavior as the current `MeteredOrdMap` implementation. Any new key prefix or fingerprint must be only an acceleration aid: equal/colliding prefixes must fall back to the existing exact comparator, and the final observable order must remain the canonical `Compare`/XDR order used today.

## Mechanism

The current post-baseline hot path still performs binary searches over `MeteredOrdMap` vectors where each probe calls the full `Compare` implementation for `LedgerKey`, `ScVal`, or `HostObject`. For soroswap, many lookups compare the same contract-data keys, SAC balance keys, and host-object map/vector keys repeatedly across `has_contract_data`, `get_contract_data`, `put_contract_data`, TTL extension, and ledger-change extraction. A protocol-gated map representation can store an order-preserving key prefix/fingerprint beside each sorted entry and compute the same prefix once for query keys; `find` compares prefixes first and invokes the existing deep comparator only when prefixes are equal or need collision disambiguation, removing a large share of repeated object walking without replacing canonical ordering.

## Trigger

Run the current soroswap apply-load case from `ai-summary/CURRENT_STATE.md`. The SAC-heavy swap path repeatedly calls `read_balance`, `receive_balance`, `spend_balance`, `write_contract_balance`, `extend_contract_data_ttl`, and instance-storage helpers; those calls build `DataKey::Balance` host values and probe the same small storage maps many times per invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — generic `MeteredOrdMap::find` binary-searches and calls `Ctx::compare` on every probe.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:318-346` — `MeteredOrdMap<Rc<LedgerKey>, V, Host>` specialization surface where a storage-key prefix/index can be added without affecting arbitrary map users.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` recursively compares vectors, maps, bytes, strings, addresses, and discriminants.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-389` and `500-514` — storage `get`, `put`, and TTL extension funnel through `StorageMap::find` / `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2317` — `has_contract_data`, `get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl` convert VM keys then probe storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-96` and `120-199` — soroswap SAC balance reads/writes repeatedly construct and probe `DataKey::Balance` entries.

## Evidence

Containment against the current trace's 71 `applyLedger` windows shows the remaining map/compare surface is still large after accepted storage-map build and lookup-fast-path work: `map lookup` + `map lookup indexed` total **1,123.771 ms** across apply-contained events, `Compare<HostObject>` totals **224.865 ms**, `obj_cmp` totals **447.394 ms**, `ScVal to Val` totals **995.922 ms**, `Val to ScVal` totals **431.617 ms**, `storage get` totals **641.711 ms**, and `storage put` totals **119.302 ms**. These are worker-aggregate Tracy totals, but even after an 8-way cluster normalization, the combined repeated comparison/conversion/probe envelope remains in Medium territory if a prefix design removes a meaningful fraction of exact comparator calls. This hypothesis is novel relative to hash-cache failures because it targets ordered-map comparison probes rather than unordered-container hashing; it is also broader than the accepted lookup fast path, which removed generic fallible-search overhead but left deep key comparison in place.

## Anti-Evidence

The existing fail summary warns that storage-map probes are often less important than host-object visit and conversion costs, and the accepted storage-map lookup specialization already captured a Low-tier win. A fingerprint scheme must not replace canonical comparison or metering semantics, must not add a crypto hash whose computation costs as much as the avoided compares, and must prove that the reduced exact-comparison count survives T=8 worker normalization. If most of the traced `ScVal to Val` / `Val to ScVal` time comes from unavoidable VM boundary value materialization rather than map-key comparison, this will fall below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related storage-map lookup and conversion hypotheses exist, but this exact order-preserving prefix/fingerprint design was not previously recorded
**Failed At**: reviewer

### Trace Summary

The SAC path does repeatedly convert `DataKey::Balance` values to storage `LedgerKey`s and then probe enforcing footprint and storage maps through `MeteredOrdMap::find`. Each `find` performs a binary search and calls the canonical `Compare` implementation for every probe, so the local inefficiency is real. However, the cited lookup/comparison/conversion zones are not independently removable by a key-prefix sidecar: conversions happen before map lookup, `obj_cmp`/`Compare<HostObject>` are broader host-object comparison surfaces, and the directly targetable lookup work runs inside the parallel Soroban worker phase and must be normalized by `T=8`.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — `MeteredOrdMap::find` charges binary-search access, then invokes `Ctx::compare` on each binary-search probe.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-242` — `insert` and `get` both funnel through `find`; `insert` then rebuilds the immutable vector map via `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` are `MeteredOrdMap<Rc<LedgerKey>, ..., Budget>`, not the `MeteredOrdMap<..., Host>` specialization cited as the storage-key insertion point.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267,693-718` — a successful enforcing storage read first probes the footprint map through `enforce_access`, then probes the storage map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-389,500-514` — writes and TTL extension reuse the same storage-map insert path and would have to maintain any sidecar during immutable map rebuilds.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:293-367` — `Compare<ScVal>` recursively compares vectors/maps/bytes and fixed-size values in canonical order.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:382-430` — `Compare<LedgerKeyContractData>` compares `(contract, key, durability)`, and `Compare<LedgerKey>` dispatches to it for contract-data keys.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:75-91,127-145` — generic vector comparison walks elements, while `Compare<Val>` delegates object comparisons to `Env::obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1281` and `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-505` — `obj_cmp` visits host objects and then calls `Compare<HostObject>`; these costs are not specific to storage-key binary search.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-165,422-443` — storage keys are built by converting `Val` to `ScVal` before probing maps; a map prefix does not remove this conversion.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` intentionally performs `has_contract_data` before `get_contract_data`, multiplying storage probes but not changing the per-probe savings ceiling.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-96,120-199,233-245` — SAC balance read/write/authorization paths repeatedly construct `DataKey::Balance` and call the storage helpers.

### Why It Failed

The proposed optimization is below the optimize-soroswap Medium severity threshold. The full cited `map lookup`/`map lookup indexed` envelope is 1,123.771 ms of aggregate worker time; normalized by the 8-way Soroban worker phase, even eliminating the entire lookup zone would be about 140 ms on the current trace, below the roughly 3% Medium floor, and a prefix sidecar can only remove a fraction of that zone because binary-search charging, vector access, error handling, insertion rebuilds, and exact fallback comparisons remain. The larger cited `Val to ScVal`, `ScVal to Val`, `obj_cmp`, and `Compare<HostObject>` numbers cannot be added to the savings estimate: conversions occur before/after lookup and broad host-object comparison zones include non-storage map users. The implementation target is also mis-scoped: durable storage maps use `Budget` context, while instance storage uses `MeteredOrdMap<Val, Val, Host>`; covering both would become a broad map-representation redesign, while covering only storage keys would miss much of the claimed host-object comparison surface.

### Lesson Learned

For Soroban storage hypotheses, size the removable work against the directly targetable map-probe fraction after parallel-worker normalization, not against summed nested Tracy zones for conversion, object visiting, and comparison. Prefix/fingerprint sidecars may be a real local cleanup, but without an isolated comparator-only measurement above the 3% apply-time floor they remain below this objective's review threshold.
