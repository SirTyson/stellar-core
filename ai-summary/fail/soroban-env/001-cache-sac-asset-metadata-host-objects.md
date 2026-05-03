# H001: Cache SAC asset metadata (name/symbol) StringObjects within a host invocation

**Date**: 2026-05-03
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3–5% soroswap apply-time reduction projected (per-SAC-event metadata read removed from hot path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the SAC `transfer`, `mint`, `burn`, `approve`, `clawback`, `set_authorized`,
or `set_admin` event constructors call `read_name(e)` (and indirectly
`read_asset_info(e)`) to populate the event topics, the host should compute the
asset name `StringObject` (and the auxiliary `String` for `read_symbol`) at
most once per `(contract_id)` per host invocation. Subsequent calls within
the same host invocation, on the same SAC contract, should return the cached
`StringObject` handle without re-traversing instance storage, re-decoding
`StellarAssetContractMetadata` from `ScVal::Map`, and re-allocating the host
`String` object for the asset name.

The protocol-visible budget (`cpu_insns`, `mem_bytes`) on each cached call
must be byte-identical to the un-cached implementation: the cache must
*replay* the same `charge_budget` / `metered_clone` / `MeteredOrdMap::get`
budget effects via direct `Budget::charge` calls, not skip them.

## Mechanism

`event::transfer` / `mint` / `burn` / `clawback` / `set_authorized` / `set_admin`
/ `approve` (in `soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs`)
each call `read_name(e)` while building the event topics. `read_name` calls
`get_contract_data(METADATA, StorageType::Instance)`, which
(`host.rs:2251–2263`) borrows the current frame's `InstanceStorageMap` and
runs a metered `Val`-keyed `MeteredOrdMap::get(SymbolSmall("METADATA"), …)`
lookup, then a `to_valid_host_val` (`ScVal`→`Val`) conversion, then a
`try_into_val::<StellarAssetContractMetadata>` that allocates a fresh host
`StringObject` for both `name` and `symbol` on every call. The asset
metadata is immutable for a given SAC contract instance within a host
invocation, so all this work after the first call for a given `contract_id`
produces a structurally equivalent `StringObject`.

The **actual** behavior pays this cost on every SAC event. The Tracy soroswap
trace shows `get_contract_data` (vmcaller wrapper) self-time of 594 ms over
67,692 calls (5.77% of trace self-time) and `ScVal to Val` self-time of
430 ms over 691,521 calls (4.17%). Soroswap performs ~13,527 SAC `transfer`
events, each contributing one `read_name` + one `try_into_val` round-trip
through this path. The `extend_current_contract_instance_and_code_ttl` call
that immediately precedes the event also touches the same frame's instance
storage. A per-host-invocation cache of the resolved `name`/`symbol`
`StringObject` plus the parsed `AssetInfo` discriminant collapses the
13K+ repeated lookups into one per SAC contract per tx.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap scenario. Each pair
swap calls `token::transfer` on two SAC token contracts; each transfer emits
a `transfer` event whose topics include the SAC asset name. With ~2,000 txs
of soroswap and multiple SAC `transfer` calls per swap, ~13,527 SAC transfer
events fire per ledger; each currently performs a fresh metadata
read-and-conversion sequence.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192–206`
  — `read_name` and `read_symbol` perform the per-call instance storage
  lookup + metadata decode that we want to cache.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:35–166`
  — every event constructor calls `read_name(e)` while building topics.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231–2265`
  — `get_contract_data(StorageType::Instance)` is the hot-path map lookup
  whose cost we are amortizing.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` (`HostImpl` struct
  definition, near top) — natural location for a per-host
  `RefCell<Option<SacMetadataCache>>` field keyed by `(ContractId,
  cache_generation)`. Generation must be invalidated whenever
  `with_mut_instance_storage` runs for the matching contract id, so any
  later `set_metadata` or other instance-storage write evicts the cache.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:138–166`
  — frame already exposes `instance: ScContractInstance`, so cache lookup
  can key on the current frame's contract id without an extra storage
  borrow.

## Evidence

- Tracy `get_contract_data` (vmcaller wrapper) self-time 594 ms over
  67,692 calls (5.77% of soroswap trace self-time, 8.77 µs/call). At least
  ~13.5K of those calls are SAC `read_name` for event topics on the
  transfer path.
- Tracy `ScVal to Val` self-time 430 ms over 691,521 calls (4.17% of
  trace) — `read_name`'s `try_into_val::<StellarAssetContractMetadata>`
  dispatches through this conversion path and contributes a measurable
  share given the SAC event multiplicity.
- `add host object` self-time 270 ms over 935K calls. Each cached
  `read_name` call would otherwise add a fresh host `StringObject`; cache
  hits avoid the corresponding `add_host_object` allocation entirely
  (the cached handle is reused).
- The data is genuinely immutable per host invocation: a SAC contract's
  metadata is set in `set_metadata` at construction and is not modified by
  any SAC entrypoint reachable on the soroswap path. The cache key only
  needs to invalidate on `set_metadata`-style writes to that contract's
  instance storage, which can be detected by tracking
  `with_mut_instance_storage` calls per contract id.

## Anti-Evidence

- Exact-budget tests in `budget_metering.rs` and `e2e_tests.rs` assert
  precise `cpu_insns`/`mem_bytes` totals; any cache that *skips* the
  underlying `charge_budget` calls will diverge. The cache must replay
  every charge that `get_contract_data` + `to_valid_host_val` +
  `try_into_val::<StellarAssetContractMetadata>` performs (instance
  storage `MapAccess`, `MapEntry`, `ValDeser`/`ValSer` constants,
  `MemCpy` for the cloned `String` bytes, `VisitObject` for any
  intermediate object visits). Once those charges are replayed exactly,
  the residual physical savings are: the binary-search probe over the
  instance storage map, the `ScVal::Map` decode/walk, the `ScString`
  bytes copy out of the entry, and the host `String` allocation +
  `add_host_object` push. The hypothesis only clears Medium if the
  cumulative residual physical work is in the multiple-µs-per-call
  range across ~13.5K SAC events.
- The cache invalidation logic adds branch overhead to every
  `with_mut_instance_storage` call. On the soroswap workload, instance
  storage is rarely mutated (SAC entrypoints called by soroswap
  generally do not touch instance storage other than the lazy lookup),
  so the invalidation cost should be negligible.
- A previous `001-small-scval-val-conversion-fast-path.md` regressed the
  benchmark; that hypothesis broadly altered all `ScVal`→`Val` calls.
  This hypothesis is narrowly scoped to one specific repeated-decode
  pattern — the SAC metadata `ScVal::Map` decode that produces the
  asset name/symbol — so it should not perturb the rest of the
  conversion path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The SAC transfer hot path does call `event::transfer_maybe_with_issuer`, which can call `read_asset_info` for issuer checks and then calls an event constructor that includes `read_name(e)` in the event topics. However, `read_name` does not deserialize `ScVal::Map` or allocate fresh `StringObject`s on every call. Instance storage is lazily converted from the frame's `ScContractInstance.storage` into a `MeteredOrdMap<Val, Val, Host>` once per frame; subsequent `get_contract_data(StorageType::Instance)` calls only look up and copy an existing `Val`, and the generated `StellarAssetContractMetadata` conversion unpacks existing `Val` fields from an existing host map.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` loads the contract instance and pushes a `Frame::StellarAssetContract` for SAC calls before dispatching to the built-in contract.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` extends TTL, updates balances, and calls `event::transfer_maybe_with_issuer`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-113,116-166` — issuer classification uses `read_asset_info`, and all relevant event constructors include `read_name(e)` in topics.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-206` — `read_name` and `read_symbol` call `get_contract_data(..., StorageType::Instance)` and then convert the returned `Val` to the generated metadata struct.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-73` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — first instance-storage access initializes the frame-local `InstanceStorageMap`; mutable access marks the map modified.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` performs the `ScVal` to `Val` conversion for all instance storage entries during lazy frame initialization, not during each later `read_name`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2265` — the instance branch of `get_contract_data` only performs a `MeteredOrdMap::get` on the `Val` map and returns `.copied()`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:48-68` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1044-1083` — generated struct decoding uses `map_unpack_to_slice`, checks the existing host map keys, and copies existing `Val` fields; it does not allocate fresh `StringObject`s.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:12-45` — the SAC `String` wrapper created from a `StringObject` stores a cloned `Host` handle and the existing `StringObject` handle.

### Why It Failed

The claimed per-event `ScVal::Map` decode and fresh asset-name `StringObject` allocation do not occur on the `read_name` path. Those allocations happen when the SAC frame's instance storage is first initialized from XDR, and on the transfer path that can already be forced by `read_asset_info` before the event reaches `read_name`. A `read_name` cache could at most skip a tiny instance-map lookup, generated metadata map unpack, small-symbol key checks, and wrapper construction; preserving exact budget would still require replaying the metered lookup/unpack effects. That residual physical work is far below the objective's Medium threshold and cannot justify the projected 3-5% soroswap apply-time reduction.

### Lesson Learned

For SAC metadata hypotheses, separate frame-local instance-storage initialization from repeated reads of already-converted `Val` entries. Broad Tracy zones such as `ScVal to Val`, `add host object`, and `get_contract_data` cannot be attributed to `read_name` unless the traced source path actually performs those conversions or allocations on each event.
