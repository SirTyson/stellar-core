# H002: Reuse initialized instance-storage maps across repeated frames

**Date**: 2026-05-05
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: apply-time (SAC and repeated contract instance access)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within a single host invocation, repeated frames for the same contract instance
should not repeatedly decode the same `ScContractInstance.storage` XDR map into
host `Val`s when the instance storage has not changed. Read-only frames should
be able to reuse a Host-local initialized `InstanceStorageMap`, and mutating
frames should detach or invalidate that cache so rollback and parent-frame
reload semantics remain unchanged.

## Mechanism

`call_contract_fn` retrieves a fresh `ScContractInstance` for every contract
call, then `maybe_init_instance_storage` lazily converts that frame's
`ScContractInstance.storage` into an `InstanceStorageMap` on first instance
storage access. Soroswap repeatedly enters SAC frames for the same asset
contracts, and SAC paths such as `transfer`, `balance`, `read_asset_info`,
`read_name`, and `is_authorized` access instance storage. The current design is
lazy per frame, but not reusable across repeated frames, so the same small
instance maps are converted from `ScVal` to host `Val`, sorted into a
`MeteredOrdMap`, and backed by new host objects many times in one apply.

The optimization would add a Host-local cache keyed by `ContractId` that stores
an initialized, immutable `InstanceStorageMap` plus a generation or dirty bit
for the source contract instance entry. Frame initialization would borrow/share
that map for read-only access; `with_mut_instance_storage`,
`persist_instance_storage`, `store_contract_instance`, and
`update_current_contract_wasm` would detach and invalidate affected entries.
For next-protocol optimization this can intentionally lower the physical and
metered conversion work; for p26 compatibility it would need to replay the old
charges before using the cached map.

## Trigger

Run the current soroswap apply-load benchmark. Each swap causes multiple
cross-contract calls into the same SAC instances for balance checks, balance
mutation, TTL extension, and event metadata. A repeated SAC frame that calls
`read_name` or `read_asset_info` after a prior frame for the same contract has
already initialized instance storage should hit the cache instead of rebuilding
the `InstanceStorageMap`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` —
  `call_contract_fn` retrieves the contract instance for every call and creates
  a new `Frame::ContractVM` or `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` —
  `maybe_init_instance_storage` initializes frame-local instance storage from
  the frame's `ScContractInstance`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:38-66` —
  `InstanceStorageMap::from_instance_xdr` converts each `ScMap` item through
  `Host::to_valid_host_val` and builds a `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1214-1278` —
  reload and persist paths that must invalidate or detach cached maps.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-225`
  and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-205`
  — SAC balance/transfer and metadata reads that repeatedly touch instance
  storage in the soroswap path.

## Evidence

The current soroswap Tracy trace reports several in-scope zones that this
mechanism can reduce: `SAC transfer` total time is 2,153,411,257 ns across
13,527 calls, `ScVal to Val` self-time is 429,988,065 ns across 691,521 calls,
`new map` self-time is 331,023,872 ns across 170,072 calls, and `storage get`
self-time is 215,980,007 ns across 305,065 calls. A filtered unwrap check
confirmed all 13,527 `SAC transfer` events and all 691,521 `ScVal to Val`
events are inside `applyLedger` windows.

The source-level structure shows the repeated work is real and not merely a
single top-level setup: each frame owns its own optional instance-storage map,
and initialization converts from the frame's XDR instance snapshot rather than
consulting a Host-level initialized-map cache. Soroswap's repeated SAC calls
make this more attractive than a one-off metadata cache because the cache would
cover all instance-storage keys for the contract, not just `METADATA`.

## Anti-Evidence

This is only viable if repeated frames for the same SAC/pool contracts account
for a substantial fraction of `ScVal to Val` and `new map`; those zones also
include non-instance conversions and other map construction. Instance-storage
mutations are subtle: `with_mut_instance_storage` marks a frame modified, frame
pop can reload parent contexts, and `update_current_contract_wasm` can change
the executable mid-frame. A correct implementation therefore needs explicit
copy-on-write or invalidation, and a p26-compatible version must preserve the
old budget charges even when the physical conversion is skipped.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prior failures covered SAC metadata-object caching and TTL shortcuts, but not reuse of the initialized frame instance-storage map across frames
**Failed At**: reviewer

### Trace Summary

The repeated work exists: every `call_contract_fn` creates a fresh contract frame with `Context.storage = None`, and the first `StorageType::Instance` access in that frame rebuilds an `InstanceStorageMap` from the frame's `ScContractInstance.storage`. However, the hottest SAC balance and transfer body work does not itself use instance storage for balances or TTL extension; balances, allowances, and authorization records are persistent/temporary contract data, while instance storage is reached through metadata/admin/asset-info helper calls such as event `read_name`, issuer checks, and admin checks. That makes the target a per-SAC-frame decode of a very small SAC instance map, not the whole `SAC transfer`, `storage get`, `ScVal to Val`, or `new map` aggregate in the hypothesis evidence.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-431` — `with_frame` always constructs a new `Context` with `storage: None`, so instance storage is frame-local and not cached across repeated calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves a fresh `ScContractInstance` from storage for every contract call and embeds it in `Frame::ContractVM` or `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:113-120` — contract-instance retrieval performs a storage `get` and extracts/clones the `ScContractInstance` snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:167-245` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2541-2561` — `store_contract_instance` and `update_current_contract_wasm` can change the persisted instance entry, so any cross-frame cache would need invalidation on storage/executable updates.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:29-72` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — `with_instance_storage` and `with_mut_instance_storage` lazily initialize the current frame's storage by calling `InstanceStorageMap::from_instance_xdr`; mutable access marks the frame modified for footprint/persist behavior.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` converts each instance `ScMap` key/value with `Host::to_valid_host_val` and builds a `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2289` — only `StorageType::Instance` routes through frame instance storage; temporary and persistent contract data use ledger storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,220-245,917-935` — SAC balances and authorization flags are mostly persistent contract data; instance storage is only reached indirectly when an absent contract balance needs asset flags via `read_asset_info`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-63,94-114` and `metadata.rs:192-205` — SAC transfer event classification reads asset info and then reads the asset name from instance metadata, causing at most one frame-local instance-storage initialization followed by ordinary map lookups in that same frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/admin.rs:7-21` and `asset_info.rs:10-34` — admin and asset info are the actual SAC instance-storage keys (`Admin`, `AssetInfo`, plus metadata), confirming the maps are small.

### Why It Failed

The claimed inefficiency is real but over-projected. `ScVal to Val` and `new map` totals are broad host-wide zones that include many non-instance conversions and map constructions; the safely removable subset here is one small `InstanceStorageMap::from_instance_xdr` per repeated SAC frame that actually touches instance storage. For a typical SAC instance this is only a few key/value conversions and one small `MeteredOrdMap` build per frame. Scaling the hypothesis's own counts by the identifiable instance-storage subset yields a low-single-digit percentage upper bound before subtracting mandatory p26 budget replay, first-use cache misses, mutation invalidation, persistent-balance work, event construction, and storage/TTL operations. Under this objective, Low findings are rejected, so this does not clear the required 3% Medium apply-time floor.

The proposed cache is also not a clean p26 physical-only optimization: preserving existing protocol-visible budget behavior would require replaying the same conversion, map-construction, object-allocation, and comparison charges on cache hits. Once those mandatory charges are kept, only the physical XDR-to-host-object construction for a tiny instance map remains removable, further reducing the expected impact.

### Lesson Learned

Frame-local instance-storage initialization is a real one-time-per-frame cost, but it should not be inferred from whole `ScVal to Val`, `new map`, `storage get`, or `SAC transfer` zones. For SAC hypotheses, first separate persistent/temporary balance and allowance data from the small instance metadata/admin map, then count first instance-storage accesses per frame; repeated `read_name` or `read_asset_info` calls inside the same frame already use the initialized map and do not re-decode XDR.
