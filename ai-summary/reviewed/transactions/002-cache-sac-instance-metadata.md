# H002: Cache Immutable SAC Instance Metadata Within Native Transfer Frames

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap and SAC apply-time reduction by avoiding repeated instance-storage decoding and metadata lookups during native SAC event emission
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every SAC `transfer` should emit the same transfer/mint/burn event topics and data, perform the same issuer classification, charge the same protocol-visible budget for the active protocol, and leave the same ledger state. However, immutable SAC instance metadata such as `AssetInfo` and `StellarAssetContractMetadata.name` should not be repeatedly decoded and looked up through generic instance-storage maps for every event emission in a ledger when the current SAC contract instance already contains those values and normal transfers do not mutate them.

## Mechanism

`event::transfer_maybe_with_issuer` calls `is_issuer` for the sender and receiver and then calls `transfer`, `mint`, or `burn`. `is_issuer` calls `read_asset_info`, and `transfer`/`mint`/`burn` call `read_name`, so a normal non-issuer contract-to-contract transfer repeatedly probes SAC instance storage for immutable metadata. `Host::call_contract_fn` creates a `Frame::StellarAssetContract` with a `ScContractInstance`, and `Host::maybe_init_instance_storage` decodes the instance `ScMap` into an `InstanceStorageMap` on first access in that frame; the metadata helpers then go back through `Host::get_contract_data`, `with_instance_storage`, `MeteredOrdMap::get`, and `ScVal` conversion. A per-frame or per-invocation immutable SAC metadata cache, populated from the `ScContractInstance` once and invalidated if instance storage is mutably accessed, should remove repeated map construction/lookups and conversions from native SAC transfer event emission while preserving deterministic event content.

## Trigger

Run either current apply-load scenario from `ai-summary/CURRENT_STATE.md`: `soroswap, TX=2000, T=8` or `sac, TX=6000, T=8`. The trigger is the repeated successful SAC `transfer` path, especially contract-to-contract transfers where neither endpoint is the asset issuer and every event still reads asset info and metadata name.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` creates `Frame::StellarAssetContract` with the current `ScContractInstance` before dispatching to the native SAC implementation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — `maybe_init_instance_storage` decodes the instance storage `ScMap` into an `InstanceStorageMap` on first instance-storage access in each frame.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` converts every instance-storage `ScMapEntry` key/value into host `Val`s and builds a metered ordered map.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-65` — `transfer_maybe_with_issuer` performs repeated issuer checks before event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-113` — `transfer` reads the metadata name for the event topic.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` fetches `InstanceDataKey::AssetInfo` through generic instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` — `read_name` fetches and decodes `StellarAssetContractMetadata` through generic instance storage.

## Evidence

In the current soroswap trace, timestamp-filtering inside `applyLedger` windows shows `SAC transfer` at 2,153,411,257 ns aggregate across 13,527 calls. Nested under `SAC transfer`, metadata- and instance-storage-adjacent work is prominent: `ScVal to Val` totals 870,437,313 ns, `get_contract_data` from `vmcaller_env.rs:270` totals 592,030,513 ns, `storage get` totals 523,805,619 ns, `map lookup` totals 464,712,385 ns, `map lookup indexed` totals 436,513,754 ns, and `new map` totals 325,891,339 ns. These are apply-descendant events, not tx-set-construction zones.

The current SAC trace shows the same pattern more strongly in the headline SAC workload: within 28 `applyLedger` windows totaling 2,722,490,387 ns, `SAC transfer` totals 3,729,403,370 ns aggregate across 36,008 calls, while `ScVal to Val` is 592,583,991 ns, `map lookup` is 556,801,516 ns, `storage get` is 511,093,603 ns, `map lookup indexed` is 474,261,920 ns, `new map` is 289,793,474 ns, and `get_contract_data` is 198,536,049 ns. A cache that removes even a substantial subset of repeated immutable instance metadata decoding/lookups can plausibly reach the 3-10% Medium band after dividing aggregate worker time by `T=8`, and it helps the soroswap path as well as the SAC benchmark.

## Anti-Evidence

Prior failed work rejected a narrow SAC issuer endpoint fast path as below threshold; this hypothesis is broader and must prove that immutable metadata decode/lookup, not just endpoint classification, accounts for a Medium-tier share. The implementation must be careful around SAC functions that mutate instance storage (`set_metadata`, admin/asset setup paths, or future extensions): cached metadata must be frame-local or invalidated on `with_mut_instance_storage` so it cannot observe stale values. As with other Soroban host optimizations, current-protocol metering cannot silently change; this likely needs next-protocol gating or explicit equivalent budget charges for the skipped instance-storage conversion and lookup work.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The traced SAC transfer path confirms that `StellarAssetContract::transfer` and `transfer_from` finish by calling `event::transfer_maybe_with_issuer`, which performs up to two `read_asset_info` calls and then one `read_name` call for the transfer/mint/burn event. For a normal contract-to-contract transfer with existing balances, the balance updates use persistent balance entries and do not necessarily initialize instance storage first, so the event's first metadata read can pay the full lazy `ScContractInstance.storage` conversion for the frame. Subsequent metadata reads in the same event still go through `Host::get_contract_data`, `with_instance_storage`, `MeteredOrdMap::get`, and generated `TryIntoVal` decoding even though `AssetInfo` and metadata name are immutable for normal transfer frames. The mechanism is therefore real, hot in the benchmarked SAC transfer path, and distinct from the previously rejected endpoint address fast path.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `Host::call_contract_fn` loads the `ScContractInstance` and stores it directly in `Frame::StellarAssetContract` before dispatching the native SAC call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:91-170` — each `Context` holds per-frame `storage: Option<InstanceStorageMap>`, while `Frame::StellarAssetContract` exposes the immutable instance through `Frame::instance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — `Host::maybe_init_instance_storage` lazily converts the frame's full instance `ScMap` into an `InstanceStorageMap` on first instance-storage access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` converts every instance key/value with `Host::to_valid_host_val` and builds a metered ordered map, so a read of one metadata field can construct the entire instance-storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — immutable access initializes and borrows the instance map; mutable access marks `is_modified`, which provides the correct invalidation signal for any cached metadata.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2264` — instance `put_contract_data`, `has_contract_data`, and `get_contract_data` route through `with_mut_instance_storage`/`with_instance_storage` and `MeteredOrdMap` operations.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` updates balances and emits the SAC event via `transfer_maybe_with_issuer`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:229-249` — `transfer_from` follows the same event path after allowance and balance updates.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,220-245` — with existing contract balances, authorization and balance updates use persistent balance data; asset-info instance reads are only needed for missing-balance authorization/clawback defaults.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-65,94-167` — issuer classification reads `AssetInfo` twice in the non-issuer case and event emission reads metadata name once.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` always fetches `InstanceDataKey::AssetInfo` through generic instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:163-198` — `set_metadata` is the initialization writer and `read_name` decodes full `StellarAssetContractMetadata` through generic instance storage.
- `ai-summary/fail/transactions/summary.md:18,28,38` — prior failures cover SAC address decoding, generic storage conversion caching, and issuer endpoint fast paths, but not a next-protocol-gated immutable SAC metadata cache populated from the already-loaded `ScContractInstance`.
- `ai-summary/CURRENT_STATE.md:41-64,115-124` — the current benchmark baseline is measured with next-protocol enabled, so a protocol-gated host optimization can affect the apply-load benchmark while preserving released p26 metering.

### Findings

The inefficiency exists. A single non-issuer SAC transfer event performs two `read_asset_info` calls and one `read_name` call, and all three currently route through generic instance-storage access. The first such access in a frame can force `InstanceStorageMap::from_instance_xdr` to convert the full instance map even though only immutable SAC metadata is needed; later reads repeat map lookup and generated conversion work.

The path is hot enough for the objective. Both benchmark scenarios repeatedly execute `SAC transfer`, and the current diagnostic evidence shows large aggregate SAC transfer time and visible instance-storage-adjacent zones inside apply windows. The exact reclaim is not the sum of those nested zones because persistent balance operations also contribute to `get_contract_data`, `storage get`, and map lookup totals, but removing one full instance-map construction plus three metadata lookups/decodes per normal transfer is plausibly in the Medium band for the SAC workload and worth a PoC against the soroswap run.

The fix must be protocol-gated or exactly budget-preserving. The previous generic storage-conversion cache failed because p26 storage conversion and map operations are part of protocol-visible metering. This narrower hypothesis is viable because the current objective already benchmarks protocol 27 via `--enable-next-protocol-version-unsafe-for-production`; a correct implementation should enable the shortcut only for next protocol, or explicitly charge the skipped p26-equivalent costs before returning cached values.

Correctness constraints are manageable. `with_mut_instance_storage` marks the frame's instance storage as modified, and `persist_instance_storage` only writes modified maps back on frame pop. A frame-local SAC metadata cache can therefore be bypassed or invalidated after any mutable instance-storage access, avoiding stale reads during `init_asset`, admin changes, or future SAC extensions. The cache must be scoped to the current frame/contract instance and must not be shared across hosts, frames, or ledger states.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs`, `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs`, `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs`, and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs`.
- **Change description**: add a next-protocol-only, frame-local immutable SAC metadata cache populated from the `ScContractInstance` already stored in `Frame::StellarAssetContract`; use it for `AssetInfo` and metadata name reads in the SAC event path when instance storage has not been mutably accessed. Bypass or clear the cache whenever `with_mut_instance_storage` runs, and fall back to existing generic `get_contract_data` reads for current protocol or modified instance storage.
- **Correctness check**: existing SAC transfer, transfer_from, mint/burn event, metadata/name/symbol, init_asset, set_admin, authorization, and storage-metering tests should remain semantically unchanged. Expect budget-number updates only if the optimization is next-protocol-gated and intentionally changes next-protocol host metering.
- **Benchmark focus**: compare all three non-Tracy `scripts/run_apply_load_matrix.py` runs for `soroswap, TX=2000, T=8` and `sac, TX=6000, T=8` against the `ai-summary/CURRENT_STATE.md` baseline. The expected signal is reduced median apply time from fewer per-transfer instance-map constructions, map lookups, and metadata conversions; promotion requires a reproducible 3-10% improvement band for Medium.
