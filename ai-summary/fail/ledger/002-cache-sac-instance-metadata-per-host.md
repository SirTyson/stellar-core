# H002: Cache SAC immutable instance metadata per host invocation

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban SAC apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated SAC instance-storage reads and conversions inside hot transfer calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC calls should preserve the same authorization checks, issuer special cases, event topics, TTL behavior, and final ledger entries. Within a single host invocation, immutable SAC instance metadata such as `AssetInfo` and `METADATA.name` should be read and decoded once per current SAC contract unless a write to the same instance key occurs; repeated transfer-side checks and event construction should reuse that decoded value instead of re-reading instance storage.

## Mechanism

The SAC transfer path repeatedly reads immutable instance data through generic contract-data APIs. `read_asset_info` fetches `InstanceDataKey::AssetInfo` via `get_contract_data`, `read_asset` immediately converts it into `Asset`, `event::is_issuer` reads `AssetInfo` to decide whether to emit mint/burn/transfer events, and `read_name` fetches the `METADATA` instance value for event topics. In a soroswap swap, the same token SAC contract is entered multiple times and these instance values do not change, but every call still pays storage lookup, host value conversion, `AssetInfo`/metadata decoding, and associated metered map comparisons.

The proposed optimization is to add a per-host SAC metadata cache keyed by current contract ID and instance key, storing decoded `AssetInfo`, decoded `Asset`, and/or metadata name. `read_asset_info`, `read_asset`, and `read_name` would consult this cache in enforcing mode and invalidate it on writes to the same instance keys (`write_asset_info`, `set_metadata`, or generic instance `put` for those keys). The cache is deterministic because it only memoizes reads from the current host's own storage snapshot/overlay and is discarded at host finish.

## Trigger

Run the current soroswap apply-load workload (`soroswap, TX=2000, T=8`). Each generated swap calls the router with a two-token path, causing SAC transfer calls for token-in/token-out contracts. The transfer path calls `spend_balance`, `receive_balance`, and `event::transfer_maybe_with_issuer`, which repeatedly need asset/issuer metadata and event name metadata for the same current SAC contract.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - hot `SAC transfer` entry point.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` - `read_asset_info` and `read_asset` always read/decode `AssetInfo`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` - event selection can call `is_issuer` on both addresses, each reading `AssetInfo`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-113` - transfer event topic construction reads SAC name metadata.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-197` - `read_name` reads and decodes the `METADATA` instance value.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:391-403`, `:785-807`, and `:929-944` - balance and authorization helpers repeatedly convert the same SAC `AssetInfo` into classic `Asset` / issuer checks.

## Evidence

The current soroswap trace reports `SAC transfer` total time of 2,153,411,257 ns and self-time of 558,183,960 ns over 13,527 calls at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212`; timeline overlap analysis shows 100% of these events are inside `applyLedger`. Supporting descendant zones that overlap `applyLedger` 100% include `get_contract_data` total 594,010,156 ns at `soroban-env-common/src/vmcaller_env.rs:270` plus 142,529,580 ns at `soroban-env-host/src/vm/dispatch.rs:304`, `ScVal to Val` self 429,988,065 ns at `host/conversion.rs:436`, and `map lookup indexed` self 408,451,716 ns at `host/metered_map.rs:330`.

This targets a different SAC path than the previously rejected fused balance/trustline read PoC. That PoC removed duplicate mutable balance/trustline reads but regressed in benchmark; this hypothesis targets immutable instance metadata reads and conversions used for asset/issuer/event logic, which can be cached without changing balance mutation structure.

## Anti-Evidence

The existing storage layer may already make repeated instance lookups relatively cheap via indexed map access, and the trace does not currently isolate `read_asset_info` or `read_name` with dedicated spans. A PoC must add enough local instrumentation or differential measurement to show this subset is large enough for Medium impact. The cache must be invalidated on instance metadata writes and must be keyed by current contract ID, because a single host invocation can enter multiple SAC contracts in the same router call.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent to prior SAC balance/storage and Soroban input-cache reviews, but not a duplicate of an immutable SAC instance-metadata cache
**Failed At**: reviewer

### Trace Summary

`StellarAssetContract::transfer` is on the soroswap apply path and calls `spend_balance`, `receive_balance`, and `event::transfer_maybe_with_issuer`; those helpers can read `AssetInfo` through `read_asset`/`read_asset_info` and read `METADATA.name` through `read_name` multiple times per SAC transfer. However, these are `StorageType::Instance` reads, and the host lazily converts the contract instance's `ScMap` into an in-memory `InstanceStorageMap` once per frame before subsequent `get_contract_data` calls perform only a small metered map lookup and return a copied `Val`. The claimed durable-storage lookup cost is therefore not present for these metadata reads, and the remaining cacheable work is a small subset of broad aggregate worker-thread zones that must be normalized by 8-way cluster parallelism.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` is the hot SAC entry point and dispatches to balance mutation plus event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` — `read_asset_info` reads `InstanceDataKey::AssetInfo` from instance storage and `read_asset` converts it to classic `Asset`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26,47-64,94-113,163-165` — event selection can call `is_issuer` twice and event construction reads `read_name`, but only one of transfer/mint/burn is emitted per transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-197` — `read_name` gets the `METADATA` instance value and converts it to `StellarAssetContractMetadata`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:391-403,785-807,929-944` — account/trustline helpers read `Asset` or `AssetInfo` to identify issuer and trustline type.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2263` — `get_contract_data` dispatches `StorageType::Instance` to `with_instance_storage` and `s.map.get(&k, self)?.copied()`, not to durable `Storage::get`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap` stores instance entries as a `MeteredOrdMap<Val, Val, Host>` populated from the `ScContractInstance` storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:29-72` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — instance storage is lazily initialized once per current contract frame and then reused for read-only accesses; mutable accesses mark it modified for later persistence.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1254-1278` — instance storage is only written back when modified, so the hot transfer metadata reads are already served from the frame-local copy.
- `src/simulation/ApplyLoad.cpp:3382-3475` — the benchmark constructs each swap with token-in and token-out SAC instance keys in the read-only footprint and two SAC transfers through the router path.
- `ai-summary/fail/ledger/002-fuse-sac-balance-auth-storage-reads.md:44-82,108-130` — the adjacent mutable balance/trustline-read optimization targeted persistent/RW entries and reached PoC, but its final review blocker was reproducibility; it is not a duplicate of this immutable instance-metadata cache.
- `ai-summary/fail/ledger/001-cluster-local-decoded-soroban-input-cache.md:53-76` — a broader repeated Soroban input-decoding cache was rejected below threshold after parallelism normalization, which constrains the severity estimate for this narrower instance-only subset.

### Why It Failed

The core optimization is technically plausible but below this objective's Medium severity threshold. The hypothesis overstates the cost by treating SAC metadata reads as generic contract-data storage lookups; in the actual `StorageType::Instance` branch, the durable contract instance has already been decoded into `InstanceStorageMap`, and repeated reads are small in-memory `MeteredOrdMap` lookups plus value-to-Rust-type conversion. There is no repeated footprint enforcement, persistent ledger-entry lookup, TTL lookup, or durable storage fetch to remove for `AssetInfo` or `METADATA.name`.

The cited Tracy zones are too broad to support a 3-10% apply-time projection. `SAC transfer` total includes balance mutation, authorization, event emission, host dispatch, and all child calls; its self-time is 558 ms aggregate, which is only about 70 ms on an 8-cluster critical path, around 1.3% of the cited 5.23 s `applyLedger` trace even if eliminated entirely. The cacheable metadata subset is much smaller: roughly a few instance reads per SAC transfer, drawn from broad aggregate `map lookup indexed` and `ScVal to Val` zones that also include many non-SAC maps, storage construction, contract execution, auth, and result processing. Even an ideal per-host metadata cache would therefore be a Low-tier cleanup, not a Medium optimize-soroswap finding.

### Lesson Learned

For SAC instance metadata, distinguish `StorageType::Instance` from persistent/temporary contract data. Instance reads are already frame-local after one lazy `ScContractInstance` decode, so severity estimates must be based on the remaining in-memory map and conversion subset, with aggregate worker times normalized by configured cluster parallelism.
