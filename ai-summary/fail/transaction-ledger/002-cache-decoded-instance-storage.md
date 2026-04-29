# H002: Cache decoded contract instance storage across repeated SAC frames

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding repeated instance-storage decoding and host-object conversion for stable SAC metadata
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every contract call should observe the same current contract instance, instance-storage values, re-entry behavior, TTL effects, and rollback semantics as today. Repeated read-only calls into the same Stellar Asset Contract during one invoke-host-function transaction should not rebuild the same `InstanceStorageMap` from the same `ScContractInstance.storage` map in every short-lived SAC frame when the instance has not been modified.

## Mechanism

`call_contract_fn` retrieves the target contract instance from enforcing storage for every cross-contract call and stores a cloned `ScContractInstance` in the new `Frame::StellarAssetContract`. The first instance-storage access in that frame calls `maybe_init_instance_storage`, which converts `ScContractInstance.storage` into an `InstanceStorageMap` by walking every instance `ScMap` entry and converting keys and values into host `Val`s. Soroswap repeatedly calls SAC `transfer` and `balance` for the same token contracts; those calls read stable instance metadata such as `AssetInfo` and `METADATA_KEY` name, so a per-host cache keyed by contract ID and invalidated on instance-storage persistence can reuse the decoded immutable instance map instead of reconstructing it for each SAC frame.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. In the longest `applyLedger` window, each worker executes about 77-78 `SAC transfer` calls and 76-78 `SAC balance` calls; the hottest worker spends 37.190 ms in `SAC transfer` and 9.498 ms in `SAC balance`. The same worker window contains heavy conversion/object work such as `visit host object` at 47.824 ms and `ScVal to Val` at 12.102 ms, and SAC instance metadata reads are one repeated source of those conversions.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the contract instance and creates a fresh `Frame::StellarAssetContract` for every SAC call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — `maybe_init_instance_storage` lazily converts the frame's `ScContractInstance.storage` to an `InstanceStorageMap` every time a new frame first touches instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:46-65` — `InstanceStorageMap::from_instance_xdr` walks the instance `ScMap`, converts each key/value to a host `Val`, collects a vector, and builds a `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-224` — hot SAC `balance` and `transfer` paths extend instance TTL and then read stable metadata while processing balances and events.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` gets the `AssetInfo` instance-storage value and decodes it on every issuer-classification path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-205` — `read_name` / `read_symbol` get and decode the same metadata instance-storage value for event topics and metadata calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1258-1278` — `persist_instance_storage` is the natural invalidation point when a frame modifies instance storage.

## Evidence

The soroswap workload repeatedly crosses from user Wasm into built-in SAC contracts inside `applyLedger`. The source shows every SAC call gets its own frame, and instance storage is frame-local: `Frame::StellarAssetContract` owns an `ScContractInstance`, while `maybe_init_instance_storage` rebuilds `InstanceStorageMap` from that instance when `get_contract_data(..., StorageType::Instance)` is first used. SAC metadata is stable during swaps, but `transfer_maybe_with_issuer` and event-topic construction repeatedly call `read_asset_info` and `read_name`, forcing the same instance map and generated contracttype conversions to be recreated across frames.

This differs from the reviewed SAC balance-storage and duplicate-balance-read hypotheses. Those optimize persistent balance `ContractData` reads/writes in `balance.rs`; this targets instance-storage decoding for SAC metadata and frame setup before those persistent balance helpers run. It also differs from the failed current-contract TTL coalescing hypothesis: TTL extension changes ledger-live-until behavior, while this preserves the existing TTL calls and only reuses decoded read-only instance metadata until an instance-storage write invalidates it.

## Anti-Evidence

The trace does not have a narrow span around `InstanceStorageMap::from_instance_xdr`, so a PoC should add temporary counters or spans to isolate how much of `ScVal to Val`, `visit host object`, and SAC self-time comes from instance metadata decoding. The cache must be conservative around re-entrancy and instance-storage mutation: if `with_mut_instance_storage` marks a frame modified or `persist_instance_storage` writes a new instance map, cached entries for that contract ID must be discarded before any outer frame reload. If the reviewed typed SAC balance and host-object conversion batching hypotheses land first, the remaining conversion share may shrink and should be remeasured before implementation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this code through parallel Soroban apply: `InvokeHostFunctionOpFrame::doParallelApply` enters the Rust bridge, `e2e_invoke::invoke_host_function_with_trace_hook_and_module_cache` constructs a `Host`, and `Host::invoke_function` eventually calls user Wasm that cross-calls SAC contracts. Each SAC cross-call creates a new `Frame::StellarAssetContract`; on the first `StorageType::Instance` access in that frame, `maybe_init_instance_storage` converts the frame's cloned `ScContractInstance.storage` into a host `InstanceStorageMap`. The repeated transfer-side decode exists, but the claimed balance-side decode is generally not on the hot `balance` path, and reusing a cached decoded map would skip deterministic conversion/allocation budget charges that Core observes in returned CPU and memory usage.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` — C++ invokes the Rust bridge, records returned CPU/memory, and maps resource-limit failures based on those returned values.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` is the Soroban parallel-apply operation entry point.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge creates the transaction `Budget` and calls the p26 host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-500` — enforcing storage and host are constructed, the host function is invoked, then final CPU/memory and ledger changes are produced.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — every contract call retrieves and clones the current contract instance and creates a fresh SAC frame for `ContractExecutable::StellarAsset`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-562` — `with_frame` pushes a frame with empty per-frame instance storage, persists modified instance storage on success, and rolls back storage/events/auth on failure.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1278` — instance storage is lazily initialized from the frame instance, reloaded for re-entrant parent frames after a persist, and persisted back to enforcing storage when modified.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` walks the instance `ScMap`, calls `to_valid_host_val` for each key/value, metered-collects the vector, and builds a `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:29-73` — immutable instance access initializes storage lazily, while mutable access marks the per-frame storage modified.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2264` — `put_contract_data`, `has_contract_data`, and `get_contract_data` route `StorageType::Instance` operations through per-frame instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460,543-655` — `ScVal` to `Val` conversion recursively creates host objects and performs metered allocations/copies for object-valued entries.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-224` — `balance` extends TTL and reads persistent balance data; `transfer` extends TTL, updates balances, and emits transfer/mint/burn events.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,232-245` — normal `balance` reads persistent balance data and does not read SAC instance metadata; `is_authorized` only falls back to `read_asset_info` when a contract balance is absent.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-107` — transfer event classification calls `read_asset_info` for issuer checks and `read_name` for event topics, causing transfer frames to initialize instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` fetches the `AssetInfo` value from instance storage and decodes it into the generated contract type.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-205` — `read_name` and `read_symbol` fetch metadata from instance storage and decode generated contract-type values.

### Why It Failed

The proposed fix is not correctness-preserving as stated. `InstanceStorageMap::from_instance_xdr` is not just an avoidable decode; it is part of deterministic Soroban metering. It performs metered vector allocation/collection, `MeteredOrdMap` construction, recursive `ScVal to Val` conversion, host-object creation, and shallow-copy/heap-allocation charges. `InvokeHostFunctionOutput` returns the resulting CPU and memory totals to Core, and Core uses those totals to decide resource-limit failures. A cache that directly reuses decoded `Val` maps would therefore change visible resource consumption and can change whether a transaction succeeds, fails with budget exceeded, or reports particular CPU/memory usage.

The hot-path claim is also overstated. The traced `transfer` path does initialize instance storage through `read_asset_info` / `read_name`, but the normal `balance` path extends the current contract instance TTL and reads persistent balance storage; it does not decode the instance map unless a contract-balance authorization fallback needs `is_asset_auth_required`. Thus the maximum recoverable work is narrower than the hypothesis's transfer-plus-balance count. A behavior-preserving cache would need to replay the exact metering and failure ordering for the original instance-map conversion, at which point only a small actual allocation/conversion subset for a 2-3 entry SAC instance remains; that is not a credible 3-10% soroswap apply-time reduction.

### Lesson Learned

For Soroban host decode-cache hypotheses, distinguish wall-clock object reuse from protocol-visible budget accounting. Reusing decoded host values across frames is unsafe unless the design explicitly preserves or intentionally protocol-gates the exact metering semantics. Also verify the specific SAC function path: `transfer` reads instance metadata for issuer classification and event topics, but `balance` generally does not initialize instance storage.
