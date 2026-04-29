# H001: Cache SAC Address Shapes and Immutable Metadata During Built-in Calls

**Date**: 2026-04-29
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in SAC-heavy host execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC `transfer` and `balance` should preserve the same authorization checks, balance updates, emitted events, return values, and budget/resource accounting, but repeated reads of immutable per-contract SAC data and repeated decoding of the same endpoint `Address` object should not repeatedly traverse the host object table and instance-storage map during one built-in call. For a soroswap SAC transfer, the code should decode `from`, `to`, asset info, and event metadata once per call or per SAC frame, then reuse those decoded values while preserving the same observable metering inputs.

## Mechanism

The current SAC path stores `Address` as only `(Host, AddressObject)`, so every `Address::to_sc_address()` calls `Host::scaddress_from_address`, which enters the hot `visit host object` path and clones the stored `ScAddress`. `contract.rs::transfer` then calls helpers that repeatedly decode the same endpoint shape (`is_authorized`, `spend_balance`, `receive_balance`, event issuer classification), while those helpers also call `read_asset` / `read_asset_info` / `read_name` multiple times through instance storage even though SAC asset info and metadata are immutable after initialization. A SAC-local execution context that caches decoded endpoint shapes plus immutable `AssetInfo`/metadata can remove repeated object-table visits, storage lookups, and `ScVal` conversions without changing ledger output; any skipped budget operations must either be replayed exactly or explicitly treated as a protocol-visible metering optimization.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). The swap path repeatedly invokes SAC `transfer` and `balance` for the same token contracts and account/contract endpoints. A PoC should add a SAC-call-local cache (for example, a small context object passed through `balance.rs` and `event.rs`) that decodes each endpoint `Address` once and reads immutable SAC asset metadata/name once, then reuses those values in `is_authorized`, account/trustline balance transfer, and event emission.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-375` — `Address` holds only a host object handle; `to_sc_address` re-enters the host object table on every shape check.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — `Host::scaddress_from_address` implements that shape check via `visit_obj` plus a metered clone.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-225` — SAC `balance` and `transfer` are the hot built-in entry points exercised by soroswap.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,156-229,233-254,376-430,785-808` — balance/auth helpers repeatedly decode address shape and reread the SAC asset for account/trustline paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-64,94-113` — transfer-event classification rereads asset info and metadata after balance updates have already read the same immutable SAC data.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` and `metadata.rs:192-198` — immutable SAC instance metadata is loaded and converted through storage for each helper call.

## Evidence

The current soroswap diagnostic trace is apply-contained for the targeted zones: timestamp containment against `applyLedger` windows shows `SAC transfer` at **2,406.469 ms total** across **6,656 calls**, `SAC balance` at **545.826 ms total** across **6,636 calls**, `visit host object` at **2,372.465 ms** across **2,689,616 calls**, `get_contract_data` at **1,000.265 ms** across **86,580 calls**, `has_contract_data` at **503.453 ms** across **60,073 calls**, `ScVal to Val` at **721.780 ms**, and `Val to ScVal` at **653.180 ms**. The call graph is an `applyLedger` descendant through `applySorobanStageClustersInParallel` -> worker `parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> Rust `invoke_host_function` -> SAC built-in dispatch.

This is distinct from the failed `001-sac-transfer-address-classification.md` record. That investigation targeted only the event helper's impossible-issuer fast path and failed because soroswap transfers commonly have account endpoints. This hypothesis targets a broader repeated-decoding pattern across balance authorization, trustline/account balance updates, asset reads, metadata reads, and event emission; account endpoints are still in scope because the account path is exactly where `read_asset`, trustline authorization, and repeated `Address::to_sc_address` calls occur.

## Anti-Evidence

Only a subset of the large `visit host object`, conversion, and storage zones belongs to SAC address/metadata reads; guest maps, contract vectors, auth, and generic storage also use the same zones. Budget/resource semantics are also consensus-visible: if the PoC skips object visits or storage reads entirely, it may change returned `cpu_insns`/`mem_bytes` and resource-limit behavior. A behavior-preserving implementation should either replay equivalent metering or demonstrate that p26 intentionally accepts the reduced metering; otherwise reviewers may reject it even if wall-clock improves.
