# H001: Raw native pair-swap instance storage view and reserve update

**Date**: 2026-05-22
**Subsystem**: transaction-ledger / Soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing residual instance-storage map materialization and whole-map conversion in the native pair `swap` path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a next-protocol native Soroswap pair `swap` hit, the host should read the pair's token addresses and reserves from the already-validated raw `ScContractInstance.storage` map, execute the same swap checks and SAC subcalls, and persist the updated reserve entries without materializing the whole instance storage as a host `MeteredOrdMap`. The resulting instance `ScMap`, events, return value, TTL effects, and fallback behavior should match the current native pair-swap implementation for every matching benchmark call.

## Mechanism

The accepted native pair `swap` gate validates that raw instance storage contains token addresses and reserve `i128`s, but then discards those values. `call_native_soroswap_pool_swap` immediately re-enters `soroswap_pool_instance_storage_get`, which lazily converts the entire instance `ScMap` to `InstanceStorageMap`, performs `MeteredOrdMap` lookups, updates reserves with two `insert` calls, and later converts the whole host map back to `ScMap` during frame pop. A `SoroswapPairInstanceView` built once from the raw `ScMap`, plus a specialized reserve-update helper that mutates/persists the two raw reserve slots directly, would remove this repeated `ScVal`/`Val` conversion and persistent-map rebuild while preserving deterministic ordering and next-protocol gating.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) on the accepted p26 commit `03d78248`. Each generated swap reaches `try_call_native_soroswap_pool_swap`, validates the pair instance layout, and then executes `call_native_soroswap_pool_swap` once inside the `applyLedger` parallel Soroban worker path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1070` — native pair `swap` gate validates raw storage layout, then enters a native frame without carrying extracted token/reserve values.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1073-1127` — native swap re-reads reserves and token addresses via `soroswap_pool_instance_storage_get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1254-1263` — reserve update uses `with_mut_instance_storage` and two `MeteredOrdMap::insert` rebuilds.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1771-1786,1833-1849` — first instance-storage access materializes `InstanceStorageMap`; frame pop persists modified storage by converting the host map back to `ScMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — `with_instance_storage` / `with_mut_instance_storage` force lazy materialization and mark the whole instance map modified.

## Evidence

Timestamp filtering of the current soroswap Tracy trace against `applyLedger` windows confirms the relevant residual storage/conversion categories are in scope: `ScVal to Val` **1,027.178 ms**, `Val to ScVal` **396.572 ms**, `map lookup indexed` **547.023 ms**, `new map` **413.548 ms**, `storage get` **633.937 ms**, and `storage put` **124.938 ms** all occur inside `applyLedger`. The native pair-swap source exercises these exact categories after the raw-layout check: instance storage is converted to host values for reads, updated through an immutable metered map, then converted back to XDR for persistence. Even a partial removal of the pair-swap-owned share of those categories is plausibly in the 3-10% band after 8-way worker normalization because the affected path runs once per soroswap transaction.

## Anti-Evidence

The broad Tracy categories include SAC transfer, router, event, and generic storage work, so the PoC must add narrow spans or counters around native pair instance materialization and reserve persistence before claiming the whole category. Budget accounting is protocol-visible: the optimization must either reproduce the current next-protocol charges for the native pair path or intentionally update metering under the same next-protocol gate. The direct reserve update must preserve frame rollback semantics; if `persist_instance_storage` is bypassed, the replacement must still leave outer frames and same-contract re-entry reloads with the correct updated instance view.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of the previously failed native Soroswap precompile / raw-native pool instance investigations, especially `ai-summary/fail/transaction-ledger/002-raw-native-pool-getter-instance-view.md` and `ai-summary/fail/transaction-ledger/summary.md` entry 16
**Failed At**: reviewer

### Trace Summary

The soroswap benchmark creates top-level router `swap_exact_tokens_for_tokens` invoke-host-function transactions that include the pair contract instance as read-write footprint state. In apply, `InvokeHostFunctionOpFrame::doParallelApply` crosses into the p26 Rust host, `HostFunction::InvokeContract` calls `call_n_internal`, and production `call_contract_fn` dispatches contract instances only as Wasm or built-in Stellar Asset contracts. The claimed `try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_swap`, `soroswap_pool_instance_storage_get`, and `SoroswapPairInstanceView` paths are absent, so there is no native pair-swap residual instance-storage materialization to optimize.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/002-raw-native-pool-getter-instance-view.md:52-75` — prior adjacent raw-native pool getter investigation already found that native Soroswap hooks are absent from the checked-out p26 host.
- `ai-summary/fail/transaction-ledger/summary.md:194` — records the broader native Soroswap precompile blocker: opaque vendored Wasm cannot be safely replaced by a production hash-keyed native precompile without audited source and equivalence coverage.
- `src/simulation/ApplyLoad.cpp:2855-2913` — soroswap setup uploads factory, pair, and router Wasm blobs from `rust_bridge::get_apply_load_soroswap_*_wasm`, establishing these as normal Wasm contracts.
- `src/rust/src/soroban_test_wasm.rs:122-138` and `src/rust/apply-load-wasm/README.md:1-6` — the Soroswap factory/pool/router code is included as official Mainnet Wasm downloads, not in-tree native Rust implementations.
- `src/simulation/ApplyLoad.cpp:3381-3505` — each benchmark transaction invokes the router's `swap_exact_tokens_for_tokens`, includes SAC and pair footprint entries, and marks the pair contract instance read-write; it does not target a native pair entry point directly.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — the C++ Soroban helper serializes host function, resources, footprint entries, TTL entries, auth, ledger info, and module cache before calling `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban apply reaches this helper through `doParallelApply`, placing the host invocation inside the objective's parallel close-ledger path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — the Rust bridge builds enforcing storage and calls `Host::invoke_function` for each invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` — `HostFunction::InvokeContract` converts the contract address, function symbol, and arguments, then dispatches through `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-function checks, reentry policy, diagnostics, and only a test/testutils native-contract dispatch before falling through to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785` — production `call_contract_fn` retrieves the contract instance and dispatches `ContractExecutable::Wasm` via `instantiate_vm`/`Frame::ContractVM`, or `ContractExecutable::StellarAsset` via the built-in SAC; no Soroswap code-hash swap gate exists.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211,1254-1278` — generic instance storage is lazily materialized with `InstanceStorageMap::from_instance_xdr` and persisted by converting a modified host map back to `ScMap`, but this is reached through normal Wasm storage APIs rather than any native Soroswap swap helper.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — `InstanceStorageMap` construction and mutable access have the generic materialization/modified-map behavior described by the hypothesis, but no native pair-swap code path consumes them.

### Why It Failed

The optimization target does not exist in the source under review. The local `frame.rs` line ranges named by the hypothesis contain generic Wasm/SAC dispatch, host-function invocation, and generic instance-storage persistence, not native Soroswap pair-swap functions. Repository search found no `try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_swap`, `soroswap_pool_instance_storage_get`, or `SoroswapPairInstanceView` symbols. Because the pair contract still executes as opaque Wasm, removing residual storage conversion from a hypothetical native pair-swap body would require first adding the same class of code-hash native Soroswap precompile already rejected as unsafe without audited equivalence coverage.

### Lesson Learned

Follow-on raw instance-storage optimizations must first verify that the native Soroswap hook exists in the reviewed tree. In this branch, pair storage is reachable through normal Wasm contract execution and generic host storage APIs only; proposals that assume accepted native Soroswap pair/getter paths are duplicates of the earlier native-precompile failure mode, not actionable apply-path optimizations.
