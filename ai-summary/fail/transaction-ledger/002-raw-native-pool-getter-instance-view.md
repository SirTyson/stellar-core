# H002: Return native Soroswap pool getters from raw instance storage without per-getter map materialization

**Date**: 2026-05-22
**Subsystem**: transaction-ledger / Soroban host invocation
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing residual storage-map decode, lookup, and repeated TTL work in the accepted native pool-getter path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Native Soroswap pool getters should preserve the accepted next-protocol behavior while returning fixed pool fields directly from the validated pool `ScContractInstance.storage` map. For a matching pool code hash and getter symbol, the host should extend the pool instance/code TTL as required, push the same native contract frame, and return the same token/factory/reserve/k_last values without constructing a fresh `InstanceStorageMap` and searching it for every getter.

## Mechanism

The accepted native getter path already receives the contract `ScContractInstance` before entering the native frame and validates the raw `ScMap` layout in `soroswap_pool_instance_matches_getter`. It then calls `call_native_soroswap_pool_getter`, which extends current-contract instance/code TTL and uses `soroswap_pool_instance_storage_get` -> `with_instance_storage(|s| s.map.get(...))`, forcing lazy instance-storage materialization and metered map lookup for every zero-argument getter.

Instead, `try_call_native_soroswap_pool_getter` can extract a typed `SoroswapPoolInstanceView` from the raw `ScMap` once, pass the needed value into the native frame, and coalesce the mandatory TTL extension to once per pool contract per host invocation (or otherwise prove the duplicate extensions are semantically no-ops). This preserves deterministic return values and the native-frame semantics while cutting residual `ScVal to Val`, `new map`, `map lookup indexed`, and `extend_current_contract_instance_and_code_ttl` work that remains after the VM-instantiation win.

## Trigger

Run the current soroswap apply-load benchmark from `CURRENT_STATE.md`. Router execution repeatedly calls native-emulated pool getters (`token_0`, `token_1`, `factory`, `get_reserves`, `k_last`) against the same pair instances during `closeLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:816-848` — `try_call_native_soroswap_pool_getter` gates the accepted native getter path and already has the raw `ScContractInstance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:869-905` — raw `ScMap` layout validation scans known pool storage keys before the getter is called.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:907-943` — `call_native_soroswap_pool_getter` performs per-getter TTL extension and dispatches to storage lookups.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:945-987` — `soroswap_pool_instance_storage_get` materializes/searches instance storage through `with_instance_storage` for values already present in the validated raw instance.

## Evidence

- The accepted trace shows native pool getters are active: `Vm::instantiate_wasmi` dropped from the previous accepted trace's **20,389** in-apply instantiation events to **14,040**, implying roughly **6,349** getter calls now bypass Wasm but still execute the residual native getter body.
- In the current soroswap trace, apply descendants still include `extend_current_contract_instance_and_code_ttl` at **890.843 ms total / 390.272 ms self** over **41,981** calls, `map lookup indexed` at **579.551 ms total**, `new map` at **484.740 ms total**, and `ScVal to Val` at **1,074.400 ms total**. The native getter body directly exercises these categories through TTL extension, instance storage materialization, typed validation, and return construction.
- This is narrower than the rejected generic no-op TTL and storage-map lookup ideas: it uses the accepted exact-code-hash native getter gate, fixed raw pool layout, and known getter set, so it can avoid generic `InstanceStorageMap` construction only in the soroswap-native path.

## Anti-Evidence

- The full trace categories include non-getter work from SAC, router, pair, and generic host execution. A PoC must add narrow native-getter spans/counters to isolate the getter-only share before claiming the full category reduction.
- TTL extension coalescing must be carefully scoped. The safe minimum is to preserve one instance/code TTL extension per pool contract before any getter returns; skipping all extensions would change ledger effects when the threshold is crossed.
- If router-native specialization lands first, it may remove many pool getter calls entirely, making this residual native-getter cleanup less additive.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — exact raw-native-pool-getter residual optimization was not present in target fail/success records, though adjacent native-precompile and instance-storage decode failures exist
**Failed At**: reviewer

### Trace Summary

The close-ledger soroswap path applies `INVOKE_HOST_FUNCTION` operations through `InvokeHostFunctionOpFrame::doParallelApply`, crosses into the p26 Rust host via `e2e_invoke::invoke_host_function`, and dispatches `HostFunction::InvokeContract` through `Host::call_n_internal`. In the checked-out p26 source, `call_contract_fn` retrieves the contract instance and then dispatches only two production executable types: `ContractExecutable::Wasm` instantiates a VM and invokes Wasm, while `ContractExecutable::StellarAsset` enters the built-in SAC frame. The claimed `try_call_native_soroswap_pool_getter`, raw layout validator, native getter dispatcher, and `SoroswapPoolInstanceView` code paths do not exist in this source tree, so there is no accepted native pool-getter body whose residual `InstanceStorageMap` materialization can be optimized.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:40` — prior instance-storage decode caching was rejected because `InstanceStorageMap::from_instance_xdr` performs protocol-visible metered conversion/allocation; this is adjacent but not the exact claimed native getter residual path.
- `ai-summary/fail/transaction-ledger/summary.md:74,194` — prior Soroswap router/pair native precompile work was rejected because the workload uses opaque vendored Wasm blobs without an audited equivalence harness.
- `src/simulation/ApplyLoad.cpp:3381-3505` — the benchmark constructs top-level router `swap_exact_tokens_for_tokens` Soroban transactions with router/pair/SAC footprint entries; pair/pool execution is reached as normal contract execution from the router.
- `src/rust/src/soroban_test_wasm.rs:122-138` — Soroswap factory, pool, and router contracts are embedded as Wasm byte arrays via `include_bytes!`, not as in-tree native contract implementations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ serializes host function, resources, footprint entries, TTL entries, auth, and ledger info, then calls `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban operations use `doParallelApply`, placing the Rust host invocation inside the parallel apply worker path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — the Rust bridge builds enforcing storage and invokes `Host::invoke_function` for each Soroban operation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` — `HostFunction::InvokeContract` converts the contract ID, function symbol, and arguments, then calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-function checks, reentry checks, diagnostics, test-only native-contract dispatch behind `test`/`testutils`, and then calls `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785` — production `call_contract_fn` retrieves the `ScContractInstance` and dispatches either to Wasm VM instantiation/invocation or to the built-in Stellar Asset Contract; there is no Soroswap code-hash getter gate before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — instance storage is lazily materialized from the current frame's `ScContractInstance` only when generic instance-storage access occurs.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:29-66` — `InstanceStorageMap::from_instance_xdr` converts each raw instance-storage `ScMap` key/value into host `Val`s and builds a `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2200-2264` — generic instance `has/get_contract_data` uses `with_instance_storage` and `s.map.get`, but this path is invoked by Wasm/host storage APIs rather than by any native Soroswap getter dispatcher in the checked-out source.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2335` — `extend_current_contract_instance_and_code_ttl` extends the current contract instance and code TTL; no native Soroswap getter path coalesces or wraps this call in the source under review.

### Why It Failed

The core mechanism depends on a prerequisite accepted native pool-getter implementation that is absent from the actual p26 host source. The local `frame.rs` line range named by the hypothesis contains the generic Wasm instantiation path, not `try_call_native_soroswap_pool_getter` or related helpers, and a repository search found no Soroswap-native getter symbols. Without that native path, pool getters still execute as Wasm contract calls, so there is no residual native getter `with_instance_storage` lookup to remove. Adding the missing native code-hash pool precompile first would fall back into the already-failed native Soroswap precompile class, which requires audited contract-source equivalence that this hypothesis does not supply.

### Lesson Learned

Do not write follow-on optimizations against accepted native Soroswap hooks unless the hook is present in the source tree being reviewed. For this workload, raw instance-storage shortcuts are only actionable after a real, audited, protocol-gated native getter path exists; otherwise the optimization target is either nonexistent or a duplicate of the previously rejected native precompile direction.
