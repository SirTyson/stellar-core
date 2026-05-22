# H001: Raw Native Pair Swap Instance Storage View

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing residual instance-storage map materialization, host-value conversion, and immutable-map rebuilds from the accepted native pair `swap` path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a next-protocol native Soroswap pair `swap` hit, the host should read the pair token addresses and reserves from the already-gated raw `ScContractInstance.storage`, execute the same checks and SAC subcalls, update reserve keys 2 and 3, and emit the same event while preserving the current native frame, rollback, and fallback behavior. Released p26 ledgers and non-matching hashes, symbols, argument shapes, or instance layouts should continue to execute the Wasm path unchanged.

## Mechanism

The accepted native `swap` gate validates the raw pair `ScMap` layout before entering the native frame, but `call_native_soroswap_pool_swap` then discards those extracted facts and re-reads keys through `soroswap_pool_instance_storage_get`. That path lazily materializes the whole instance `ScMap` into `InstanceStorageMap`, converts every key/value to host `Val`, performs repeated `MeteredOrdMap` lookups, and updates reserves with two immutable `insert` rebuilds before frame pop converts the modified host map back to `ScMap`. A native `SoroswapPairInstanceView` carried from the raw gate into the frame, plus a direct reserve-update helper for keys 2 and 3, should remove much of this residual work without changing deterministic ledger output.

## Trigger

Run the current next-protocol soroswap apply-load scenario (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Each measured swap reaches `Host::try_call_native_soroswap_pool_swap` for the vendored pair Wasm hash and then executes the residual native body once inside the `applyLedger` parallel worker path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1070` at p26 commit `03d78248` — native pair `swap` gate validates the exact hash, symbol, arity, argument shape, and raw storage layout, then clones the instance into a native frame without carrying the decoded fields.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:966-1008` at p26 commit `03d78248` — `soroswap_pool_instance_storage_get` and typed wrappers re-enter frame instance storage for each token/reserve lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1073-1153,1254-1263` at p26 commit `03d78248` — native swap re-reads reserves and token addresses, then updates reserve keys through two `MeteredOrdMap::insert` calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` — lazy instance-storage materialization converts the whole raw `ScMap` into host `Val`s and marks mutable access as modified.

## Evidence

The current apply-window Tracy aggregation confirms these residual categories remain descendants of `applyLedger`: `ScVal to Val` totals 1.027s over 758,894 events, `Val to ScVal` totals 371.5ms, `new map` totals 413.5ms, `map lookup indexed` totals 547.0ms, and `map lookup` totals 572.8ms. The native pair source directly exercises these categories after the raw-layout gate: first access to instance storage materializes the map, subsequent key reads search it, reserve update rebuilds it twice, and frame pop must persist the modified storage. Because this path runs once per soroswap transaction and is already next-protocol gated, a raw typed view can trade protocol metering exactly where the accepted native pair swap already does.

## Anti-Evidence

The broad Tracy zones also include SAC, router, event, and generic storage work, so a PoC must add narrow spans or counters around native pair instance materialization and reserve persistence. Direct raw reserve persistence must preserve native-frame rollback: failed swaps must leave the pair instance unchanged, and successful swaps must leave the same sorted `ScMap` representation as the current `InstanceStorageMap` persistence. If narrow measurement shows the pair-owned share of `ScVal to Val`/`new map`/lookup work is below the 3% floor, this should be demoted.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact instance-storage-view optimization; related native-Soroswap records already flag the same false premise that a native pair `swap` helper exists
**Failed At**: reviewer

### Trace Summary

The Soroban apply path reaches the p26 host through `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, the C++/Rust bridge, `invoke_host_function_or_maybe_panic`, and finally `Host::invoke_function`. Top-level `InvokeContract` calls go through `call_n_internal` and `call_contract_fn`, where this checkout dispatches `ContractExecutable::Wasm` only by instantiating a `Vm` and pushing `Frame::ContractVM`; the only production native contract branch is `ContractExecutable::StellarAsset`. The generic instance-storage inefficiency described in the hypothesis is real for Wasm host storage calls, but the claimed native Soroswap pair `swap` gate, `call_native_soroswap_pool_swap`, and `soroswap_pool_instance_storage_get` functions do not exist in the traced source tree, so there is no accepted native swap body to optimize.

### Code Paths Examined

- `src/transactions/TransactionFrame.cpp:2385-2430` — parallel Soroban transactions dispatch their single operation through `op->parallelApply` inside the apply worker.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` — parallel invoke-host-function apply calls `rust_bridge::invoke_host_function` with the host function, footprint entries, auth, ledger info, PRNG seed, and module cache.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge code builds the budget/config context and calls `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-485` — host invocation builds enforcing storage, installs auth/ledger info/module cache, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts XDR args to host values and enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` dispatches every `ContractExecutable::Wasm` through `instantiate_vm` and `Frame::ContractVM`; only SAC uses `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` — production frame variants are `ContractVM`, `HostFunction`, and `StellarAssetContract`; there is no native Soroswap frame or native pair swap context.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:46-67` — instance storage is lazily materialized by converting every raw `ScMap` key/value to host `Val`, and mutable access marks the map modified.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2262` — instance `put_contract_data`, `has_contract_data`, and `get_contract_data` use `with_mut_instance_storage`/`with_instance_storage` and `MeteredOrdMap` lookups/inserts.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-222` — `MeteredOrdMap::insert` returns a rebuilt immutable map rather than mutating in place.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:522-543,1254-1277` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:278-288,407-455` — frame success persists modified instance storage by converting the host map back to `ScMap` through `Val to ScVal` conversion.
- `ai-summary/fail/soroban/001-exact-router-native-swap-plan.md:59-63` and `ai-summary/fail/soroban/002-fuse-native-soroswap-sac-subcalls.md:61-72` — prior reviews of adjacent native-Soroswap variants independently observed that the claimed accepted native pair `swap` helper is absent in this checkout.

### Why It Failed

The optimization target is not present. The current p26 host has generic Wasm execution plus SAC native dispatch; searches for `try_call_native_soroswap`, `call_native_soroswap`, `soroswap_pool_instance_storage_get`, `SoroswapPairInstanceView`, `NativeContract`, and `soroswap` found no production native Soroswap pair `swap` implementation. Because the supposed residual work occurs only inside a nonexistent accepted native `swap` body, there is no viable code path where carrying a raw `SoroswapPairInstanceView` from the gate into the native frame could reduce soroswap apply time.

The underlying generic instance-storage costs do exist, but optimizing them broadly would be a different hypothesis with protocol-visible metering and severity constraints. On the actual apply path, pair `swap` remains a Wasm contract call; instance-storage host functions are invoked from Wasm through the standard frame/storage machinery, and direct raw reserve persistence would require introducing the same native Soroswap semantic/metering design already retained as under-specified in prior native-bypass reviews.

### Lesson Learned

Before proposing residual cleanup under a native Soroswap implementation, first verify that the native implementation exists in the traced checkout. Aggregate `ScVal to Val`, `Val to ScVal`, map construction, and lookup Tracy totals are not enough to justify a Soroswap-specific optimization when the claimed hash-gated native pair frame and helper functions are absent; future work must either complete the native-Soroswap precompile specification or target the generic instance-storage path directly with exact metering and Medium-threshold measurements.
