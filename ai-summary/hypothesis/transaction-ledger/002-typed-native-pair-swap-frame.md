# H002: Typed Native Soroswap Pair Swap Frame

**Date**: 2026-05-23
**Subsystem**: transaction-ledger / soroban-env apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing generic instance-storage and event-building work from the accepted native pair swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the next-protocol native Soroswap pair `swap` hook recognizes the canonical pair Wasm hash, `swap` symbol, three-argument shape, and instance-storage layout, it should produce the same reserves update, SAC transfer side effects, contract event, return value, and contract-error behavior as the current native emulation. It should not build generic `InstanceStorageMap` / `MeteredOrdMap` state or generic host-object event containers when the storage keys and event schema are fixed and already validated by the native hook.

## Mechanism

`try_call_native_soroswap_pool_swap` first validates the raw `ScContractInstance.storage` layout, but then enters a generic `Frame::NativeContract`; the first `soroswap_pool_instance_storage_get` lazily converts the same instance `ScMap` into an `InstanceStorageMap`, and the reserve update later rebuilds generic map state before persisting. The native path also constructs the fixed swap event through `symbol_new_from_slice`, `vec_new_from_slice`, and `map_new_from_slices`. A typed native pair frame could carry the already-validated token/reserve values, update keys 2 and 3 directly in a fixed `ScMap` representation, and emit the fixed event through a protocol-gated direct representation, removing generic map conversion/lookup/insert/event-object work from every soroswap swap while keeping the same observable ledger and event XDR.

## Trigger

Run the current soroswap apply-load scenario on the accepted native-pair baseline. The hot path is a native `swap` per transaction that still performs generic instance-storage access and event construction inside the `invoke_host_function` apply subtree.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native pair swap recognizer validates hash, symbol, argument shape, and raw instance-storage layout before entering a generic native frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1304` — native pair swap body repeatedly calls `soroswap_pool_instance_storage_get`, updates reserves via `with_mut_instance_storage`, and builds the fixed swap event through generic host containers.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1882` — lazy instance-storage conversion and persistence path used by the native swap body.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` — `InstanceStorageMap::from_instance_xdr` converts every instance-storage pair from `ScVal` to `Val` and constructs a `MeteredOrdMap`.

## Evidence

The current source now contains the accepted native Soroswap pool getter and pair-swap hooks, so the previous "hook absent" rejection no longer applies to this code path. Tracy self-time inside the apply subtree still shows broad residual generic host categories that this path exercises: `ScVal to Val` (493.9 ms), `Val to ScVal` (249.3 ms), `new map` (350.8 ms), `map lookup indexed` (441.2 ms), and `write xdr` (160.3 ms) in the soroswap trace. The native swap source structurally confirms fixed-key instance reads (0/1/2/3), fixed-key reserve writes (2/3), and fixed-schema event construction on every matched swap.

## Anti-Evidence

Prior narrower hypotheses around invocation-scoped pool view caches and direct event construction were either below threshold or rejected when native hooks were absent. This hypothesis must therefore be implemented as a combined typed-frame path, not a single lookup cache or event-only refactor, and it must be protocol-gated because generic instance-storage conversion and event construction are budget-visible. The reviewer should add narrow spans or counters around the native swap body to confirm that the fixed-storage plus fixed-event subset clears the Medium floor before PoC.
