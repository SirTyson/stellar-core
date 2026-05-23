# H001: Typed Native Soroswap Instance Frame

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing whole-instance `ScVal` -> `Val` materialization and generic map lookups from the next-protocol native Soroswap getter/swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol native Soroswap pool getter and pair `swap` calls, the host should preserve the same protocol-gated frame/auth/TTL/rollback behavior and the same final storage/event outputs, while reading the fixed pair instance fields (`token_0`, `token_1`, reserves, `factory`, `k_last`) through a typed native view rather than constructing a full `InstanceStorageMap` for every native frame.

## Mechanism

The accepted native path first retrieves a full `ScContractInstance`, validates the fixed Soroswap layout from its `ScMap`, then pushes `Frame::NativeContract` and calls `soroswap_pool_instance_storage_get`, which lazily converts the whole instance storage map into host `Val`s through `InstanceStorageMap::from_instance_xdr`. This repeats conversion and `MeteredOrdMap` lookup work for fields that were already inspected in the source `ScMap`; a new next-protocol native frame variant can carry typed borrowed/cloned field values from the validated `ScMap`, initialize mutable instance storage only if fallback/reentrancy requires it, and write the two reserve fields back with a narrow typed path on successful native `swap`.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload (`soroswap, TX=2000, T=8`). Every matching vendored pool getter and native pair `swap` currently enters `try_call_native_soroswap_pool_getter` / `try_call_native_soroswap_pool_swap`, validates the `ScContractInstance.storage` layout, and then re-reads the same values through `with_instance_storage`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` - `call_contract_fn` retrieves and clones the full instance before trying the native fast paths.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-972` - native getter validation reads the `ScMap`, then the getter body re-reads via `soroswap_pool_instance_storage_get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` - native `swap` validates token/reserve fields, then performs additional instance-map gets and two generic inserts for reserve updates.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` - `maybe_init_instance_storage` converts frame `ScContractInstance.storage` into `InstanceStorageMap` on first access.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` - `ScVal to Val` conversion zone targeted by avoiding whole-map instance conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,325-339` - `new map` and `map lookup indexed` zones targeted by avoiding generic host-map construction/lookups for fixed native fields.

## Evidence

The current accepted soroswap Tracy trace reports apply-contained work in the relevant zones: `ScVal to Val` has 493.9 ms self-time at `host/conversion.rs:436` (1.144 s total inside `applyLedger`), `new map` has 350.8 ms self-time at `host/metered_map.rs:148` (461.9 ms inside `applyLedger`), and `map lookup indexed` has 441.2 ms self-time at `host/metered_map.rs:330` (586.0 ms inside `applyLedger`). Source inspection shows the native Soroswap fast paths already have the `ScContractInstance.storage` `ScMap` at dispatch time and already validate the exact keys needed by the getter/swap bodies, so the later host-map conversion is redundant for the accepted fixed-code-hash native path.

## Anti-Evidence

A previous Soroswap pair instance-storage specialization was rejected because broad conversion/map zones overstated the pair-specific subset. This hypothesis must therefore be reviewed with focused instrumentation that counts only native getter/swap frames and proves the typed frame removes a large enough subset; it must also preserve rollback if a native `swap` fails after reserve mutation, and it must remain gated to the next protocol because instance-storage metering will change.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated

### Trace Summary

The current accepted p26 native Soroswap path retrieves a `ScContractInstance`, validates the pool layout directly from its `ScMap`, then pushes `Frame::NativeContract` carrying the full instance. Both native getters and native `swap` then call `soroswap_pool_instance_storage_get`, which enters `with_instance_storage`, lazily converts the entire instance `ScMap` into an `InstanceStorageMap`, and performs generic `MeteredOrdMap` lookups for fields already identified during validation. The `swap` path also rebuilds the generic host map twice to replace reserve keys 2 and 3 before `persist_instance_storage` converts the host map back to `ScMap`. This is inside the next-protocol `closeLedger` apply path for every accepted native getter/swap frame, so the inefficiency is real and hot.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` - `call_contract_fn` retrieves the contract instance, checks the native getter path, then the native swap path, before falling back to VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872` - `try_call_native_soroswap_pool_getter` gates on next protocol, exact pool hash, getter symbol, and instance layout, then pushes `Frame::NativeContract` with a metered clone of the full instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-972` - native getter layout checks read `ScContractInstance.storage` directly as `ScMap`, but getter execution re-enters `soroswap_pool_instance_storage_get` and pays frame-local instance-storage initialization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` - `try_call_native_soroswap_pool_swap` validates argument shape and the token/reserve keys from the same source `ScMap`, then pushes `Frame::NativeContract` with the full instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1266` - native `swap` re-reads token/reserve keys through `soroswap_pool_get_required_val`, then performs two generic `MeteredOrdMap::insert` rebuilds for reserve updates.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` - first instance-storage access calls `maybe_init_instance_storage`, which constructs `InstanceStorageMap` from the frame instance.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` - `InstanceStorageMap::from_instance_xdr` converts every instance-storage key and value through `to_valid_host_val` and builds a metered host map.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` - each `ScVal` to `Val` conversion enters the traced `ScVal to Val` zone.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,196-242` - host map construction and lookup/insert paths account for the targeted `new map` and generic lookup/rebuild costs.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:437-630,1866-1885` - `with_frame` handles rollback and persists modified instance storage on success; any typed reserve writeback must preserve this success-only behavior and same-contract parent reload semantics.

### Findings

- **Inefficiency exists**: YES. The native fast path validates the needed instance fields from `ScMap`, then immediately pays to materialize the whole same map as `Val` pairs and search it again through `MeteredOrdMap`.
- **Hot path**: YES. This is reached by the accepted native Soroswap pool getter and pair `swap` paths used by the benchmark's `closeLedger` apply flow, after the exact Wasm-hash/next-protocol gates have already selected the optimized native execution path.
- **Existing optimizations**: PARTIAL but insufficient. The accepted direct SAC balance optimization already avoids a full instance clone for SAC executable checks, but the pair's own `Frame::NativeContract` still stores the full `ScContractInstance` and initializes `InstanceStorageMap` on first read.
- **Correctness constraints**: A typed frame is feasible, but the PoC must preserve `with_frame` rollback, auth push/pop, trace formatting, current-contract identity, TTL extensions, contract error behavior, and same-contract parent storage reload after a successful reserve mutation. The change must remain next-protocol gated because it intentionally changes protocol-visible metering.
- **Impact estimate**: Medium. The source path executes once per native getter frame and once per native swap frame, and each initialization converts all instance storage entries even when the getter needs one or two fields. The broad Tracy zones are not sufficient by themselves, but the targeted subset is a high-frequency native Soroswap frame cost with enough repeated `ScVal` conversion, host-map construction, lookup, and two reserve-update rebuilds to plausibly clear the objective's 3% floor.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, especially `Frame`, `try_call_native_soroswap_pool_getter`, `try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_getter`, `call_native_soroswap_pool_swap`, `maybe_init_instance_storage`, and `persist_instance_storage`. Touch `auth.rs`, `host.rs`, and `host/trace/fmt.rs` only as needed to support a typed native frame variant.
- **Change description**: Add a next-protocol-only typed native Soroswap frame/view that owns the validated token addresses, reserve values, factory, and optional `k_last` in XDR/typed form, and make native getter/swap reads use that view instead of `with_instance_storage`. For `swap`, update reserve keys 2 and 3 through a narrow success-only typed writeback that preserves rollback and reload behavior without constructing a full `InstanceStorageMap` unless a fallback/reentrant path genuinely needs it.
- **Correctness check**: Existing generic frame rollback, auth, storage, TTL, and Soroban host tests cover the surrounding invariants, but this native path has limited direct equivalence coverage. The PoC should add focused native-vs-Wasm equivalence tests for getter returns, successful reserve updates, event output, rollback on post-mutation failure, reentry/parent reload behavior if applicable, and fallback for malformed layouts.
- **Benchmark focus**: Instrument only accepted native Soroswap getter/swap frames to count avoided `InstanceStorageMap::from_instance_xdr`, `ScVal to Val`, `new map`, lookup, and insert rebuild work. Then run `scripts/run_apply_load_matrix.py` three non-Tracy times against the current `CURRENT_STATE.md` baseline and require a reproducible 3-10% soroswap median apply-time reduction.
