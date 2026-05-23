# H002: Use Typed Native Pair Instance Storage for Soroswap Swap

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding generic `InstanceStorageMap` lookups/inserts in the accepted native pair `swap` path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a matching next-protocol native Soroswap pair `swap`, the host should read token addresses and reserves, validate output amounts, perform the SAC transfer, read post-transfer balances, update reserves, emit the pair event, and persist the pair instance storage exactly as the current native path does. Because the native gate already requires the fixed vendored pool storage layout, the implementation should not repeatedly access the pair instance through generic `Val` keys and `MeteredOrdMap` operations when a typed `{token_0, token_1, reserve_0, reserve_1, k_last}` view can be validated once and written back once.

## Mechanism

At accepted p26 commit `fbbea0d9`, `call_native_soroswap_pool_swap` repeatedly calls `soroswap_pool_instance_storage_get`, which builds `Val::from_u32(key)` and calls `with_instance_storage(|s| s.map.get(&key, self))` for token/reserve keys. After computing new balances, it updates reserves through two functional `s.map.insert(...)` calls. For the exact native pair layout, decoding the instance `ScMap` once into a typed local struct and persisting the updated reserve fields once should remove repeated generic map lookups, value conversions, and immutable-map rebuilds while preserving deterministic event and ledger-entry output.

## Trigger

Run the current accepted soroswap workload (`soroswap-tx-2000-t-8`) under the diagnostic Tracy trace. Successful native pair swaps call `soroswap_pool_instance_storage_get` for key 0 during initialization checks, keys 2/3 for reserves, keys 0/1 for token addresses, then mutate keys 2/3 through `MeteredOrdMap::insert`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:893-929` — native-gate helpers scan `ScMap` by integer storage key to validate the exact pool layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:969-1009` — `soroswap_pool_instance_storage_get` converts each integer key into `Val` and performs a generic instance map lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1076-1304` — `call_native_soroswap_pool_swap` repeatedly reads typed pair fields, writes reserves through two generic inserts, and emits the swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1257-1266` — reserve writeback rebuilds the instance map twice with `s.map.insert`.

## Evidence

The target sits inside `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel`, not TX-set construction. Timestamp filtering against `applyLedger` windows shows the apply-contained Rust host storage/map envelope is still large: `storage get` totals 672,084,842 ns, `map lookup` totals 1,223,514,982 ns, `map lookup indexed` totals 585,969,208 ns, and `new map` totals 461,915,256 ns inside apply windows. The accepted native pair path already proves the vendored pair layout can be hash/symbol/layout gated safely; a typed pair-instance view narrows the remaining generic map work for that same path rather than introducing a new native contract.

## Anti-Evidence

These aggregate map zones include much more than pair instance storage, so the reviewer should isolate native-pair key 0/1/2/3/5 accesses before promotion. The typed view must preserve metered behavior or remain explicitly next-protocol gated, must keep malformed instance layouts on the existing Wasm fallback/error path, and must write back an `ScMap` that is byte-equivalent to the current generic `InstanceStorageMap` persistence path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `002-raw-native-pair-instance-storage.md`
**Failed At**: reviewer

### Trace Summary

The source tree under review does not contain the claimed production native Soroswap pair path. `Host::call_contract_fn` retrieves the contract instance and dispatches only to Wasm execution or the Stellar Asset Contract; the only non-Wasm native Rust contract frame is test-only. Generic instance-storage `MeteredOrdMap` gets/inserts do exist for normal Wasm instance storage, but there is no `call_native_soroswap_pool_swap`, `soroswap_pool_instance_storage_get`, `try_call_native_soroswap_pool_swap`, or equivalent production branch that could be specialized into a typed pair view. This is substantially the same already-recorded failure as `002-raw-native-pair-instance-storage.md`: optimizing native pair instance storage is blocked until a native Soroswap pair implementation exists in the reviewed p26 source.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:75,97` — prior ledger failure history already rejects raw/native pair instance-storage optimizations because the p26 source has no native Soroswap pair/router/SAC helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-149` — production frame variants are `ContractVM`, `HostFunction`, and `StellarAssetContract`; `TestContract` is compiled only for test/testutils, and there is no production `NativeContract` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` loads the instance, copies arguments, then matches only `ContractExecutable::Wasm` or `ContractExecutable::StellarAsset`; no Soroswap hash/symbol/layout gate or native swap helper exists.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1279` — instance storage is lazily materialized from the active frame and persisted through the normal host storage path, confirming the generic map semantics but not the claimed native-pair helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — `with_instance_storage` and `with_mut_instance_storage` expose the current contract's generic `InstanceStorageMap`, marking mutable access modified.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2207,2231-2263` — Wasm-facing instance storage reads and writes do use `s.map.get` and `s.map.insert`, but these are generic host functions invoked by Wasm, not the absent native Soroswap pair swap implementation.

### Why It Failed

The hypothesis is not novel and the target code path is absent. It is a follow-on of the retained ledger failure `002-raw-native-pair-instance-storage.md`, which already investigated and rejected native pair instance-storage specialization because the reviewed checkout has no production native Soroswap pair swap path. Since the current soroswap benchmark executes official Soroswap Wasm through the generic host path, this proposal would require adding a new native Soroswap contract implementation rather than optimizing existing typed native pair storage.

### Lesson Learned

Before proposing Soroswap native-path storage optimizations, first confirm the exact production native Soroswap branch and helper names exist in the p26 source under review. Aggregate map lookup/insert Tracy totals are not sufficient evidence for a native pair specialization when the only actual path is generic Wasm instance storage.
