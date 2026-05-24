# H001: Native Soroswap Pool Raw Instance Storage

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic host-object/map work from the protocol-27 native Soroswap pool path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a protocol-27 Soroswap pool call matches the allowlisted pool Wasm hash and the fixed instance-storage schema, the native getter and `swap` path should produce the same return values, storage changes, events, error ordering, and deterministic ledger output as the current native emulation, while avoiding generic `ScVal` -> `Val` instance-storage materialization and repeated `MeteredOrdMap<Val, Val>` lookups for fixed integer keys.

## Mechanism

`call_contract_fn` first loads and clones the full `ScContractInstance`, then the native pool fast path clones it again into `Frame::NativeContract`; `maybe_init_instance_storage` lazily converts the instance `ScMap` to a host `InstanceStorageMap`, and `soroswap_pool_instance_storage_get` repeatedly looks up fixed keys through `MeteredOrdMap<Val, Val>`. The optimized path can keep a native-pool frame sidecar containing the already-validated raw `ScMap` fields (`token_0`, `token_1`, `reserve_0`, `reserve_1`, optional `k_last`, `factory`) and update reserves through a fixed-schema writer, preserving p26 behavior by remaining protocol-gated and preserving or intentionally rescheduling protocol-27 metering.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on protocol 27. Each accepted native pool getter or `swap` call on the allowlisted pool Wasm hash enters `try_call_native_soroswap_pool_getter` / `try_call_native_soroswap_pool_swap`, then accesses instance storage through the generic host map path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:790-817` - `call_contract_fn` retrieves the instance, builds `args_vec`, and checks native pool paths before VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` - native pool getter gate clones the instance into a `NativeContract` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` - native pool swap gate validates fixed storage shape and clones the instance into a `NativeContract` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` - fixed integer instance-storage reads go through `with_instance_storage` and `MeteredOrdMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1257-1266` - reserve updates rebuild the generic host map via two inserts.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:30-67` - `InstanceStorageMap::from_instance_xdr` converts every instance-storage `ScVal` pair into host `Val`s.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` - `maybe_init_instance_storage` performs the lazy generic conversion for each frame.

## Evidence

The current trace in `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` shows `ScVal to Val` at `host/conversion.rs:436` with 493.9ms self-time across 804,622 calls, `new map` at `metered_map.rs:148` with 350.8ms self-time, `map lookup` + `map lookup indexed` with 814.9ms self-time, and `add host object` at `host_object.rs:450` with 286.5ms self-time. Unwrapped timestamp checks place `ScVal to Val` (1.144s total duration) and `add host object` (373ms total duration) inside `applyLedger` windows, so this is not TX-set construction. The current native pool path is a good target because it knows the schema is exactly fixed u32 keys before it enters the generic map path.

## Anti-Evidence

This must not become another broad native Soroswap bypass: prior router/pair/SAC bypass proposals failed on incomplete semantic and metering specifications. The viable shape is narrower: keep the existing native pool semantics and only replace fixed-schema instance-storage representation inside that already-accepted protocol-gated path. The reviewer should require a clear metering plan because removing `to_valid_host_val`, map construction, or map lookup charges directly would change protocol-visible resource observations.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed path is real: `closeLedger` applies Soroban transactions through `InvokeHostFunctionOpFrame`, crosses the Rust bridge into `e2e_invoke::invoke_host_function`, and then `Host::invoke_function` reaches `call_contract_fn`. The native Soroswap pool gate validates the allowlisted Wasm hash and raw `ScMap` shape, but it still pushes `Frame::NativeContract` with a cloned `ScContractInstance`; the first native getter or swap storage read then calls `maybe_init_instance_storage`, converting the entire instance `ScMap` into `MeteredOrdMap<Val, Val>`. Subsequent fixed-key reads and reserve updates use the generic metered map path even though the keys and types have already been checked by the native-pool gate.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2915` — `applyTransactions` runs inside ledger close and dispatches Soroban phases that include the benchmarked invoke-host operations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply code calls `rust_bridge::invoke_host_function` with ledger entries, TTL entries, resources, auth, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — invoke-host apply adds the footprint, calls the Rust host, records storage changes, collects events, and finalizes success.
- `src/rust/src/soroban_proto_any.rs:391-451` — Rust bridge dispatch wraps protocol-specific host invocation and times the host function.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-575` — builds `Storage`, constructs `Host`, invokes the host function, finishes storage/events, and computes ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1733-1756` — `HostFunction::InvokeContract` converts args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-829` — `call_contract_fn` retrieves the full instance, checks native Soroswap pool getter/swap gates, and otherwise instantiates Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` and `1013-1073` — native getter/swap gates are protocol-27-only, hash/arg/schema-gated, and clone the instance into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-929` — the gate already reads the raw `ScMap` to validate fixed integer keys and value types.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` and `1076-1266` — native getter/swap implementation reads keys 0/1/2/3/4/5 through `with_instance_storage` and updates reserves through two `MeteredOrdMap::insert` calls.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:30-67` — `InstanceStorageMap::from_instance_xdr` converts every instance-storage key/value pair via `to_valid_host_val` and constructs a new metered map.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — immutable and mutable instance storage access lazily initializes generic storage and marks mutable access as modified.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1886` — frame storage is lazily initialized, then persisted by converting the generic host map back to `ScMap` and storing the contract instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160`, `168-242`, and `196-224` — map construction, lookup, and insert allocate/copy/charge through the generic sorted-vector map path.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-455` and `host_object.rs:446-457` — `ScVal` to `Val` conversion and address-object materialization account for the traced conversion/object work.

### Findings

The inefficiency exists and is on the soroswap apply hot path. The current native path deliberately avoids Wasm instantiation for protocol 27, but it still pays the generic instance-storage representation cost that a Wasm contract needs: full `ScMap` to host-`Val` conversion, `HostObject` allocation for address values, metered sorted-map construction, repeated binary-search lookups, and reserve updates through cloned map rebuilds. There is no cache or pool that removes this per-frame work; the `Context` starts with `storage: None`, and `maybe_init_instance_storage` materializes it on the first storage read for each native frame.

The proposed fix is correctness-plausible if it stays narrowly scoped to the existing allowlisted native pool path. A native sidecar can be initialized from the raw `ScMap` already inspected by `soroswap_pool_instance_matches_getter` / `try_call_native_soroswap_pool_swap`, expose typed accessors for keys 0/1/2/3/4/5, and for swap write a replacement `ScMap` that preserves all non-reserve entries and ordering while changing only reserve keys 2 and 3. It must not bypass the existing TTL extensions, SAC transfer/balance calls, event construction, frame rollback, or final `Storage` ledger-change accounting. Metering is the main constraint: p26 exact behavior is protected by the existing protocol gate, but protocol-27 budget/resource observations must either be explicitly redefined for this native sidecar or compensated with equivalent/coalesced charges so budget-exceeded behavior remains deterministic.

The projected impact is large enough for this objective. The current baseline soroswap median is about 218 ms, so the Medium floor is roughly 6.5 ms per applied ledger. The diagnostic trace attributes hundreds of milliseconds across the run to the exact zones this path exercises (`ScVal to Val`, `new map`, `map lookup`, `map lookup indexed`, and `add host object`), and the native pool path has already fixed the schema before paying those costs. Even partial removal of this generic instance-storage work should plausibly clear the 3% apply-time threshold, while the optimization is narrow enough to avoid the semantic risks of broader Soroswap bypasses.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, `src/rust/soroban/p26/soroban-env-host/src/storage.rs` only if a small native-sidecar type belongs there, and any minimal helpers needed near `Host::persist_instance_storage` / `store_contract_instance`.
- **Change description**: add a protocol-27-only native Soroswap pool instance-storage representation for `Frame::NativeContract` or a parallel sidecar keyed to that frame. Populate it from the already-validated raw `ScMap`, replace `soroswap_pool_instance_storage_get` / reserve update calls with typed sidecar accessors on the native path, and persist swap reserve changes by constructing the final `ScMap` directly rather than materializing and mutating `MeteredOrdMap<Val, Val>`.
- **Correctness check**: existing native pool getter/swap tests and Soroban host storage/event tests should still cover return values, storage changes, rollback, event emission, and protocol gating. Add focused tests only for the new sidecar behavior if existing tests do not compare storage output for getters, swap reserve persistence, optional `k_last`, `factory`, missing/invalid keys, and p26 fallback.
- **Benchmark focus**: run `scripts/run_apply_load_matrix.py` repeatedly on the soroswap scenario and compare top-line median apply time against `ai-summary/CURRENT_STATE.md`. A diagnostic Tracy run should show lower `ScVal to Val`, `new map`, `map lookup` / `map lookup indexed`, and `add host object` time inside `applyLedger`; the accepted PoC should demonstrate at least a reproducible 3% median apply-time reduction, not just lower budget counts.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:967-996` — added a native `Frame::NativeContract` read path for Soroswap pool instance storage so fixed u32-key reads use the frame's raw `ScContractInstance.storage` `ScMap` instead of forcing lazy `InstanceStorageMap::from_instance_xdr` and `MeteredOrdMap` materialization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1278-1406` — replaced native pool reserve writes with a raw-`ScMap` updater for keys 2 and 3, preserving all other entries and retaining the generic `with_mut_instance_storage` fallback for non-native callers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1962-1966` — taught frame-pop persistence to store the updated raw native swap instance storage directly through the existing `store_contract_instance` path.

### Demonstration

The native Soroswap pool getter and swap paths now avoid constructing the generic host instance-storage map for their fixed schema: they read from the already-cloned raw `ScMap` on `Frame::NativeContract`, and swap reserve updates construct the final `ScMap` directly. This removes the hot `ScVal` conversion, map construction, fixed-key map lookups, and two generic map inserts from the accepted protocol-27 native pool path while preserving existing TTL, SAC transfer/balance, event, rollback, and storage-persistence flow.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`, built with `make -j $(nproc)`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`. The full suite completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and p26 Soroban host Rust tests passing.
