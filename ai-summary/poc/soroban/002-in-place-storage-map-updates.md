# H002: In-Place Updates for Host `StorageMap` Writes

**Date**: 2026-04-28
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in contract-data writes and TTL updates
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Host durable storage is already owned mutably by `Storage`, so updating an entry in the transaction-local `StorageMap` should not rebuild a fresh immutable sorted map on every put or TTL extension. The storage map should preserve the same sorted key order, footprint enforcement, metering semantics, and final ledger effects, but the owned mutable map should update by one binary search followed by an in-place replacement or insertion into its backing `Vec`.

## Mechanism

`StorageMap` is a type alias for `MeteredOrdMap<Rc<LedgerKey>, Option<EntryWithLiveUntil>, Budget>`. `Storage::put_opt_helper` and `Storage::apply_ttl_extension` update it with `self.map = self.map.insert(...)`; `MeteredOrdMap::insert` is intentionally functional for host `MapObject` semantics, so it builds a new iterator, collects a new `Vec`, charges/clones the whole map, and re-validates sorted order. That immutability is unnecessary for `StorageMap`, which is not a guest-visible persistent host object and is already behind `&mut Storage`; a storage-specific `insert_mut`/`upsert_mut` path can keep the deterministic sorted vector representation while avoiding full-map allocation and clone work on every SAC balance write and TTL bump.

## Trigger

Run the current soroswap apply-load benchmark with Tracy enabled. Each SAC `transfer` spends one balance, receives another, writes updated contract-data entries via `put_contract_data`, and then extends balance TTLs via `extend_contract_data_ttl`. A PoC should add a mutable insertion/update path for `StorageMap` use sites, leave immutable `MeteredOrdMap::insert` in place for guest-visible maps, and compare repeated soroswap median apply time against the 620.996 ms baseline.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28` — `StorageMap` aliases the generic immutable `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — `Storage::put_opt_helper` enforces write access and rebuilds `self.map` through `MeteredOrdMap::insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — `Storage::apply_ttl_extension` rebuilds `self.map` when a TTL bump changes `live_until_ledger`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — generic `insert` clones prefixes/suffixes into a newly collected map and calls `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `from_exact_iter` is the traced `new map` zone, collecting and metering the rebuilt vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — `put_contract_data_into_ledger` drives existing/new contract-data writes on the SAC path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-96,100-145,156-230` — SAC balance writes and TTL extensions exercise the storage write path during soroswap swaps.

## Evidence

The current soroswap trace shows the write-side map-rebuild work inside `applyLedger`: unwrap-mode containment reports `new map` at 56,471 in-apply events totaling 186.340 ms, `storage put` at 7,413 in-apply events totaling 69.846 ms, `extend key` at 20,730 in-apply events totaling 116.339 ms, and `put_contract_data` at 6,012 in-apply events totaling 146.332 ms. The aggregate self-time export also reports `new map,soroban-env-host/src/host/metered_map.rs,148` with 125.111 ms self-time and `map lookup` with 403.316 ms self-time. The source confirms these updates happen through the immutable `MeteredOrdMap::insert` even though `Storage` has exclusive mutable access, so a targeted mutable update path removes allocation/clone overhead without changing the map's deterministic key order.

This target is distinct from prior soroban records: existing reviewed/fail entries cover read-side bucket lookup allocation, redundant host-output XDR, TTL extension frequency, and parallel-apply hash recomputation, but not the generic host `StorageMap` write implementation rebuilding an immutable map for every put/TTL update.

## Anti-Evidence

The `new map` zone is shared by guest-visible `MapObject` construction and instance-storage mutations as well as durable `StorageMap` writes, so a PoC must instrument the durable-storage subset before claiming the whole 186 ms is recoverable. `MeteredOrdMap` immutability is required for host map values returned to contracts; the optimization must be storage-specific and must not mutate guest-visible `HostMap`s in place. Resource accounting is consensus-visible, so the faster mutable path should preserve the existing budget charges or explicitly justify any p26 metering change while keeping final ledger entries, TTLs, events, and transaction results identical.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed immutable-map rebuild exists on the durable Soroban storage write path: SAC `transfer` calls `spend_balance` and `receive_balance`, each writes persistent contract-data through `put_contract_data`, and `write_contract_balance` immediately extends the same balance TTL. Those host calls enter `Storage::put` and `Storage::extend_ttl`, where `StorageMap` updates are performed by assigning `self.map = self.map.insert(...)`; the generic insert builds a fresh vector through `from_exact_iter`, charges/clones the whole map, and revalidates ordering. `StorageMap` itself is transaction-local storage state behind `&mut Storage`, while frame rollback snapshots clone the map into `RollbackPoint`, so in-place mutation of the live map can preserve rollback semantics if rollback continues restoring the cloned snapshot.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap benchmark generates `INVOKE_HOST_FUNCTION` transactions calling router `swap_exact_tokens_for_tokens`, with a source-account auth subtree for SAC `transfer` and RW footprint entries for pair SAC balances.
- `src/ledger/LedgerManagerImpl.cpp:2784-2915` — `closeLedger` transaction apply loads Soroban config, then applies parallel/sequential phases; the Soroban host invocation is therefore in the apply-time critical path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ apply invokes `rust_bridge::invoke_host_function` with ledger entries, TTL entries, auth, resources, and module cache.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust bridge dispatches the invocation to the protocol-specific host module used by p26.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` extends instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-96,100-145,156-230` — contract-account balances are written with `put_contract_data` and then extended with `extend_contract_data_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2317` — `put_contract_data` routes persistent/temporary storage to `put_contract_data_into_ledger`; `extend_contract_data_ttl` converts the key and calls `Storage::extend_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — `put_contract_data_into_ledger` probes storage, clones an existing ledger entry when present, updates its `ContractDataEntry.val`, and calls `Storage::put`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28,332-357,500-515,540-573` — durable `StorageMap` is a `MeteredOrdMap`; both `put_opt_helper` and `apply_ttl_extension` rebuild it through immutable `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,196-224` — `MeteredOrdMap::insert` performs a binary search, clones prefix/suffix iterators into a new vector via `from_exact_iter`, meters the cloned map, and calls `from_map` to rescan/revalidate sorted order.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-225,556-562` — frame push snapshots `storage.map` with `metered_clone`, and rollback restores that snapshot, so storage mutability does not require immutable per-update maps.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-224` — final ledger changes iterate the sorted `storage.map`, so an in-place update must preserve the same deterministic key ordering.

### Findings

The inefficiency is real and hot. The generic `MeteredOrdMap` API is functional because host `MapObject` values are immutable guest-visible objects, but durable `StorageMap` is not exposed as a persistent guest object and is already mutated through `&mut Storage`. On every durable put/delete and on every TTL extension that actually raises `live_until_ledger`, the current code pays for an immutable rebuild of the whole sorted vector even when the operation is a simple replacement at an already-known key. The rollback mechanism snapshots the entire storage map at frame entry and restores that snapshot on error, so replacing the live map entry in place does not inherently weaken rollback isolation.

The proposed fix is plausible if it remains storage-specific and metering-compatible. `MeteredOrdMap::find` already returns the replace/insert position after one binary search, and `Vec` can replace the found `(Rc<LedgerKey>, Option<EntryWithLiveUntil>)` in place or insert at the returned sorted position without changing final ordering. The main correctness constraint is p26 budget/resource equivalence: the PoC should either preserve the same logical charges currently paid by durable-storage `insert`, or explicitly demonstrate that any metering change is intended and accepted for protocol 26. Given the supplied trace attributes 69.846 ms to `storage put`, 116.339 ms to `extend key`, and 125.111 ms self-time to `new map` inside apply, even recovering a minority of the durable-storage rebuild overhead can plausibly clear the 3% Medium threshold on the 620.996 ms soroswap baseline; the hypothesis should proceed to PoC with durable-storage-specific instrumentation.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, with call-site updates in `Storage::put_opt_helper`, `Storage::apply_ttl_extension`, and any other production `StorageMap` setup/update sites that rebuild through `storage.map.insert(...)` such as `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` if they are measured inside apply.
- **Change description**: add a mutable storage-map update helper that performs the same key comparison/binary-search ordering as `MeteredOrdMap::insert`, then replaces an existing value or inserts into the backing `Vec` at the sorted position. Keep the immutable `MeteredOrdMap::insert` behavior for guest-visible `HostMap` and instance-storage maps unless a separate analysis proves they are safe and worthwhile.
- **Correctness check**: existing Soroban host storage, SAC, rollback, and ledger-change tests cover the behavior that must remain identical: storage footprint enforcement, contract-data writes/deletes, TTL extension, nested rollback, and final ledger changes. Pay special attention to tests under `src/rust/soroban/p26/soroban-env-host/src/test/storage.rs`, `test/stellar_asset_contract.rs`, `test/lifecycle.rs`, and rollback-focused auth/invoker tests.
- **Benchmark focus**: run repeated soroswap apply-load measurements and compare top-line apply time plus Tracy zones for `new map`, `storage put`, `extend key`, and `put_contract_data`. The PoC should separately instrument or attribute durable `StorageMap` mutable updates so it does not claim guest `MapObject` or instance-storage `new map` time as recoverable.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:1-10,231-345` — added `MeteredOrdMap::insert_mut`, a crate-private mutable upsert path that reuses the existing binary-search position, charges the same shallow map rebuild costs, replays the same final sorted-order comparisons for metering/resource equivalence, and then replaces or inserts in the backing `Vec`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:356-357,510-514,711-712,747,762-766` — switched durable `StorageMap` writes, TTL extensions, recording-mode read-through caching, and expired-entry handling from immutable map rebuild assignment to `insert_mut`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:610-615` — switched the testutils/enforcing storage setup helper to the mutable storage-map path so production-style storage setup no longer rebuilds the map.

### Demonstration

The optimization keeps guest-visible `MeteredOrdMap::insert` unchanged while giving the transaction-local durable `StorageMap` an in-place replacement/insertion path. It preserves sorted key order and existing resource observations by replaying the same sorted-order validation comparisons and bulk allocation/copy charges, but removes the actual allocation, full-vector clone, and `new map` construction work from storage puts and TTL bumps.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30` using a worktree-only `ALL_SOROBAN_GIT_STATE_STAMPS=` override for this checkout's submodule git-dir layout. Full regression passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check ALL_SOROBAN_GIT_STATE_STAMPS=`: `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
