# H002: Add an in-place storage-map update path for enforcing Soroban storage writes

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host storage mutation
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding clone-on-write vector rebuilds for hot SAC balance writes and TTL extensions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During enforcing-mode host execution, updating an already-present storage entry or TTL should replace the value at its sorted-map position without reconstructing the whole `StorageMap` vector. Frame rollback should remain exact by restoring the already-snapshotted pre-frame `StorageMap`, and ledger changes should remain byte-for-byte identical; the optimization should only change how the current mutable storage map is updated internally.

## Mechanism

`Storage::put_opt_helper` and `Storage::apply_ttl_extension` assign `self.map = self.map.insert(...)`. `MeteredOrdMap::insert` is persistent/clone-on-write: it binary-searches the key, builds a new iterator from the prefix, replacement, and suffix, allocates a fresh vector through `from_exact_iter`, deep-clone-charges every entry, and scans the rebuilt map. This is attractive for immutable-style APIs, but `Storage` owns a mutable `self.map`, and `RollbackPoint` already captures a separate metered clone on frame entry before mutations occur.

For enforcing storage writes, a specialized `replace_existing_or_insert_mut` path can binary-search once and mutate the current vector in place for the common existing-key update. Soroswap SAC balance writes and TTL extensions mostly replace entries that were loaded into the footprint at transaction start, so they do not need the general persistent rebuild. Equivalent deterministic budget charges can be batched or preserved while avoiding actual vector allocation/copy and reducing `new map` pressure.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) using `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. Each swap performs SAC `transfer` operations that mutate contract balances and extend balance TTLs. Those calls reach `Storage::put` and `Storage::extend_ttl`, which currently rebuild `StorageMap` via `MeteredOrdMap::insert` on every write/update.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` — `Storage::put_opt_helper` / `put` enforce write access and then rebuild `self.map` with `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — `Storage::apply_ttl_extension` rebuilds `self.map` with `insert` when a TTL is extended.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:532-573` — `Storage::extend_ttl` is the hot caller for SAC balance and instance TTL updates.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — `MeteredOrdMap::insert` reconstructs a complete vector even when replacing an existing key.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-229` — frame entry snapshots `storage.map` in `RollbackPoint`, and failed exits restore that map; this is the rollback mechanism an in-place update must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:73-97,100-145,156-229` — SAC balance writes drive repeated storage puts and TTL extensions on the soroswap path.

## Evidence

- Tracy self-time in the current soroswap trace shows `new map,soroban-env-host/src/host/metered_map.rs:148` at **130.563 ms self-time** over 64,552 calls, with timestamp filtering placing 58,761 calls inside `applyLedger` windows. This is the exact helper used by `MeteredOrdMap::insert` after it reconstructs a replacement vector.
- The same trace places `storage put,soroban-env-host/src/storage.rs:388` at 7,713 events / 67.946 ms and `extend key,soroban-env-host/src/storage.rs:540` at 21,569 events / 112.316 ms inside `applyLedger`. `put_contract_data` and `extend_contract_data_ttl` account for 142.372 ms and 73.411 ms respectively inside the same windows, confirming the writes/TTL path is hot for soroswap.
- The source shows most SAC balance operations write existing footprint entries: `write_contract_balance` calls `put_contract_data` followed by `extend_contract_data_ttl`, and the benchmark footprint contains the pair contract-balance keys as read-write entries. Existing-key replacement is therefore the common case; true insert/delete remains available as a fallback.
- Determinism does not require clone-on-write here. Host execution is single-threaded per transaction, and rollback already holds an independent `StorageMap` snapshot before a frame body mutates storage. Replacing the current map's vector slot in place after that snapshot preserves the same state visible to successful execution and failed-frame rollback.
- If the mutable replacement path removes a meaningful fraction of the `new map` worker time and associated map scans/charges, the wall-clock gain after T=8 normalization is plausibly 20+ ms on the 596 ms soroswap baseline, meeting Medium severity.

## Anti-Evidence

- This must not mutate a `StorageMap` that is shared with a live rollback snapshot or initial snapshot by reference. Current `MeteredOrdMap` owns its vector by value, so assignment to the current `Storage` map is independent of previous cloned vectors, but a PoC must verify no `Rc`/borrowed vector sharing is introduced.
- Insertions for missing entries, deletions, recording-mode access, and maps not owned by `Storage` may still need the persistent `insert` API. The safe first target is enforcing-mode existing-key replacement in `Storage::put_opt_helper` and `apply_ttl_extension`.
- Metering is observable. The fast path must either preserve exact current budget totals with batched equivalent charges or be protocol-gated with tests proving intended metering changes. Skipping clone/scan charges silently could alter resource-limit-boundary transactions.
- `new map` is shared by other host structures, so the PoC must isolate the share caused by storage writes. If storage-write insertions are a small subset of `new map`, the standalone improvement could fall below the 3% objective floor.
