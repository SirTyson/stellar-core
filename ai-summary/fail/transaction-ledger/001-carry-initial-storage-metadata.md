# H001: Carry initial storage metadata instead of cloning and reserializing old entries

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host storage finalization
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing per-invocation initial-storage map cloning, initial-map lookups, and old-entry XDR serialization from ledger-change extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful invoke-host-function transaction, `get_ledger_changes` should report the same encoded keys, encoded new values, rent sizes, TTL changes, restored-entry handling, and read-only/read-write flags as today. However, the host should not clone the complete initial `StorageMap` before execution and should not reserialize every old ledger entry after execution solely to rediscover an XDR byte length that was already known when the C++ bridge supplied the encoded ledger-entry buffer.

## Mechanism

`invoke_host_function` builds `storage_map` from `encoded_ledger_entries`, immediately clones it into `init_storage_map`, and later wraps that clone in `StorageMapSnapshotSource` so `get_ledger_changes` can look up the old entry for every footprint key. When an old entry exists, `get_ledger_changes` serializes the old `LedgerEntry` into a fresh `Vec<u8>` only to pass `buf.len()` to `entry_size_for_rent`; the bytes are not returned to Core. A per-entry initial metadata record carried alongside `StorageMap` entries — original presence, old live-until ledger, and original encoded XDR size — would let the finalization pass compute old rent size and TTL deltas directly, while preserving ordered output and new-entry serialization.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. In the longest `applyLedger` window, each Soroban worker spends up to 18.235 ms in `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61`, with roughly 1,500 write-XDR events per worker. The source path serializes keys and new entries that must be returned, but it also serializes old entries in `get_ledger_changes` only to compute rent-size inputs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449` — builds `storage_map` and then clones it into `init_storage_map` before host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:976-1044` — decodes each `encoded_ledger_entries` item and has direct access to `entry_buf.as_ref().len()` while constructing the initial storage map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` — `get_ledger_changes` looks old entries up through `init_storage_snapshot`, serializes old entries into temporary buffers, and computes old/new rent sizes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `StorageMapSnapshotSource` performs a second ordered-map lookup into the cloned initial map for every final storage key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `EntryWithLiveUntil` currently stores only the current entry and live-until ledger, not original encoded size or old-state metadata.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:376-387` — `entry_size_for_rent` accepts an XDR size precisely to avoid recomputing XDR size, but the current old-entry path recomputes it by writing XDR anyway.

## Evidence

The optimization is grounded in a structural redundancy on the measured apply path. The input builder already receives encoded old ledger-entry bytes, decodes them, and can record their encoded lengths at `build_storage_map_from_xdr_ledger_entries`; after successful execution, `get_ledger_changes` reserializes the same old entries even though only `old_entry_size_bytes_for_rent` consumes the resulting length. The current trace confirms `write xdr` is an `applyLedger` descendant on Soroban worker threads: in the longest apply window the hottest worker has 18.235 ms in `write xdr`, and the full trace reports 764.103 ms self-time over 132,907 `write xdr` events.

This is distinct from the reviewed `batch-metered-xdr-valser-charges` hypothesis. That hypothesis reduces per-chunk metering overhead while still performing the same XDR writes; this one removes an entire class of old-entry writes plus the initial `StorageMap` clone and final old-map lookup. It is also distinct from the failed global pre-serialized-entry cache: this stores only per-invocation encoded sizes already present in bridge inputs, not serialized bytes in `InMemorySorobanState`, so it should avoid persistent cache-pressure regression.

## Anti-Evidence

New-entry XDR serialization and key serialization still have to happen because Core consumes those bytes, so the maximum win is limited to old-entry serialization, initial-map cloning, and snapshot lookups. The implementation must preserve metering semantics: even if it avoids the old-entry XDR write, it may need an equivalent deterministic charge if current `ValSer` consumption is considered protocol-visible for this path. Recording-mode expired-entry behavior and restored-key handling are subtle; the metadata has to preserve the current cases where old rent size is reset to zero for expired or restored entries.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The redundancy exists on the traced apply path, but the proposed metadata is insufficient to preserve current Soroban budget semantics. `invoke_host_function` builds enforcing storage from encoded ledger-entry buffers, clones the initial `StorageMap`, and after success calls `get_ledger_changes`; that function serializes every old entry through `metered_write_xdr` before calling `entry_size_for_rent`. `metered_write_xdr` does more than compute a byte length: every `Write::write` call charges `ContractCostType::ValSer`, and the budget model has non-zero CPU and memory constants per charge. Replacing recursive old-entry serialization with a stored total XDR length would change consumed instructions/memory and possibly budget-exceeded behavior, which is visible to Core through `InvokeHostFunctionOutput` and resource-limit handling.

The initial `StorageMap` clone is also less expensive than the hypothesis implies: `StorageMap` is a `MeteredOrdMap<Rc<LedgerKey>, Option<(Rc<LedgerEntry>, Option<u32>)>, Budget>`, so cloning it copies the vector and bumps `Rc` counts rather than deep-cloning ledger entries. The meaningful removable work is the old-entry XDR traversal and final lookup, but removing that work safely requires a metering story stronger than "carry original encoded size".

### Alternative Angle

A refined hypothesis should choose one of two explicit designs. First, a protocol-gated metering change could intentionally stop charging old-entry rent-size rediscovery as `ValSer`, then store original presence, old live-until ledger, original encoded XDR length, and any contract-code memory-size input alongside the storage entry. Second, a behavior-preserving optimization would need to carry or reconstruct the exact `ValSer` charge profile for each original ledger entry, not just the total length; otherwise the non-zero per-charge constants and failure points differ. The second design may recover less real time if it still has to traverse XDR structure to reproduce charges, so it should be measured before being promoted.

### Additional Code Paths

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-451` — production invocation builds `StorageMap`, clones it into `init_storage_map`, and constructs enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-508` — successful invocations wrap the cloned map in `StorageMapSnapshotSource` and call `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` — `get_ledger_changes` emits encoded keys, looks up old entries, serializes old entries for rent-size input, serializes new RW entries for Core, handles restored-key old-size resets, and emits TTL deltas.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:976-1044` — the builder already sees each original `entry_buf.as_ref().len()` while decoding ledger entries and TTL entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:376-387` — `entry_size_for_rent` accepts a caller-supplied XDR size and adds Wasm memory cost for contract-code entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `StorageMapSnapshotSource::get` performs the old-map lookup and returns cloned `Rc` entry handles.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-24,56-68` — every XDR write chunk charges `ContractCostType::ValSer` before writing to the output vector.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,369-372,725-728` — budget charging records iterations/inputs and applies non-zero `ValSer` CPU and memory constant terms, so one size-only charge is not equivalent to recursive `WriteXdr` metering.
- `src/rust/src/soroban_proto_any.rs:478-506` — Core-visible output uses consumed CPU/memory, rent changes, and ledger effects after `get_ledger_changes` succeeds.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` — C++ calls the Rust bridge, records returned CPU/memory, and maps resource-limit failures into transaction results.
