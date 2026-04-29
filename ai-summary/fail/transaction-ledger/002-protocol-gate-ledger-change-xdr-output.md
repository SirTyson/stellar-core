# H002: Protocol-Gate Direct Ledger-Change Output to Avoid Old-Entry XDR Serialization

**Date**: 2026-04-29
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing metered XDR serialization in successful host-output generation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, Core should receive the same modified ledger entries, rent changes, result value, and contract events, and every node should compute the same transaction result and ledger state. If the optimization changes `ValSer` budget accounting for host-output construction, that change must be explicit and protocol-gated; otherwise the implementation must replay exactly equivalent charges before returning output.

## Mechanism

`get_ledger_changes` walks the final host storage map and serializes every key, every existing old entry, and every new read-write entry through `metered_write_xdr`. For the apply path, much of that serialized old-entry data is not needed as an output byte vector: C++ already supplied the initial encoded ledger entries to Rust, and downstream Rust code uses old-entry serialization mainly to derive rent sizes and `ValSer` charges before `extract_rent_changes` and `extract_ledger_effects` split the data back into rent changes and modified-entry buffers. A protocol-gated direct-output path could carry initial encoded entry/key metadata from `build_storage_map_from_xdr_ledger_entries`, build rent changes and modified-entry buffers directly, and avoid old-entry/key `Vec<u8>` serialization that is currently paid on every successful soroswap invocation.

## Trigger

Run the current soroswap apply-load benchmark with Tracy enabled and inspect `write xdr` events under the long `applyLedger` windows in `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. Successful soroswap swaps with several SAC/pair storage entries cause `get_ledger_changes` to serialize old and new ledger entries after VM execution.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` - `get_ledger_changes` serializes keys, old entries, and new entries into `LedgerEntryChange`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449` - `build_storage_map_from_xdr_ledger_entries` decodes the initial encoded entries and then clones the typed storage map, but does not retain the original encoded bytes as output metadata.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` - initial entry/TTL decoding already sees every encoded ledger entry and TTL entry that later old-entry serialization reconstructs.
- `src/rust/src/soroban_proto_any.rs:479-488` - successful invocation output immediately derives rent changes and modified ledger entries from `LedgerEntryChange`.
- `src/rust/src/soroban_proto_any.rs:261-290` - `extract_ledger_effects` consumes only `encoded_new_value` and TTL-change fields, not the old-entry bytes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` - `metered_write_xdr` is the hot serialization helper behind the `write xdr` Tracy zone.

## Evidence

The current soroswap Tracy trace reports `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61` with 764.103 ms aggregate self-time and 132,907 calls. Timestamp-filtering to the five long `applyLedger` windows gives an average 30.583 ms max-thread critical-path share per window and 213.815 ms aggregate worker time. The relevant calls are descendants of `invoke_host_function` inside `InvokeHostFunctionOpFrame doParallelApply`; the source shows that successful output construction invokes `get_ledger_changes` immediately after `host.try_finish()` and before C++ `recordStorageChanges` applies the modified entries.

This is distinct from a size-only metadata shortcut: the viable design must either protocol-gate the budget change or preserve exact `ValSer` accounting. The performance opportunity is still plausible because old-entry and key bytes are reconstructed solely to feed rent/effect extraction even though the initial encoded entries are already available at the C++/Rust boundary.

## Anti-Evidence

A prior size-only variant failed because `metered_write_xdr` charges `ValSer` with per-write constant terms, so replacing serialization with byte lengths is not behavior-preserving on the current protocol. The direct-output path therefore must be protocol-gated or must capture/replay the exact charge schedule; otherwise it can change `cpu_insns`, `mem_bytes`, and budget-exceeded behavior. New-entry serialization for modified values is still needed unless storage writes retain encoded values as they are produced, so the achievable win is bounded by the old-entry/key portion of the `write xdr` zone rather than the entire zone.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to `001-carry-initial-storage-metadata.md`, but not an exact duplicate because this version explicitly allows a protocol-gated metering change
**Failed At**: reviewer

### Trace Summary

The redundant serialization is real: successful `invoke_host_function` calls `host.try_finish()`, then `get_ledger_changes`, which serializes each storage key, any existing old entry, and each new read-write entry through `metered_write_xdr`. The resulting `LedgerEntryChange` vector is immediately consumed by `extract_rent_changes` and `extract_ledger_effects`; C++ receives only the final modified ledger-entry buffers, contract events, result value, and rent fee. However, the trace's entire `write xdr` critical-path share is already only about 153 ms across roughly 5.77 s of traced `applyLedger` windows, and this proposal can remove only the old-entry/key subset while preserving result-value, event, and new-entry serialization.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` walks the final storage map and performs metered XDR writes for `encoded_key`, old entries used for rent sizing, and new read-write values returned as effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449,959-1052` — initial ledger and TTL entry buffers are decoded into `StorageMap`/`TtlEntryMap`; the original encoded buffers are not retained in the storage snapshot returned to `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:485-508` — successful host execution finishes storage/events, then builds ledger changes before encoding contract events for embedder output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:329-366,376-387` — rent extraction needs old/new rent sizes and TTL changes, not old-entry bytes, but contract-code rent size still depends on calling `wasm_module_memory_cost` on the decoded old/new entry.
- `src/rust/src/soroban_proto_any.rs:478-488` — successful invocation output computes rent from `res.ledger_changes`, then consumes the same changes to produce modified ledger-entry buffers.
- `src/rust/src/soroban_proto_any.rs:261-299` — `extract_ledger_effects` uses `encoded_new_value` and synthesized TTL entries; it does not consume `encoded_key` or serialized old-entry bytes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — every current XDR write charges `ValSer`, so skipping old-entry/key serialization either changes protocol-visible metering or requires a protocol gate/equivalent charge replay.
- `src/rust/src/bridge.rs:34-55` and `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — the C++ bridge output contains only modified ledger entries; `recordStorageChanges` decodes and applies those modified entries and does not use old-entry bytes.

### Why It Failed

The mechanism is directionally correct but below the optimize-soroswap review threshold. The cited `write xdr` critical-worker time averages 30.583 ms per long `applyLedger` window; across the five windows used in the related trace notes this is about 153 ms out of 5,774 ms, or roughly 2.6% even if every metered XDR write disappeared. The actual removable subset is smaller: result-value serialization, contract-event serialization, and new read-write ledger-entry serialization remain required for bridge output, fee/resource accounting, and C++ `recordStorageChanges`; only key serialization and old-entry serialization/rent-size derivation are targeted. That cannot plausibly reach the objective's 3% Medium floor, and Low-tier optimizations are rejected for this objective.

### Lesson Learned

When a hypothesis targets a broad Tracy category such as `write xdr`, estimate against the critical-path share of the whole category first, then subtract mandatory serialization that must remain. A protocol gate can make a metering change safe, but it does not make a bounded sub-slice of an already sub-3% category a Medium-severity soroswap optimization.
