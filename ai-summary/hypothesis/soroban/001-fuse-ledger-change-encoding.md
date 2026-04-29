# H001: Fuse Core Ledger-Change Encoding to Avoid Re-serializing Footprint Entries

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant XDR writes from the apply hot path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban host invocation should return the modified ledger entries and rent inputs needed by stellar-core without repeatedly serializing the same footprint entries. The C++ apply path should still receive identical modified entry XDR, identical TTL updates, identical rent fee, and identical transaction results for every soroswap transaction.

## Mechanism

`e2e_invoke::invoke_host_function` builds a `StorageMap` by decoding already-encoded ledger-entry buffers, clones the full initial map, then `get_ledger_changes` walks the final storage map and calls `metered_write_xdr` for every key, every old entry, and every read-write new entry before the Rust bridge immediately reduces those `LedgerEntryChange` values to rent changes and modified entries. On the soroswap trace, `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61` accounts for 764,102,894 ns self time and 1,071,528,694 ns total time across 132,907 calls, all inside `applyLedger` windows; much of this is structural marshalling work around apply results rather than contract execution.

A core-specific output path could carry old entry XDR sizes from `build_storage_map_from_xdr_ledger_entries`, compute rent changes while walking storage, and emit only `encoded_new_value` plus required TTL entries. This should preserve deterministic output order by continuing to iterate the sorted `StorageMap` / footprint-derived order used today, while avoiding old-entry reserialization and avoidable intermediate `LedgerEntryChange` fields that are not consumed by stellar-core.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the Tracy trace from `ai-summary/CURRENT_STATE.md`. The issue is triggered by every successful `InvokeHostFunctionOpFrame::doParallelApply` call whose footprint contains multiple ledger entries, especially soroswap swaps that return several modified contract-data and TTL entries.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449` — builds `storage_map`, `init_ttl_map`, then clones the initial storage map before execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292` — `get_ledger_changes` serializes keys, old entries, and new entries for every storage-map entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1043` — `build_storage_map_from_xdr_ledger_entries` decodes ledger entries from buffers whose lengths could be retained for old-entry rent sizing.
- `src/rust/src/soroban_proto_any.rs:481-488` — stellar-core bridge consumes `ledger_changes` only to compute rent changes and extract modified ledger-entry XDR.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:654-720` — C++ deserializes only `modified_ledger_entries`, so old-entry encoded bytes are not needed on the C++ side.

## Evidence

The current soroswap Tracy trace is `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. `applyLedger` spans 5,774,332,215 ns over 69 windows. All 132,907 `write xdr` events are fully contained in those `applyLedger` windows, totaling 1,071,528,694 ns; self-time export reports `write xdr,soroban-env-host/src/host/metered_xdr.rs,61,764102894,...,132907`. The source shows old entries are serialized only to recover XDR length for rent sizing, even though the exact encoded input buffer length is available when building the storage map.

## Anti-Evidence

`InvokeHostFunctionResult` is a public embedder-facing shape also used by tests and recording-mode flows, so replacing it wholesale would be risky. A viable optimization should likely add a stellar-core/core-bridge-specific extraction path or augment existing internal storage metadata while preserving the existing generic `LedgerEntryChange` API for RPC/preflight consumers. Contract-code rent size also adds `wasm_module_memory_cost`, so carrying XDR lengths must still call `entry_size_for_rent` rather than treating every length as final rent size.
