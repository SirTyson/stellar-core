# H002: Cache decoded input entry XDR sizes for ledger-change rent accounting

**Date**: 2026-04-29
**Subsystem**: ledger / Soroban host invocation output
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant per-footprint XDR serialization in successful host invocations
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each successful Soroban invocation, the Rust host must return the same ledger changes, rent size fields, TTL changes, events, and result XDR as today. Computing `old_entry_size_bytes_for_rent` should not require reserializing every old ledger entry when the embedder already supplied the exact encoded `LedgerEntry` bytes used to build the initial storage map.

## Mechanism

`build_storage_map_from_xdr_ledger_entries` decodes every input `LedgerEntry` from an encoded buffer, inserts only `(Rc<LedgerEntry>, live_until)` into `StorageMap`, and discards the original encoded length. Later, `get_ledger_changes` asks the initial snapshot for the old entry and serializes that same old entry back to XDR only to compute `old_entry_size_bytes_for_rent`. Carrying the input encoded length alongside the initial storage entry, or providing a parallel snapshot map of initial rent sizes, would avoid this redundant old-entry serialization while leaving the emitted `encoded_new_value` and `encoded_key` bytes unchanged.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with successful invoke-host-function transactions that touch multiple footprint entries. Each transaction decodes its input ledger entries into a host storage map, executes, then serializes old entries again during ledger-change construction even when those entries were supplied as XDR bytes moments earlier.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — `invoke_host_function` decodes resources, builds the storage map from encoded ledger entries, clones the initial map, and later uses it as the snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes `entry_buf` but stores only the decoded entry and TTL, not the original XDR size.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes `old_entry` at lines 227-231 solely to compute old rent size, then serializes read-write new entries separately for output at lines 264-272.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource` currently exposes only `(entry, live_until)`, so it cannot answer "initial encoded size" without reserialization.

## Evidence

In the current soroswap Tracy trace, the `write xdr` zone is fully in-scope: `132,898` of `132,907` events overlap `applyLedger`, accounting for `1,071,500,405 ns` of overlapped time. `invoke_host_function` and `Host::invoke_function` are also descendants of `applyLedger`; the trace shows `invoke_host_function` total time `9,871,843,503 ns` across 3,335 calls and `write xdr` self-time `764,102,894 ns`. The code path demonstrates at least one avoidable serialization per old entry in the footprint: unlike `encoded_new_value`, the old entry bytes are not returned to C++ and are only used for `entry_size_for_rent`.

## Anti-Evidence

Not all `write xdr` time is removable: keys, result `ScVal`, events, and new read-write values still need encoded output, and contract-code rent size uses `entry_size_for_rent` semantics rather than raw XDR length. A safe PoC must preserve metering semantics or consciously account for any budget-charge differences, because `metered_write_xdr` currently charges `ValSer` while it serializes.
