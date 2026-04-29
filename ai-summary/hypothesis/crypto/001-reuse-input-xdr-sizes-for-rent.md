# H001: Reuse input XDR sizes for rent old-entry sizing

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by removing duplicate metered XDR serialization in the host ledger-change extraction path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When Soroban host invocation computes `LedgerEntryChange.old_entry_size_bytes_for_rent`, it should use the exact XDR size of the old ledger entry that was already supplied to the host as validated input. The computed rent size should match the current value produced by reserializing the decoded `LedgerEntry`, and the output `LedgerEntryChange` stream should remain byte-for-byte identical for modified entries that still need encoded output.

## Mechanism

The current apply path decodes each input `LedgerEntry` in `build_storage_map_from_xdr_ledger_entries`, discards the original encoded length, then later reserializes the old entry in `get_ledger_changes` only to recover `buf.len()` for `entry_size_for_rent`. Soroswap has many footprint entries per ledger, so this duplicates `WriteXdr` traversal, `Vec` writes, and `ValSer` budget charging for data whose XDR length was already known when the host input was decoded. Carrying the original `entry_buf.as_ref().len()` through the storage snapshot (or a parallel key-to-size map) would remove the old-entry size serialization pass while preserving deterministic rent-size results.

## Trigger

Run the current soroswap apply-load Tracy benchmark (`1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`) and inspect `write xdr` events under `applyLedger`. The trace contains 132,907 `write xdr` events, all inside `applyLedger` windows, with 1,071,528,694 ns total time and 764,102,894 ns self-time. A soroswap ledger with many existing contract-data entries triggers the duplicate old-entry serialization in `get_ledger_changes`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1044` — `build_storage_map_from_xdr_ledger_entries` decodes each `entry_buf` but does not retain `entry_buf.as_ref().len()`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-299` — `get_ledger_changes` reserializes `old_entry` at lines 227-231 solely to pass its length into `entry_size_for_rent`, then separately serializes new values that are actually returned to C++.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:368-387` — `entry_size_for_rent` uses the supplied XDR size directly for non-`ContractCode` entries.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` is the hot serialization zone (`write xdr`) whose old-entry size-only calls can be avoided.

## Evidence

The current trace confirms `write xdr` is entirely in scope: unwrap-mode analysis found 132,907 `write xdr` events and 1.071 s total `write xdr` time wholly inside 69 `applyLedger` windows totaling 5.774 s. Structurally, `build_storage_map_from_xdr_ledger_entries` already receives the canonical XDR bytes from C++ (`entry_buf`) and immediately decodes them into `Rc<LedgerEntry>`, while `get_ledger_changes` later creates a fresh `Vec<u8>` for the old entry only to measure its length. If old-entry size-only serialization is roughly one third of `write xdr` work in the storage-change phase, eliminating it would recover about 5-6% of trace apply time before accounting for secondary allocation and budget-charge savings, which meets the Medium severity floor.

This is distinct from prior rejected FFI-output hypotheses: new modified entries and contract events still need encoded bytes for C++ output, but old entries do not. The proposed change targets a host-internal size recomputation pass, not the required Rust-to-C++ `modified_ledger_entries` return path rejected in H010.

## Anti-Evidence

The current `ValSer` budget model is calibrated around recursive `WriteXdr` leaf calls, and `get_ledger_changes` currently charges that serialization. A viable implementation must either preserve protocol-visible resource accounting exactly, or be explicitly gated as a protocol/resource-model change; simply skipping the charge could change whether a near-budget transaction succeeds. Contract-code entries still need `wasm_module_memory_cost` added in `entry_size_for_rent`, so the optimization can only reuse the XDR byte length, not the full rent size, for those entries.
