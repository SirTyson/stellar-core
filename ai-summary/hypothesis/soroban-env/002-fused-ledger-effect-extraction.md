# H002: Fused Ledger-Effect Extraction Skips No-Op Footprint Work

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding per-footprint key serialization, map lookups, and temporary `LedgerEntryChange` records that are discarded before crossing the C++ bridge
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

On the enforcing apply path, the Rust host should return exactly the same modified ledger entries, TTL ledger entries, rent changes, and contract events to stellar-core, but it should not fully materialize no-op `LedgerEntryChange` records for footprint entries whose data and TTL do not change and whose only role is to be filtered out by `extract_rent_changes` / `extract_ledger_effects`.

## Mechanism

`get_ledger_changes` currently iterates every entry in `storage.map`, serializes every key into `entry_change.encoded_key`, looks up the initial entry by position, computes rent metadata, and pushes a `LedgerEntryChange` even for no-op footprint entries. The bridge layer immediately filters this vector into rent changes and `modified_ledger_entries`; a fused enforcing-mode extractor can compute those two outputs directly, using cached initial TTL metadata for key hashes and emitting encoded `LedgerEntry` bytes only for entries that actually need to be upserted, while preserving the existing full `LedgerEntryChange` path for recording-mode tests/simulation.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload. Each successful Soroban transaction calls `invoke_host_function`, then `get_ledger_changes`, then Rust-side `extract_rent_changes` and `extract_ledger_effects` before C++ `recordStorageChanges` re-parses only `modified_ledger_entries`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` builds a full `LedgerEntryChange` for every footprint/storage entry and serializes each `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:490-580` — enforcing `invoke_host_function` calls `get_ledger_changes` even though the bridge only needs extracted effects.
- `src/rust/src/soroban_proto_any.rs:261-290,481-488` — bridge extraction discards read-only/no-op `LedgerEntryChange` records and forwards only encoded modified entries plus TTL entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` — C++ consumes `modified_ledger_entries`, reparses each emitted `LedgerEntry`, and never sees the intermediate no-op Rust records.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:72` — `write xdr` zone targeted by skipping key/new-entry serialization that does not contribute to outputs.

## Evidence

The current accepted soroswap trace shows `invoke_host_function` at `e2e_invoke.rs:488` with 828.3 ms self-time across 7,891 calls, and `write xdr` at `host/metered_xdr.rs:72` with 160.3 ms self-time / 150.5 ms apply-contained total. Source inspection shows `LedgerEntryChange.encoded_key` is populated for every storage-map entry, but in the normal enforcing bridge flow the full vector is immediately reduced to rent changes and `modified_ledger_entries`; read-only and no-op read-write records do not cross the FFI boundary except through their filtered TTL/rent effects.

## Anti-Evidence

The current comments say `InvokeHostFunctionResult.ledger_changes` intentionally contains every footprint item, and recording-mode/simulation rely on that shape. The optimization must therefore be an enforcing-only fused extraction path, must prove that the soroswap footprint has enough no-op or TTL-only entries to clear the Medium floor, and must not change rent-fee computation or the ordering of emitted modified entries and TTL entries.
