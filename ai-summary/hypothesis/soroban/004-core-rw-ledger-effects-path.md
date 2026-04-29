# H004: Core enforcing output can skip read-only/no-op LedgerEntryChange materialization

**Date**: 2026-04-29
**Subsystem**: soroban / rust bridge
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in post-host ledger-effect extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For enforcing-mode stellar-core apply, Rust should return exactly the ledger effects C++ consumes: modified read-write ledger entries, synthesized TTL entries whose live-until increases, rent-change inputs, event/resource totals, and the invocation result. Read-only footprint entries that did not change should not be expanded into full `LedgerEntryChange` records with encoded keys, old-entry XDR buffers, footprint-map lookups, and rent-size computation when `extract_ledger_effects` will drop them and `extract_rent_changes` will skip them as no-ops.

## Mechanism

`get_ledger_changes` currently iterates every `storage.map` item, including read-only footprint entries, and unconditionally serializes each key (`metered_write_xdr`), loads the initial entry, serializes the old entry for rent sizing, checks the footprint map, and only then marks read-only entries. Later, `extract_ledger_effects` ignores read-only entries except for possible TTL changes, and `extract_rent_changes` filters out unchanged TTL/size pairs. In stellar-core's enforcing path, read-only entries are not supposed to produce modified ledger entries, and read-only TTL bumps are handled by core parallel-apply RO TTL machinery rather than by returned host ledger effects. A core-specific extractor can iterate the read-write footprint and changed TTL set directly, preserving output order and ledger effects while avoiding read-only/no-op `LedgerEntryChange` materialization.

## Trigger

Run the current soroswap apply-load benchmark. Soroswap footprints include read-only contract instance/code entries and token/pair state that are supplied to the Rust host for execution but are not returned to C++ as modified ledger entries. A PoC should add a stellar-core enforcing output path that computes rent changes and `modified_ledger_entries` directly from RW storage entries and TTL deltas, leaving recording/preflight `LedgerEntryChange` behavior unchanged. If p26 resource accounting is intended to remain exactly unchanged, the PoC must add an exact metering-preservation mode; otherwise it must explicitly treat skipped read-only output materialization as a p26 metering optimization and test resource-limit boundary behavior.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` — `get_ledger_changes` builds a `LedgerEntryChange` for every storage-map item and serializes key/old-entry data before knowing whether the entry is read-only.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-365` — `extract_rent_changes` drops changes whose TTL and rent size are unchanged.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` drops read-only entries and only forwards encoded new values plus synthesized TTL entries to C++.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — enforcing footprints and storage maps are built from C++ input buffers before invocation, giving the optimized core path the read-write key set and initial sizes needed for direct extraction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — C++ `recordStorageChanges` consumes only returned modified ledger-entry buffers and treats omitted RW entries as deletes; it never consumes read-only `LedgerEntryChange` records.
- `src/transactions/ParallelApplyUtils.cpp:1003-1039` and `src/transactions/InvokeHostFunctionOpFrame.cpp:381-535` — C++ parallel apply has separate RO TTL bump/read materialization paths, so the optimized Rust output path must not duplicate read-only no-op accounting.

## Evidence

The current soroswap trace shows the relevant post-host/output region fully inside `applyLedger`: `write xdr` accounts for **1,071.529 ms** across **132,907** calls, `map lookup` for **1,321.581 ms** across **754,812** calls, `storage get` for **847.123 ms** across **176,910** calls, and `ScVal to Val` for **721.780 ms** across **480,076** calls. `get_ledger_changes` is not separately zoned, but source inspection places it immediately after successful host execution (`e2e_invoke.rs:493-508`) and before `extract_ledger_effects` discards read-only changes (`soroban_proto_any.rs:261-301`).

The previous old-entry output PoC was rejected because preserving exact `ValSer` traversal reduced the optimization to avoiding buffer allocation and did not improve top-line apply time. This hypothesis is broader and targets the control flow that forces read-only/no-op entries through the entire public `LedgerEntryChange` pipeline in the core enforcing path. If read-only entries are skipped before key and old-entry serialization, the PoC removes work rather than merely swapping a `Vec<u8>` for a counting writer.

## Anti-Evidence

This is a more invasive and more semantics-sensitive change than a buffer-allocation cleanup. Host output materialization currently contributes to returned `cpu_insns` and `mem_bytes`, and lowering that accounting can affect resource-limit behavior, fee refunds, and metadata at boundaries. Reviewers already rejected a "close enough" bulk metering replacement for old-entry serialization, so a viable PoC must either preserve exact metering through a faster caller-specific structure, or explicitly justify and test the protocol/resource-accounting change. The read-only skip must also prove that no read-only TTL extension or restore case is lost; recording/preflight mode should keep the existing full `LedgerEntryChange` contract for downstream consumers.
