# H002: Emit changed-only Soroban ledger effects without all-entry XDR re-encoding

**Date**: 2026-04-29
**Subsystem**: transaction-ledger, soroban host bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by cutting Rust/C++ ledger-effect serialization overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban host invocation, Core should receive exactly the modified ledger entries, TTL bumps, result value, events, and rent inputs needed to update `TxParallelApplyLedgerState` and charge refundable fees. It should not need to XDR-encode keys and old entries for every footprint entry, then filter that intermediate structure down to modified entries and immediately XDR-decode those entries again in C++.

## Mechanism

`e2e_invoke::get_ledger_changes` iterates `storage.map` for every footprint entry and calls `metered_write_xdr` for each key, old entry, modified new value, and event payload (`e2e_invoke.rs:183-290`, `metered_xdr.rs:56-67`). The wrapper then computes rent changes and calls `extract_ledger_effects`, which discards read-only unchanged entries and returns only encoded modified entries/TTL entries to C++ (`soroban_proto_any.rs:478-506`, `soroban_proto_any.rs:261-301`). C++ immediately decodes each returned modified entry in `InvokeHostFunctionOpFrame::recordStorageChanges` (`InvokeHostFunctionOpFrame.cpp:654-720`), so a changed-only effect representation that tracks dirty entries and TTL bumps during host storage mutation, while computing rent sizes from cached encoded sizes, should avoid substantial XDR write/read work without changing ledger semantics.

## Trigger

Run the current soroswap Tracy trace and inspect `write xdr`, `read xdr with budget`, and `recordStorageChanges` under `applyLedger`:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -e /mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-02-soroswap-tx-2000-t-8.tracy
```

The issue is triggered by successful soroswap swaps with several read-only and read-write footprint entries: the host builds a full `LedgerEntryChange` vector for the whole storage map even when Core only applies the modified subset.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-290` — `get_ledger_changes` scans all storage entries and XDR-encodes keys/entries into `LedgerEntryChange`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-67` — `metered_write_xdr` is the hot `write xdr` zone.
- `src/rust/src/soroban_proto_any.rs:478-506` — successful invocation computes rent changes, extracts encoded ledger effects, and returns `InvokeHostFunctionOutput`.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` filters the all-entry change vector down to modified entries and synthetic TTL entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:654-720` — Core decodes returned modified-entry buffers and applies them to the parallel ledger state.

## Evidence

In the current soroswap trace, `write xdr` accounts for about 1.04s of self-time inside `applyLedger` over 116,447 in-apply calls, and `read xdr with budget` contributes about 78ms more. `recordStorageChanges` itself is smaller, about 44ms inside `applyLedger`, but it confirms the bridge boundary immediately decodes the encoded modified-entry buffers that Rust just produced. The hot zone is in the `invoke_host_function` descendant of `InvokeHostFunctionOpFrame doParallelApply`, so it is inside the measured apply path rather than tx-set construction.

## Anti-Evidence

Some of the current full-change structure feeds rent computation and TTL extension logic, so simply dropping read-only or old-entry data would be incorrect. A viable optimization must preserve rent inputs, TTL max semantics, event/result encoding, and deterministic ordering of returned effects; the likely shape is to track dirty keys/TTL changes during storage mutation and keep cached old/new encoded sizes for rent, then emit the same final modified entries in a deterministic order.
