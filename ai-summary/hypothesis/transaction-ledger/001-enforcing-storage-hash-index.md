# H001: Add a hash-indexed enforcing-storage lookup path

**Date**: 2026-04-29
**Subsystem**: transaction-ledger, soroban host storage
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing per-contract storage lookup overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During soroswap apply, enforcing-mode Soroban storage should validate footprint access and return ledger entries in deterministic order, but individual `get`, `has`, and `put` operations should not repeatedly binary-search small ordered vectors and perform metered host comparisons for every storage access. The host should preserve the same budget charges, storage errors, ledger effects, and output ordering while using an apply-local O(1) lookup structure for hot enforcing-storage reads and writes.

## Mechanism

The current enforcing storage path stores both `FootprintMap` and `StorageMap` as `MeteredOrdMap` (`storage.rs:25-27`) and every `Storage::try_get_full_helper` call performs `self.map.get` after footprint enforcement (`storage.rs:252-266`). `MeteredOrdMap::find` is a binary search with a Tracy zone named `map lookup` (`metered_map.rs:168-180`), so the soroswap workload pays comparison and binary-search overhead on every SAC balance/transfer and pool storage access even though the footprint is already fixed for the transaction. A sidecar `HashMap`/index keyed by `LedgerKey` or cached key hash for enforcing mode, with the existing ordered vector retained only for deterministic iteration/effect extraction, should reduce `storage get`, `has_contract_data`, and `put_contract_data` self-time without changing observable ledger output.

## Trigger

Run the current soroswap apply-load Tracy profile (`scripts/run_apply_load_matrix.py --tracy`, soroswap TX=2000, T=8) and export self-times with:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -e /mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-02-soroswap-tx-2000-t-8.tracy
```

The candidate triggers on transactions that perform many contract storage operations over a small declared footprint, such as soroswap swaps repeatedly calling SAC `balance`/`transfer` and pool contract reads/writes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` are `MeteredOrdMap` aliases.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266` — enforcing storage `get` validates the key and calls `self.map.get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-180` — `MeteredOrdMap::find` performs the profiled binary search.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-451` — each host invocation builds the enforcing storage map from the transaction footprint.

## Evidence

In the current soroswap trace, timestamp correlation against `applyLedger` windows shows these zones are inside the measured apply subtree: `map lookup` has about 1.30s self-time over 660,907 in-apply calls; `storage get` has about 847ms over 154,903 in-apply calls; `get_contract_data` has about 1.00s, `has_contract_data` about 499ms, `put_contract_data` about 307ms, and `new map` about 392ms inside `applyLedger`. These zones are descendants of host invocation under `TransactionFrame::parallelApply` / `InvokeHostFunctionOpFrame doParallelApply`, not tx-set construction. The structural pattern is a high-call-count lookup path where the host repeatedly searches ordered metered maps even though the enforcing footprint is immutable and small for the duration of the transaction.

## Anti-Evidence

`MeteredOrdMap` provides deterministic ordering and budget metering, so a direct replacement with an unordered container could change iteration order or metering if done naively. A viable implementation must keep deterministic ordered storage for output and charge the same protocol costs; the optimization should be limited to an internal sidecar lookup/index for enforcing-mode access, not recording-mode footprint discovery or externally visible map semantics.
