# H002: Copy-on-write invoke storage snapshots instead of cloning the full `StorageMap`

**Date**: 2026-05-04
**Subsystem**: soroban-env / rust
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-invocation Rust storage-map clone/diff scaffolding while preserving transaction isolation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each invoke-host transaction, the host must see the same enforcing footprint entries and TTLs as today. Successful transactions must return the same modified ledger entries, TTL changes, events, return value, fees, and budget totals; failed transactions must return no ledger changes and must not leak mutations into later transactions. Any replacement for the initial-storage clone must preserve p26 metering exactly or be gated to a new protocol with deliberate metering changes.

## Mechanism

`e2e_invoke::invoke_host_function` builds a fresh `StorageMap` from the C++-provided footprint buffers and immediately performs `init_storage_map = storage_map.metered_clone(budget)?` before constructing `Storage`. After host execution, `get_ledger_changes` compares final `Storage` against `StorageMapSnapshotSource { map: &init_storage_map }`, forcing a second full map snapshot even though only a small subset of the footprint is actually modified by the transaction. A copy-on-write storage snapshot could store each entry's original value next to the live slot, or log the original value on first write/delete, then diff against that embedded old value without a separate full `StorageMap` clone; p26 could still replay the same logical clone charges while avoiding the physical clone and extra map lookups.

## Trigger

Run the current soroswap apply-load benchmark. Each successful swap enters `invoke_host_function` with a small but non-empty footprint, builds `StorageMap`/TTL maps from encoded ledger entries, clones the whole map for the initial snapshot, executes the host, and diffs the result. The trigger is ordinary successful Soroswap execution where thousands of transactions repeat this clone-and-diff setup inside `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-451` — builds `storage_map` and `init_ttl_map`, then clones `storage_map` into `init_storage_map` before creating enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-507` — constructs `StorageMapSnapshotSource` over the clone and calls `get_ledger_changes` after successful execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — builds the per-invocation `StorageMap` from XDR ledger-entry and TTL buffers.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28,92-128` — defines `StorageMap`/`FootprintMap` as `MeteredOrdMap`s; this is the map shape that would need an original-value sidecar or first-write log.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource` currently exposes the cloned map to the diff code.

## Evidence

The current diagnostic trace shows the whole single-transaction Rust invoke wrapper inside `applyLedger`: `invoke_host_function,soroban-env-host/src/e2e_invoke.rs,488,741215306 ns self,6776 calls`, with related storage/map leaves such as `new map,soroban-env-host/src/host/metered_map.rs,148,331023872 ns`, `map lookup indexed,...,408451716 ns`, `map lookup,...,345449339 ns`, `storage get,...,215980007 ns`, and `storage put,...,79591389 ns`. The storage clone itself is not separately zoned, but source reading shows it is mandatory on every invocation before host execution and is part of the per-transaction scaffolding that remains after prior C++ add-read/XDR-size micro-optimizations were rejected as too small. Unlike the already-rejected Rust-owned cluster overlay, this does not move the C++/Rust bridge boundary or keep state across transactions; it only changes the Rust-internal representation of one invocation's initial snapshot.

## Anti-Evidence

The removable slice must be measured directly because `invoke_host_function` self-time also includes required XDR decoding, host setup, result/event encoding, and budget accounting. `StorageMap` is metered and immutable-by-convention, so replacing a physical clone with a COW old-value sidecar must not accidentally remove protocol-visible `MeteredClone` charges or change `get_ledger_changes` ordering. If exact charge replay makes the COW path more expensive, or if the clone proves to be a small fraction of the wrapper zone, this should be rejected rather than expanded into the broader cluster-overlay design already recorded as non-viable.
