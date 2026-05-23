# H002: Avoid storage-map snapshot clone and second-pass lookups

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant host-side storage-map copies and lookups during result assembly
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each successful Soroban invocation, ledger-change extraction should compare final storage against the exact initial entries that were built from the transaction footprint, produce the same `LedgerEntryChange` values, compute the same rent inputs, and preserve the same budget-visible semantics. It should not need to deep-clone the entire initial `StorageMap` and then perform another metered map lookup for every entry during `get_ledger_changes`.

## Mechanism

`invoke_host_function` builds a `StorageMap`, immediately performs `let init_storage_map = storage_map.metered_clone(budget)?`, then later wraps that clone in `StorageMapSnapshotSource` and calls `init_storage_snapshot.get(key)` for every final storage entry in `get_ledger_changes`. On soroswap this sits in the apply-contained host path where `new map` at `soroban-env-host/src/host/metered_map.rs:148` totals 350,833,562 ns / 182,192 calls, while `map lookup indexed` at line 330 and `map lookup` at line 173 total 441,212,837 ns and 373,789,996 ns respectively. Replacing the deep initial clone with a compact immutable initial-entry snapshot indexed by footprint order, or retaining shared initial entry references and using them directly in `get_ledger_changes`, should remove a full per-invoke map copy and a second binary-search lookup pass without changing the final change list.

## Trigger

Run the soroswap apply-load benchmark and profile the `applyLedger` subtree. Any successful SAC transfer or pool operation with a nontrivial footprint triggers `invoke_host_function`, clones the just-built storage map at startup, mutates storage through persistent `MeteredOrdMap::insert`, and then scans the final map to re-find each initial entry via `StorageMapSnapshotSource::get`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-450` — `build_storage_map_from_xdr_ledger_entries` returns the initial map, then `storage_map.metered_clone(budget)?` clones it before moving the original into `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates final `storage.map` and calls `init_storage_snapshot.get(key)` for each entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource` implements the initial snapshot as another lookup into a cloned `StorageMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `from_exact_iter`/`new map` builds vector-backed maps.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-190` and `196-221` — map lookup and immutable insert rebuild the vector-backed map on hot storage paths.

## Evidence

The initial snapshot exists only so result assembly can recover old entries and old TTL values; the invocation itself does not need a second independently mutable copy of the map. The footprint already defines the deterministic key set, and `build_storage_map_from_xdr_ledger_entries` already sees every initial entry and TTL value while constructing the storage map. A compact side snapshot built at that point can preserve all old-entry/rent semantics while avoiding deep `MeteredClone` work and repeated binary searches during `get_ledger_changes`.

## Anti-Evidence

Prior dirty-key and mutable-overlay host-storage ideas failed because they changed output tracking semantics or introduced broad mutable map behavior. This hypothesis is narrower: it should leave `Storage` mutations and the final full-footprint scan intact, and only replace the representation of the immutable initial snapshot used by `get_ledger_changes`. Budget metering is a protocol-visible surface, so any implementation must either preserve metered costs exactly or be protocol-gated with updated budget expectations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `002-positioned-initial-storage-snapshot.md`
**Failed At**: reviewer

### Trace Summary

The reviewed checkout still shows the described path: `invoke_host_function` builds enforcing storage, clones `storage_map` into `init_storage_map`, then `get_ledger_changes` asks `StorageMapSnapshotSource` to look up each final storage key in that cloned map. The `MeteredOrdMap` implementation confirms those `get` calls use the normal binary-search `find` path, while `insert` and clone-related map construction share the broad `new map` Tracy span. However, novelty fails because the ledger failure summary already records the substantially equivalent positioned initial-storage snapshot hypothesis and rejects it at reviewer stage.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-451` — `build_storage_map_from_xdr_ledger_entries` returns the initial storage map, then `storage_map.metered_clone(budget)?` creates the snapshot copy before the original map is moved into enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-507` — successful invocation output wraps `init_storage_map` in `StorageMapSnapshotSource` and passes it into `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates final `storage.map`, encodes keys, recovers old entries from the snapshot, computes rent inputs, checks footprint access type, and appends deterministic changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource::get` performs a keyed lookup in the cloned `StorageMap` and returns shallow `Rc` clones of old entries.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,168-190,227-249` — vector-backed map construction is traced as `new map`; keyed `get` uses `find`/binary search and `get_at_index` is the only direct indexed accessor present in this checkout.
- `ai-summary/fail/ledger/summary.md:36` — prior ledger novelty record for `002-positioned-initial-storage-snapshot.md` covers the same optimization angle: replacing the initial storage map clone with a positional snapshot to avoid per-entry lookup.

### Why It Failed

This is a duplicate investigation. The proposed compact/positional immutable initial-storage snapshot is substantially the same as the prior `002-positioned-initial-storage-snapshot.md` ledger failure summarized in `ai-summary/fail/ledger/summary.md`. The current source trace confirms the path under discussion, but the review pipeline has already evaluated this optimization angle, so it should not be promoted as a novel Medium hypothesis. The cited broad `new map` and `map lookup` Tracy totals also cannot be attributed entirely to the initial snapshot: they include mandatory storage-map construction, mutation-driven functional map rebuilds, footprint checks, and other host storage lookups.

### Lesson Learned

Before re-proposing Soroban host storage snapshot optimizations, check the condensed ledger failure history for positioned-snapshot and known-position lookup variants. A new hypothesis needs materially new evidence isolating removable wall-clock time in the current baseline, not aggregate `MeteredOrdMap` spans that mix snapshot lookup with mandatory storage and mutation work.
