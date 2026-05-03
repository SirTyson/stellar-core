# H002: Replace per-invocation initial storage-map clone with a positional snapshot

**Date**: 2026-05-03
**Subsystem**: ledger / Soroban host invocation input-output accounting
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by avoiding a full cloned `StorageMap` and follow-up old-entry map lookups per host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban host invocation should preserve the old ledger-entry values
needed for `get_ledger_changes` without cloning a full key/value
`MeteredOrdMap` for every transaction. The old-entry snapshot should stay
aligned with the fixed enforcing-mode storage positions so ledger-change
construction can retrieve old values by position while producing the same
encoded keys, old sizes, TTL changes, rent changes, and new values.

## Mechanism

At the current optimized p26 source commit
`fa1226b3068605c5376efe56c6cf809ca225a036`,
`invoke_host_function` still performs
`let init_storage_map = storage_map.metered_clone(budget)?` before constructing
the enforcing `Storage`, then wraps that clone in `StorageMapSnapshotSource` and
passes it back to `get_ledger_changes`. The same code already builds
`InitialEntryMetadataByPosition` using `storage.enforce_storage_idx`, proving
the storage key set is fixed and positional during enforcing execution. A
compact `InitialStorageSnapshotByPosition` (for example, a vector of the
initial `Option<EntryWithLiveUntil>` values aligned to `storage.map`) would
avoid cloning the entire `MeteredOrdMap` and would let `get_ledger_changes`
consume old values by index instead of re-looking them up in a separate map.

## Trigger

Run soroswap apply-load with successful invoke-host-function transactions.
Every invocation builds the host storage from the encoded footprint entries,
clones the initial storage map, executes the host, and then calls
`get_ledger_changes` to compare final storage against the initial snapshot.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-590`
  (`fa1226b3`) — `invoke_host_function` builds `storage_map`, clones it into
  `init_storage_map`, creates enforcing `Storage`, and later calls
  `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:188-217`
  (`fa1226b3`) — `initial_entry_metadata_by_position`, existing positional
  metadata construction using the enforcing storage index.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-365`
  (`fa1226b3`) — `get_ledger_changes` iterates final storage and asks the
  initial snapshot for old values.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:250-339`
  (`fa1226b3`) — enforcing `Storage` stores `enforce_storage_idx` and preserves
  stable key positions while writes replace values in place.

## Evidence

The current soroswap trace shows `invoke_host_function`
(`soroban-env-host/src/e2e_invoke.rs:488`) with 741,215,306 ns self-time over
6,776 calls, entirely inside `applyLedger`. The same trace shows all
`new map` (449,677,501 ns), `map lookup`/`map lookup indexed`
(1,123,770,554 ns), and `ScVal to Val` (995,921,819 ns) events overlapping
`applyLedger`; while not all of these are from the initial snapshot path, the
clone and old-snapshot lookup are uninstrumented work currently folded into the
large `invoke_host_function` self bucket. Source evidence is strong: the host
already has a fixed enforcing storage index and already uses positional metadata
to avoid key lookups for old-entry size accounting.

## Anti-Evidence

`metered_clone` may be shallow for `Rc` values, so the saved copy cost is not
the full size of each ledger entry. The change must also preserve budget
accounting: if the current clone intentionally charges memory/CPU for the
initial snapshot, the positional snapshot must either charge equivalently for
p26 or be protocol-gated like prior host metering optimizations. This is
distinct from the previously rejected mutable-overlay insertion hypothesis
because it targets the immutable initial snapshot and `get_ledger_changes`
lookup path, not the final storage write representation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to `ai-summary/success/ledger/002-cache-old-entry-xdr-sizes.md`, but not an exact duplicate; that success cached old-entry XDR sizes and introduced positional metadata, while this hypothesis targets the remaining initial-storage snapshot clone.
**Failed At**: reviewer

### Trace Summary

The enforcing invoke path decodes input ledger entries into a `StorageMap`, shallow-clones that map into `init_storage_map`, builds enforcing `Storage` with stable key-position side indexes, runs the host, and then constructs ledger changes. The current optimized code already passes `Some(&init_storage_map)` into `get_ledger_changes`, and that function retrieves old entries with `get_at_known_position(pos, budget)` rather than a key-based map search when the snapshot and final storage sizes match. Therefore the hypothesis's "follow-up old-entry map lookups" are no longer binary/key lookups on this path; the only clearly removable work is the shallow snapshot container clone plus a positional vector access wrapper.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-579` — `invoke_host_function` builds `storage_map`, clones it into `init_storage_map`, constructs enforcing `Storage`, builds `InitialEntryMetadataByPosition`, and passes both the cloned map and metadata into `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:188-219` — `initial_entry_metadata_by_position` already aligns decoded ingress metadata to enforcing storage positions using `storage.enforce_storage_idx` when available.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-357` — `get_ledger_changes` iterates `storage.map` by position; old entries are read from `init_storage_map.get_at_known_position(pos, budget)` on the optimized path, and footprint access type is also read by known position.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1151` — `build_storage_map_from_xdr_ledger_entries` records input XDR size and TTL metadata while constructing the storage map, and pre-fills missing footprint keys with `None`, giving enforcing storage a fixed key set.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — `Storage::with_enforcing_footprint_and_map` builds side indexes from key to sorted-vector position for both footprint and storage maps.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:430-457` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:600-628` — enforcing writes and TTL extensions replace values at known positions, preserving the storage key set and position validity.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:325-339` — `get_at_known_position` skips binary search and key comparisons, but deliberately charges the same budget profile as a successful `get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:355-405` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:427-435` — cloning the snapshot map allocates and shallow-copies the backing vector; `Rc<LedgerKey>` and `Rc<LedgerEntry>` clones are reference-count bumps, not deep ledger-entry copies.
- `ai-summary/success/ledger/002-cache-old-entry-xdr-sizes.md:23-41` — prior confirmed work already converted old-entry rent-size metadata and snapshot access to positional paths, producing the Medium-tier win that this hypothesis partly relies on as evidence.

### Why It Failed

The remaining inefficiency is real but materially smaller than claimed. The current code already uses the fixed enforcing storage positions to avoid binary/keyed old-entry lookups in `get_ledger_changes`; a vector snapshot would not unlock the major "lookup removal" implied by the mechanism. It would primarily replace a shallow `MeteredOrdMap` clone of `Vec<(Rc<LedgerKey>, Option<EntryWithLiveUntil>)>` with a smaller vector of cloned `Option<EntryWithLiveUntil>` values.

That change may be a clean Low-tier micro-optimization, but it does not support the objective's required 3-10% Medium projection. If the new vector preserves the current p26 budget accounting, it must still pay comparable metered access charges and only saves the extra key/container shallow copy. If it deliberately removes those charges, most of the savings would come from a budget-semantics change that needs protocol-gating justification, and the already-confirmed old-entry XDR-size optimization shows the larger, serialization-heavy portion of this area has already been harvested. Under the optimize-soroswap review rules, a real but sub-Medium follow-up must be rejected rather than downgraded.

### Lesson Learned

After the positional metadata and old-entry XDR-size work, follow-up Soroban host-output hypotheses must distinguish between keyed `MeteredOrdMap` searches, indexed `MeteredOrdMap` accesses that only preserve budget profile, and shallow `Rc` container copies. The first category can justify Medium-tier performance work; the remaining initial-snapshot clone by itself is too narrow without direct trace evidence that it consumes at least 3% of `applyLedger`.
