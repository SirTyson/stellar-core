# H002: Track Dirty Host Storage Keys to Skip Unchanged Footprint Output Walks

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by making ledger-change extraction proportional to modified/TTL-bumped keys instead of the full enforcing storage map
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, production apply should emit ledger effects and rent inputs only for entries that changed: read-write entries with new/deleted values and read-only or read-write entries whose TTL was extended. Unchanged read-only footprint entries should not require key XDR serialization, old-entry serialization, initial-snapshot lookup, footprint lookup, or `LedgerEntryChange` allocation merely to be discarded later by `extract_ledger_effects`. The old full-footprint output walk should remain available for recording/simulation compatibility or released-protocol exact metering, but the next-protocol production path can track dirty keys as mutations happen.

## Mechanism

`build_storage_map_from_xdr_ledger_entries` constructs `StorageMap` with every provided footprint entry and then adds `None` placeholders for footprint keys that were not loaded (`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:976-1052`). `get_ledger_changes` then iterates `storage.map.iter(budget)?` over that entire map (`e2e_invoke.rs:206-291`), serializes every key, looks up old state through `StorageMapSnapshotSource::get`, serializes old entries to compute rent size, looks up every key in the footprint map, and only later allows `extract_ledger_effects` to discard read-only entries (`src/rust/src/soroban_proto_any.rs:261-301`). Soroswap swap transactions have a roughly half read-only footprint (`routerInstance`, two SAC instances, `routerCode`, `pairCode`) and a roughly half read-write footprint (`two trustlines`, two SAC balances, pair instance). The actual behavior therefore makes the output phase pay per-footprint-entry work for immutable read-only entries on every tx even though unchanged read-only entries do not contribute modified ledger entries or rent changes.

## Trigger

Run the current soroswap apply-load benchmark from `CURRENT_STATE.md`. Instrument `Storage::put_opt_helper`, `Storage::apply_ttl_extension`, and `get_ledger_changes` to count `(storage.map.len, dirty_entries, ttl_changed_entries, read_only_unchanged_entries)` per invocation. The triggering condition is the normal soroswap swap footprint: read-only router/token/code entries are present in enforcing storage, but only pair/balance/trustline entries and TTL bumps can become output effects.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-357` - `try_get_full_helper` and `put_opt_helper`; mutation points can record dirty keys and first-seen old values.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-615` - `apply_ttl_extension` / `extend_ttl_v2`; TTL extension points can record keys whose live-until values changed.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` - `get_ledger_changes` currently walks the full `storage.map`, serializes old/new data, and consults the footprint for every entry.
- `src/rust/src/soroban_proto_any.rs:261-301` - `extract_ledger_effects` discards read-only entries and only materializes modified entries plus TTL entries, showing the full read-only walk is not needed for production bridge output.
- `src/simulation/ApplyLoad.cpp:3449-3476` - soroswap swaps build a fixed mixed footprint with five read-only entries and five read-write entries, making unchanged read-only output work repeat at high volume.

## Evidence

- The diagnostic trace confirms the candidate output/input surfaces are under `applyLedger`: `write xdr` totals about `168 ms`, `read xdr with budget` about `179 ms`, `storage get` about `642 ms`, and `map lookup`/`map lookup indexed` about `1.12 s` inside apply windows. `recordStorageChanges` alone accounts for `98 ms` over 6,776 invocations after Rust has already filtered its `LedgerEntryChange` list.
- The current Rust code has no dirty-key set in `Storage`: `StorageMap` is the only post-execution source of changes, so `get_ledger_changes` must rediscover unchanged vs changed status by scanning all entries and comparing access types.
- This is not the same as the rejected old-entry XDR-size cache. That work preserved the full released-protocol output walk and exact metered serialization; this hypothesis is a next-protocol production extraction mode that changes the algorithm to be proportional to actual writes/TTL bumps and avoids visiting unchanged read-only entries at all.
- Deterministic output ordering can be preserved by recording dirty keys and TTL-changed keys in footprint order or sorting them by the same `LedgerKey` ordering before extraction. The final modified entries and TTL entries remain byte-identical for the keys that actually changed.

## Anti-Evidence

- The impact must be measured carefully because prior bridge-output hypotheses were below Medium when they preserved all metered XDR walking. This hypothesis only clears the objective if the next-protocol dirty-key path removes enough full-footprint work, especially read-only code/instance entries, to exceed the 3% floor.
- Dirty tracking must handle rollback: frame errors roll back `StorageMap`, events, and authorization snapshots. Any dirty-key side table has to be included in rollback points or derived from committed storage mutations only, otherwise failed internal calls could leak false output effects.
- Recording-mode and simulation APIs may rely on full footprint ledger changes, including footprint-only entries. The optimized path should be limited to production enforcing apply output used by stellar-core's `InvokeHostFunctionOutput`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - related to prior `get_ledger_changes` / bridge-output failures, but not a duplicate because it proposes a new dirty-key extraction mode rather than preserving the full metered walk
**Failed At**: reviewer

### Trace Summary

The inefficiency exists: production `invoke_host_function` clones the initial enforcing `StorageMap`, executes the host function, then `get_ledger_changes` walks every final storage-map item, serializes every key, consults the initial snapshot, serializes old entries for rent sizing, consults the footprint, and only later lets the bridge discard read-only entries. However, the proposed dirty-only production output does not match the current C++/Rust bridge contract. `InvokeHostFunctionOutput.modified_ledger_entries` can only carry new `LedgerEntry` values; `recordStorageChanges` treats every read-write footprint key not covered by that vector as deleted, so omitting unchanged read-write keys would erase live entries unless a new explicit deletion/pass-through representation is added.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` - enforcing invocation builds a full `StorageMap`, clones it as `init_storage_map`, finishes the host, and calls `get_ledger_changes` only on successful invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-291` - `get_ledger_changes` allocates for `storage.map.len()`, iterates all storage entries, serializes keys, reads the initial snapshot, serializes old entries for rent size, looks up footprint access type, and serializes new values for all present read-write entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-365` - rent extraction consumes `LedgerEntryChange` records only when a TTL exists and the live-until value or size actually changes.
- `src/rust/src/soroban_proto_any.rs:261-301` - `extract_ledger_effects` drops read-only ledger changes but emits every present non-read-only new value plus TTL entries whose live-until value increased.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-765` - `recordStorageChanges` decodes `modified_ledger_entries`, marks matching read-write footprint keys as covered, upserts returned entries, and then erases every uncovered read-write key; omission is currently the deletion signal.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-408` - `put` and `del` both funnel through `put_opt_helper`, the natural mutation point for a dirty-key set, while `del` stores `None` in the map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-642` - TTL extension only mutates the storage map when the computed live-until ledger increases, so TTL-dirty tracking would be possible at this point.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-225` and `:401-562` - frame rollback snapshots and restores only `StorageMap`, events, and auth; any side-table dirty tracking would need to be included in rollback state or derived after rollback.
- `src/simulation/ApplyLoad.cpp:3447-3476` - soroswap swaps use five read-only and five read-write footprint keys, confirming the repeated mixed-footprint shape.

### Why It Failed

The proposed fix would break correctness if implemented against the current output contract. A dirty-only `modified_ledger_entries` vector has no way to distinguish "unchanged read-write entry" from "deleted read-write entry"; Core currently relies on absence from the returned vector to erase read-write footprint entries. Therefore the target surface is incomplete: preserving semantics would require either an explicit deletion/change output format and matching `recordStorageChanges` changes, or retaining pass-through output for all live read-write footprint entries and only skipping read-only no-ops.

The severity claim is also not established at the objective's Medium threshold. The broad trace zones cited include input bridge serialization, contract storage reads, general map lookups, and `recordStorageChanges`; the read-only output walk is only a subset, and `recordStorageChanges` already runs after Rust has filtered read-only changes. Prior failed investigations of `get_ledger_changes` and C++/Rust bridge XDR work bound related output/bridge savings below the 3% floor unless the entire XDR walk can be skipped safely. This hypothesis does not provide a complete safe output protocol for doing that, so it cannot be promoted for the optimize-soroswap objective.

### Lesson Learned

For Soroban host output optimizations, first account for the bridge's deletion semantics: current `modified_ledger_entries` is both a value list and an implicit coverage map for read-write footprint keys. Skipping no-op read-only `LedgerEntryChange` construction may be a useful future protocol-gated refinement, but a viable Medium-severity proposal must include an explicit correctness-preserving output representation and isolate the removable read-only output-walk cost from broader input/XDR/storage trace totals.
