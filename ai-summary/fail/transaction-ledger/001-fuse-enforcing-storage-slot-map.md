# H001: Fuse enforcing Soroban footprint and storage maps into one slot map

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing duplicate enforcing-storage map lookups and key comparisons
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-26 enforcing Soroban execution, a storage read, write, delete, `has`, or TTL extension should validate footprint access and retrieve or update the associated ledger entry with one deterministic key lookup. A key declared read-only should still reject writes, an undeclared key should still raise `ExceededLimit`, missing declared keys should still return `MissingValue` or `false` as today, and the final ledger changes, rent fee, events, diagnostics, and transaction result should be identical to the current two-map implementation.

## Mechanism

`Storage` currently stores access permissions in `FootprintMap` and entry values in `StorageMap`. In enforcing mode, `try_get_full_helper` first calls `prepare_read_only_access`, which performs a `FootprintMap` lookup through `Footprint::enforce_access`, then immediately performs a second `StorageMap` lookup for the same `Rc<LedgerKey>`; `put_opt_helper` similarly checks the footprint map and then updates the storage map. A protocol-gated enforcing-only representation such as `MeteredOrdMap<Rc<LedgerKey>, EnforcingStorageSlot>` can store `{access_type, entry}` together and make `get`/`has`/`put`/`del`/`extend_ttl` use a single lookup plus a local access-type check.

This is significant for soroswap because the accepted baseline still spends large aggregate worker time in storage and map primitives inside `applyLedger`: `storage get` is 453.519 ms over 228,838 events, `storage put` is 84.640 ms over 25,410 events, `storage has` is 43.790 ms over 20,516 events, generic `map lookup` is 636.489 ms, indexed `map lookup` is 386.588 ms, and `obj_cmp` is 827.944 ms in the timestamp-filtered apply windows. The proposal preserves determinism because it changes only the host-local storage layout for a single transaction and does not add parallelism or reorder commits.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and use the accepted trace `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`. Each invoke-host-function transaction builds enforcing storage from its footprint and then the router, pair, and SAC paths repeatedly call host storage APIs; every enforcing storage access currently pays both a footprint lookup and a storage lookup.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` are separate `MeteredOrdMap<Rc<LedgerKey>, ...>` structures keyed by the same `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` performs the first lookup for enforcing reads/writes.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper` performs `prepare_read_only_access` and then immediately looks up the same key in `self.map`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — `Storage::put_opt_helper` checks write access in `self.footprint` before inserting into `self.map`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-573` — TTL extension re-enters the same get/update path and would use the fused slot to avoid a second same-key lookup.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — enforcing invocation setup builds the footprint and storage maps separately today; the fused map can be bulk-built at the same boundary.

## Evidence

- Timestamp-filtered Tracy aggregation over the accepted soroswap trace found 70 `applyLedger` windows totaling 5.092 s, and the relevant storage zones are descendants of those windows rather than TX-set construction. Inside those windows: `storage get` totals **453,518,609 ns**, `storage put` totals **84,640,083 ns**, `storage has` totals **43,790,017 ns**, `extend key` totals **178,892,316 ns**, `map lookup` totals **636,488,924 ns**, `map lookup indexed` totals **386,587,986 ns**, and `obj_cmp` totals **827,944,291 ns**.
- The source shows a concrete duplicate lookup boundary. For enforcing reads, `prepare_read_only_access` only proves the key is in the footprint and then `self.map.get` repeats the key search to obtain the value. Since enforcing setup already inserts one storage-map entry for every footprint key, the two maps have the same key domain during apply.
- This is not a duplicate of the accepted bulk host-storage-map builder: that optimization changes how the two maps are constructed, while this changes the per-access representation used after construction. It also differs from the queued/reviewed immediate `has_contract_data` cache because it benefits every enforcing storage operation, not only adjacent has/get pairs.

## Anti-Evidence

- `MeteredOrdMap` operations are protocol-visible through budget charges. A safe implementation likely needs a protocol-gated metering change or explicit compatibility charges that preserve old budget totals while removing uncharged wall-clock work.
- The broad map and object-comparison zones include non-storage maps, host object comparisons, and contract data structures. A reviewer should add narrow counters around `Footprint::enforce_access` plus `StorageMap::get/insert` before accepting the full projected benefit.
- Recording mode has different semantics because it mutates the footprint as it discovers accesses and reads through a `SnapshotSource`. The candidate should initially be enforcing-only to avoid changing preflight behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The claimed duplicate lookup is present in enforcing storage: `Storage::try_get_full_helper` calls `prepare_read_only_access`, which reaches `Footprint::enforce_access` and performs a `FootprintMap` lookup, then immediately calls `self.map.get` for the same `Rc<LedgerKey>`. Writes and deletes similarly enforce the footprint before calling `StorageMap::insert`, and TTL extension re-enters the get path through `prepare_extend_ttl`. Enforcing setup also populates `StorageMap` with an entry, including `None` for missing values, for every footprint key, so the same-key domain premise is valid for the apply path. The optimization is novel relative to the prior bulk map-construction success, typed SAC fast path success, SAC TTL fusion failure, and immediate has/get cache failure, but its removable critical-path share is below the objective threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` are separate `MeteredOrdMap<Rc<LedgerKey>, ...>` instances keyed by the same ledger-key type.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` performs a metered map lookup and read/write permission check for every enforcing access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — reads call `prepare_read_only_access` and then perform a second lookup in `self.map`; the value is cloned only after the second lookup succeeds.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — writes validate key/entry type, enforce `ReadWrite` access through the footprint map, then call `self.map.insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-428` — `has` is implemented as `try_get_full(...).is_some()`, so it pays the same footprint lookup plus storage lookup as a read.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-573` — TTL extension validates the request, calls `get_with_live_until_ledger`, then conditionally reinserts the entry with a new live-until value.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-720` — enforcing `prepare_read_only_access` does only the footprint access check; recording mode has different read-through/cache semantics and should not be fused by this hypothesis.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — host setup builds the footprint map and then builds the storage map, explicitly inserting `None` storage slots for footprint keys missing from the encoded ledger entries.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2317` — persistent/temporary `has_contract_data`, `get_contract_data`, `put_contract_data`, `del_contract_data`, and `extend_contract_data_ttl` all enter the storage helpers during contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — generic `put_contract_data_into_ledger` can compound the same storage access pattern by checking `has`, then reading, then writing for existing values.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — each `MeteredOrdMap::get`/`insert` performs a metered binary search; a true single-lookup fused update would require a new storage/map API and explicit budget semantics.
- `ai-summary/CURRENT_STATE.md:39-78` — the accepted current baseline is the `soroswap, TX=2000, T=8` non-Tracy median set averaging 278.740030 ms, while the Tracy run is diagnostic only.
- `ai-summary/fail/transaction-ledger/summary.md:24-30` — prior rejected storage-map and map-position hypotheses establish that aggregate worker timings must be normalized by the eight Soroban clusters before projecting apply-time impact.

### Why It Failed

The optimization target is real, but the projected impact is below the objective's Medium floor. The hypothesis's own diagnostic trace reports 70 `applyLedger` windows totaling 5.092 s with `T=8`; even deleting the entire broad `map lookup` category would save only `636.489 ms / 8 = 79.6 ms` across the whole trace, about 1.6% of the Tracy apply window and roughly `79.6 ms / 70 = 1.14 ms` per ledger against the 278.740 ms headline non-Tracy baseline. The fused slot can remove only the footprint-side subset of those lookups, not every map lookup, indexed storage lookup, object comparison, storage conversion, TTL check, clone, or insertion cost. Because the objective accepts only Medium/High findings and rejects Low-tier projections, this is not viable for the optimize-soroswap pipeline.

### Lesson Learned

For enforcing Soroban storage, proving a duplicated same-key lookup is not enough. The removable subset must be sized after cluster normalization and after filtering broad `MeteredOrdMap`/`obj_cmp` zones down to the exact footprint-enforcement lookup being eliminated; generic map work in the current soroswap trace is too small to support a Medium finding by itself.
