# H002: Add an enforcing-storage lookup index beside ordered host storage maps

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing repeated binary searches and `LedgerKey` comparisons in storage get/has/put/extend with deterministic indexed lookup
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban enforcing storage should preserve the same footprint checks, ordered `MeteredOrdMap` contents, ledger changes, serialization order, and budget totals as today. However, once an invoke-host-function transaction has built its complete enforcing `FootprintMap` and `StorageMap`, hot storage operations should not have to binary-search the ordered vector and repeatedly compare XDR-heavy `LedgerKey`s for every `get`, `has`, `put`, and TTL extension on the same small fixed key set.

## Mechanism

`StorageMap` and `FootprintMap` are `MeteredOrdMap<Rc<LedgerKey>, ...>` values backed by sorted vectors. Every storage operation eventually calls `MeteredOrdMap::find`, which charges a binary-search cost and then runs comparator-driven binary search over `Rc<LedgerKey>` entries; writes call `insert`, which performs the same lookup before reconstructing a new ordered vector. For enforcing-mode storage, the complete footprint and initial storage map are known at host construction time, so `Storage` can maintain a private `LedgerKey`-hash side index from key to ordered-map position (or a small fixed lookup table keyed by the already validated footprint) while retaining the ordered map as the source of truth for deterministic iteration and output.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`. Timestamp filtering confirms the lookup zones are inside `applyLedger`: across applyLedger windows, `map lookup` at `soroban-env-host/src/host/metered_map.rs:95` appears 641,355 times for 1,037.215 ms total event time, and in the longest 972.093 ms apply window it appears 59,819 times for 119.518 ms total event time with 17.506 ms on the critical worker. The same longest window contains `storage get` at 93.244 ms, `storage has` at 23.381 ms, `storage put` at 19.465 ms, and `extend key` at 25.237 ms; these are the storage operations that repeatedly probe the same enforcing maps during soroswap router, pair, and SAC execution.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28` - `FootprintMap` and `StorageMap` aliases use ordered vector maps keyed by `Rc<LedgerKey>`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303` - `try_get_full_helper`, `try_get_full`, `get`, and `try_get` probe `self.map.get` for every storage read.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:380-389` - `put` enters the same ordered-map update path for every storage write.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:532-573` - `extend_ttl` calls `prepare_extend_ttl` and then storage update helpers for repeated TTL checks/extensions.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` - `find` performs the charged comparator-driven binary search.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-242` - `insert` and `get` both depend on `find`, so both reads and writes pay the lookup cost.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-452` - enforcing storage maps are built once from the known transaction footprint before host execution begins.

## Evidence

The source has a structural mismatch between data shape and access pattern. Soroswap footprints are fixed before invocation and small enough to preserve an ordered vector for deterministic output, but the host performs many repeated lookups against the same keys during one transaction: SAC balance reads/writes, pair instance updates, router/pair storage reads, and TTL extension all route through `Storage` and then `MeteredOrdMap::find`. The trace shows both the generic `map lookup` zone and the storage-specific callers are descendants of the measured `applyLedger` worker path, and the longest-window critical-worker lookup time is large enough that eliminating the comparator/search portion for enforcing storage plausibly saves around 10 ms on the critical path.

This is not the failed `metered-map-last-position-cache` hypothesis. A last-position cache only helps immediate repeated same-key probes and failed because hit rate is limited; an enforcing-storage side index covers arbitrary repeated footprint keys throughout the transaction while preserving the ordered map for iteration. It is also distinct from the reviewed bulk-build hypothesis, which removes repeated construction-time `insert`s before invocation; this targets runtime storage probes after the maps have already been built.

## Anti-Evidence

Budget accounting is protocol-visible. The index must either charge the same logical map-access and binary-search budget totals as today or be protocol-gated with explicit metering changes; silently making lookup cheaper could change resource-limit outcomes. `LedgerKey` hashing has its own cost and memory footprint, so the side index should be limited to enforcing `Storage` maps rather than generic `MeteredOrdMap` or recording mode. If the reviewed SAC typed-balance and duplicate-read hypotheses remove most SAC storage traffic first, the remaining non-SAC router/pair lookup share may fall below Medium and should be remeasured before implementation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL - duplicate/superseded by `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md`, recorded in `ai-summary/success/000-summary.md` and reflected in `ai-summary/CURRENT_STATE.md`
**Failed At**: reviewer

### Trace Summary

The runtime path is real: `invoke_host_function` decodes a fixed footprint and ledger-entry set, builds `FootprintMap` and `StorageMap`, and constructs enforcing `Storage` before contract execution. Enforcing reads call `prepare_read_only_access`, which probes the footprint map, then `try_get_full_helper` probes the storage map; writes and TTL extension likewise use footprint enforcement and `StorageMap::insert`, which is backed by `MeteredOrdMap::find`. However, this exact optimization area has already been confirmed in the current optimization arc as a storage-map lookup fast path, and the recorded measured result is Low, not Medium.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` - production invocation builds the restored-key set, footprint, storage map, initial snapshot, and enforcing `Storage` before creating the `Host`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956` - `build_storage_footprint_from_xdr` constructs the footprint as a `FootprintMap` by inserting read-write and read-only keys into a metered ordered map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` - `build_storage_map_from_xdr_ledger_entries` builds `StorageMap`, checks every ledger-entry key against the footprint, and inserts missing footprint entries as `None`, so enforcing storage starts from a complete fixed key set.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28` - both `FootprintMap` and `StorageMap` are `MeteredOrdMap<Rc<LedgerKey>, ...>` aliases.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` - `Footprint::enforce_access` performs a metered ordered-map lookup for every enforcing access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303` - read operations call `prepare_read_only_access` and then `self.map.get`, producing a footprint lookup plus a storage lookup per read.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-389` - write operations enforce read-write footprint access and then call `self.map.insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-573` - TTL extension reads the entry through `get_with_live_until_ledger` and, when the TTL is extended, updates the storage map through another insert.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-719` - enforcing-mode `prepare_read_only_access` only enforces the footprint; recording-mode cache-fill logic is not part of the production path.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` - `find` charges binary-search access, performs comparator-driven binary search, and is used by both `get` and `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:294-300` - `contains_key` also routes through `find`.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-430` - comparing `LedgerKey` values checks supported key types and dispatches to type-specific comparisons, so map lookup comparisons can be non-trivial.
- `ai-summary/CURRENT_STATE.md:1-10,18-30` - the accepted baseline is explicitly after the validated `LedgerKey` storage-map lookup fast path, with authoritative soroswap median apply times around 297-313 ms.
- `ai-summary/success/000-summary.md:4` - the prior accepted storage-map lookup fast path is recorded as Low severity with a 2.17% average soroswap median improvement.

### Why It Failed

This is not viable for the optimize-soroswap review queue because it has already been investigated and accepted under the Soroban-env storage-map lookup fast-path record, and the measured effect was only Low. The source trace confirms the underlying inefficiency, but the objective-specific reviewer rule accepts only Medium or High hypotheses; a confirmed ~2.17% median improvement is below the required 3% floor.

The mechanism also overlaps with prior transaction-ledger failures: generic last-position caching was rejected because critical-path map-lookup savings must account for cluster parallelism and deterministic metering, while in-place storage-map updates were rejected because the write-update portion alone was sub-threshold. This hypothesis broadens the lookup scope beyond those failures, but the already-confirmed storage lookup fast path establishes the actual top-line impact and supersedes another review of the same lookup family.

### Lesson Learned

For Soroban enforcing-storage lookup hypotheses, use the current accepted baseline and success summary before projecting from Tracy aggregate lookup zones. Runtime map lookup overhead is real, but in this arc the validated storage-map lookup optimization measured below the Medium threshold, so follow-up variants need a clearly larger mechanism than side-indexing the same fixed enforcing key set.
