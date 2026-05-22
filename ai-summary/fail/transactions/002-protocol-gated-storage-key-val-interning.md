# H002: Protocol-Gated Storage-Key Val Interning

**Date**: 2026-05-22
**Subsystem**: transactions / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating repeated physical `ScVal` host-object construction and ordered-map churn for immutable storage keys during host invocation.
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When Soroswap transactions repeatedly read and write the same contract storage keys, the host should resolve those keys to the same logical values and produce identical ledger changes, events, return values, and errors. For protocol 27+ benchmarking, the host may charge a revised cheaper cost model and reuse deterministic per-invocation key objects, but it must not share mutable objects across transactions or alter current p26 metering.

## Mechanism

The enforcing-storage path repeatedly converts ledger-key `ScVal`s into host `Val`s and probes persistent metered maps even though many keys are immutable within a single host invocation. The current trace has `ScVal to Val` at `host/conversion.rs:436` with 471.1 ms self-time, `map lookup` at `metered_map.rs:173` with 370.2 ms, `map lookup indexed` at `metered_map.rs:330` with 439.2 ms, and `new map` at `metered_map.rs:148` with 355.7 ms; these events are inside the `applyLedger` descendant `parallelApply`/`invoke_host_function` path. A protocol-gated per-Host storage-key interner, populated while building the enforcing storage map and consulted by `Storage::get_with_live_until_ledger` / storage-key conversion, can preserve determinism while avoiding repeated physical host-object allocation and map reconstruction for canonical read-only key values.

## Trigger

Run the current soroswap apply-load scenario on the accepted protocol-27 baseline. The trigger is the repeated Soroswap router/pair/SAC storage access pattern where thousands of invocations convert and look up equivalent storage keys during `invoke_host_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-452` — builds the enforcing storage map and the initial snapshot for each host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-329` — hot `Storage::get_with_live_until_ledger` lookup boundary for contract storage keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` — generic `ScVal` to host `Val` conversion for storage keys and values.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:148-173` and `:330` — ordered-map allocation and lookup zones hit heavily by enforcing storage.

## Evidence

`csvexport-release -e` on the current soroswap trace reports `ScVal to Val` 471,110,683 ns, `map lookup` 370,232,726 ns, `map lookup indexed` 439,180,697 ns, and `new map` 355,668,368 ns. The apply-window overlap script counted the same zone families inside `applyLedger` (`ScVal to Val` 1,074,400,446 ns total-time overlap, `map lookup*` 1,201,099,534 ns, `new map` 484,740,377 ns), so this is not a TX-set-construction Tracy trap. Dividing aggregate worker time by T=8 still leaves a multi-percent upper bound if a key interner removes a broad slice of repeated conversion and map churn rather than only one lookup site.

## Anti-Evidence

A previous current-protocol storage-conversion cache was rejected because conversion work includes protocol-visible budget charges and rollback-sensitive host objects. This hypothesis is only viable if it is protocol-gated to p27+, keeps the cache strictly per Host invocation, charges the new cost model explicitly, and never reuses mutable storage values across nested frames or transaction boundaries. If the PoC cannot separate immutable key interning from mutable value semantics, it should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The enforcing apply path builds `Footprint` and `StorageMap` from XDR before constructing the `Host`, using `LedgerKey` values directly; it does not convert ledger-key `ScVal`s into host `Val`s during storage-map population. During contract storage calls, the host converts the contract-supplied key `Val` into an `ScVal`/`LedgerKey`, then performs mandatory footprint and storage-map lookups, and only converts stored ledger values back through `ScVal to Val` after a successful read. A per-Host storage-key `Val` interner populated from the enforcing storage map therefore cannot remove the cited `ScVal to Val` value-conversion span, nor can it eliminate the persistent-map rebuilds caused by `MeteredOrdMap::insert`.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-452` — `invoke_host_function` builds the footprint/storage map and clones the initial storage snapshot before `Host::with_storage_and_budget`; there is no host object table or key `Val` interning surface at this point.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` decode XDR, derive `LedgerKey`s with `ledger_entry_to_ledger_key`, insert them into metered maps, and add missing footprint entries; this uses `LedgerKey` comparison, not `ScVal`-to-`Val` conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242` — `has_contract_data` / `get_contract_data` convert the contract-supplied key with `storage_key_from_val`, then storage lookup returns an entry whose value is converted with `to_valid_host_val`; the cited `ScVal to Val` span is value materialization, not storage-key interning.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — durable writes also convert the supplied key once, then execute `has`, `get_with_live_until_ledger`, and `put` map operations; a key `Val` interner does not remove the map probes or copy-on-write map rebuilds.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-165,422-443,543-565` — storage-key construction goes through `from_host_val_for_storage` (`Val` to `ScVal`), while `to_host_val` / `to_host_obj` (`ScVal to Val`) recursively allocates host objects for ledger values and maps.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-329` — `try_get_full_helper` and `get_with_live_until_ledger` enforce footprint access and perform storage-map lookup; they clone the stored entry and have no existing key-object reuse boundary.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-174,196-240` — `new map` is emitted by persistent-map construction/reconstruction and `map lookup` by binary search; interning key host objects does not avoid these operations.

### Why It Failed

The hypothesis depends on treating broad `ScVal to Val`, `new map`, and `map lookup` trace families as removable by storage-key `Val` interning, but the actual key path uses the opposite conversion direction (`Val` to `ScVal`) and still must perform footprint/storage lookups. The expensive `ScVal to Val` work on this path is primarily stored value materialization such as `ContractDataEntry.val`, and the `new map` churn comes from `MeteredOrdMap` insert/rebuild semantics, not repeated construction of immutable key host objects. A narrower cache of contract-supplied key handles to `LedgerKey`s might remove some repeated key conversion, but the provided evidence does not isolate that cost and the remaining safely removable slice is below the objective's Medium threshold.

### Lesson Learned

For Soroban storage hypotheses, separate the three distinct costs before projecting impact: contract key ingress (`Val` to `ScVal` / `LedgerKey`), stored value egress (`ScVal` to `Val`), and metered ordered-map lookup/rebuild. A key interner cannot claim savings from value-conversion or persistent-map construction zones unless the traced code path actually routes those operations through the proposed cache.
