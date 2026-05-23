# H008: Carry Footprint Access Types Beside Storage Entries During Ledger-Change Extraction

**Date**: 2026-05-23
**Subsystem**: soroban, rust
**Severity**: Low
**Impact**: Soroswap apply-time reduction by avoiding one metered footprint-map lookup per host storage entry during output extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a Soroban invocation succeeds, Rust output extraction should classify every storage entry as read-only or read-write exactly as declared in the transaction footprint. For every entry it should return the same encoded key, encoded new value, TTL change, rent size fields, and delete sentinel semantics that C++ `recordStorageChanges` expects today.

## Mechanism

`get_ledger_changes` iterates `storage.map` and then performs `footprint_map.get(key, budget)` to recover the access type for the same key. Because the enforcing `StorageMap` is built from the footprint and retains the same sorted-key universe, a side vector or zipped representation could carry `AccessType` alongside each storage entry and avoid the extra metered binary search. The expected deviation was that this repeated lookup might be a meaningful part of post-host output extraction for soroswap's many small invocations.

## Trigger

Run the current soroswap apply-load benchmark. Every successful Soroban host invocation calls `get_ledger_changes` after `host.try_finish()`, iterates the transaction's storage map, and classifies each entry before returning modified ledger entries to C++.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` walks `storage.map`, serializes keys/values, computes TTL changes, and looks up `AccessType` from `footprint_map`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:424-451` — invocation builds the enforcing footprint and storage map before executing the host function.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-190` — each `MeteredOrdMap::get` performs a metered binary search and key comparison.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` consumes `LedgerEntryChange` and preserves the C++ output contract.

## Evidence

The current Tracy trace keeps the surrounding output path inside `applyLedger`: `invoke_host_function` has 15,702 in-apply events and `recordStorageChanges` is called once per successful invocation. The source shows an unconditional `footprint_map.get` at `e2e_invoke.rs:257-258` after the code has already iterated the storage map entry for the same key. The lookup is conceptually redundant because storage enforcement guarantees every storage key is covered by the footprint and C++ depends only on the resulting read-only/read-write classification.

## Anti-Evidence

The access-type lookup is only a tiny part of `get_ledger_changes`, which is dominated by required XDR traversal, rent-size computation, TTL hashing/encoding, and output contract semantics. Prior retained failures already rejected old-entry XDR materialization, dirty-only output, storage-map snapshot CoW, and host-output XDR shortcuts as sub-threshold or contract-breaking. Removing or bypassing the metered lookup would also change Soroban budget observations unless the exact map-lookup charges are replayed, which leaves only the physical binary-search work as recoverable.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — this isolates the access-type lookup inside `get_ledger_changes`, distinct from prior old-entry serialization and dirty-output investigations.

### Why It Failed

The optimization is below the objective threshold and constrained by metering. Soroswap footprints contain only a handful of storage entries per invocation, so one avoided binary search per entry is bounded by a small fraction of the already-rejected output-extraction envelope. A correct implementation must either preserve the existing `MeteredOrdMap::get` charge sequence, eliminating most of the savings, or make a protocol-visible metering change.

### Lesson Learned

When a candidate is a sub-slice of the host-output extraction path, first compare it to the retained failures for old-entry serialization, dirty output tracking, and storage-map cloning. If the parent output path did not clear Medium, an internal binary-search cleanup cannot clear Medium without new direct measurements showing an unexpectedly dominant isolated cost.
