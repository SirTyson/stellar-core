# H002: Identity-Skip Unchanged Read-Only Entries in get_ledger_changes

**Date**: 2026-05-21
**Subsystem**: soroban-env (e2e_invoke, storage)
**Severity**: Medium
**Impact**: apply-time reduction in post-invocation diff computation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `get_ledger_changes` iterates the post-execution storage map, a
read-only entry that the contract did not touch must yield a no-op
`LedgerEntryChange`: `read_only = true`, `encoded_new_value = None`, no TTL
delta, and an old-entry size that is identical to the value the input
buffer's length already conveyed. The expected implementation: detect that
"untouched" condition via cheap pointer identity (`Rc::ptr_eq`) between the
final-map entry's `Rc<LedgerEntry>` and the snapshot's, and short-circuit
the rest of the per-entry work — no XDR encoding of key or old entry, no
fresh allocation, no metered map lookups beyond what's necessary to mark
the change as "read-only no-op".

## Mechanism

`get_ledger_changes` (`e2e_invoke.rs:206-291`) iterates *every* entry in
`storage.map`, including all read-only entries. For each one it
unconditionally encodes the key (`metered_write_xdr` → `entry_change.encoded_key`,
line 208), looks up the init snapshot (line 225), encodes the old entry
(line 228), allocates a `Vec<u8>` for the encoding, computes
`entry_size_for_rent`, populates a `LedgerEntryLiveUntilChange`, and pushes
the change into the output vector. For an untouched read-only entry the
*entire* output is dead weight: downstream code (`recordStorageChanges` on
the C++ side) reads `entry_change.read_only == true` and discards the
entry. The actual ledger-state delta for an unmodified read-only entry is
empty — the encoded key, encoded old value, and TTL fields are never read.
The deviation: we do an O(footprint) chain of XDR encodes + map lookups +
allocations per op to produce a `LedgerEntryChange` that the consumer
treats as a no-op.

## Trigger

Run the soroswap apply-load benchmark. Each op has ~10-20 read-only
Soroban entries in its footprint (token contract code, asset metadata,
read-only balance lookups in the AMM path). For ops that don't modify
those entries (the common case for read-only entries by definition), the
per-entry diff work is pure overhead. Identity check via `Rc::ptr_eq`
fires for every read-only entry because the same `Rc<LedgerEntry>` is
inserted into both `storage_map` (line 1043) and `init_storage_map` (the
shallow clone at line 449) — neither path mutates the entry, so the `Rc`
identity is preserved.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-291`
  (`get_ledger_changes`, per-entry loop) — short-circuit unchanged
  read-only entries via `Rc::ptr_eq`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-449`
  (snapshot construction) — confirm `init_storage_map` is a shallow clone
  that preserves `Rc` identity for unmodified entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs`
  (`Storage::put`/`get`) — confirm that read-only access paths do not
  rewrap the `Rc<LedgerEntry>` (which would defeat identity).
- `src/rust/soroban/p26/soroban-env-host/src/xdr.rs::LedgerEntryChange`
  (consumer struct) — verify the downstream contract on a "no-op"
  `LedgerEntryChange`: what minimal fields must be set for `read_only =
  true` entries to satisfy C++ `recordStorageChanges`
  (`transactions/InvokeHostFunctionOpFrame.cpp:641`)?

## Evidence

1. The `init_storage_map` snapshot is built via `storage_map.metered_clone(budget)?`
   (line 449). `StorageMap` is the project's `MeteredOrdMap` HAMT, whose
   clone is structural-sharing — i.e. the `Rc<LedgerEntry>` values are
   reference-counted, not deep-copied. Therefore unmodified entries have
   `Rc::ptr_eq(post, snapshot) == true` by construction.
2. The Soroban host's `Storage` enforces footprint access types: a
   read-only entry cannot be written. So no `storage.put` will ever
   replace the `Rc<LedgerEntry>` for a read-only key, guaranteeing
   identity preservation across the invocation.
3. The C++ consumer `recordStorageChanges`
   (`transactions/InvokeHostFunctionOpFrame.cpp:641-741`) iterates only
   `out.modified_ledger_entries` — entries with `encoded_new_value !=
   None`. For read-only entries with `encoded_new_value = None`, the C++
   side already skips per-entry processing (the loop body is gated on
   `modified_ledger_entries`, which excludes read-only entries). So
   producing a stub `LedgerEntryChange` for read-only entries is wasted
   serialization work that the consumer never reads.
4. Tracy: `invoke_host_function` self-time 7.20% (741M ns / 6776 calls /
   ~109µs each). Subtracting other tracked descendants (VM,
   instantiate_wasmi, dispatch wrappers) leaves a sizable portion in the
   non-zoned setup/teardown — `get_ledger_changes` and friends are
   prominent candidates. Eliminating ~75% of the per-entry work on
   read-only entries (estimated ~50-100ms aggregate Tracy savings) maps
   to ~6-12ms wall savings under 8-way parallelism — within Medium
   severity (3-10% of 272.9ms baseline).
5. Combines cleanly with H001 (cache entry size): even on the
   write-affecting code paths, the `Rc::ptr_eq` short-circuit applies to
   the OLD-entry encoding for ReadWrite entries that the contract chose
   not to modify. Soroswap routinely lists balance keys in ReadWrite
   footprint that aren't actually written on every code path.

## Anti-Evidence

1. `MeteredOrdMap::insert` calls `metered_clone` of the inserted value
   when restructuring the HAMT internal nodes. If insertion ever rewraps
   the `Rc<LedgerEntry>` (e.g. via `Rc::clone` then `Rc::metered_new`),
   identity could be lost. Need to verify the actual map mutation path
   preserves `Rc` identity for already-present read-only keys. (Inspection
   of `storage.rs` and `MeteredOrdMap` is required to confirm.)
2. The `LedgerEntryChange` struct's downstream contract may require the
   `encoded_key` to be populated even for read-only entries — e.g.
   diagnostic event extraction, simulation mode, or fee computation
   paths. Need to verify by inspecting consumers in
   `transactions/InvokeHostFunctionOpFrame.cpp` and any test/sim paths.
3. Recording mode (`add_footprint_only_ledger_changes`, line 305) may
   depend on read-only `LedgerEntryChange` entries being fully populated.
   That path is `#[cfg(any(test, feature = "recording_mode"))]` only — so
   the enforcing-mode optimization (the only one that runs during apply)
   is safe, but a clean refactor must preserve recording-mode behavior.
4. The savings depend on the read-only fraction of the footprint. If
   soroswap ops have a high *write* fraction (e.g. most footprint entries
   are balances being updated), the win narrows. Need to confirm via
   actual footprint counts — but the AMM swap pattern (read token
   metadata + write balances on both sides) typically has ~50/50
   read-only/read-write entries per op, so the read-only path is a real
   and consistent chunk of work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban-env/summary.md` entry `004.md` ("Batch e2e footprint/storage/TTL map construction and avoid re-serializing old ledger entries in `get_ledger_changes`") and the follow-up `ai-summary/fail/soroban-env/001-cache-entry-size-in-storage-map.md`
**Failed At**: reviewer

### Trace Summary

The traced apply path builds the enforcing storage map from encoded ledger entries, shallow-clones it as the initial snapshot, runs the host, and then calls `get_ledger_changes` before reading the final CPU/memory budget totals. `get_ledger_changes` does perform the claimed per-entry work for read-only entries: it encodes the key, performs TTL/snapshot/footprint lookups, serializes the old entry into a discarded buffer, computes rent size, marks `read_only`, and pushes a no-op `LedgerEntryChange`. Downstream C++ only receives modified entries and TTL effects, so a read-only entry with no TTL extension is not directly consumed; however, skipping the metered serialization and lookup work is the same previously rejected `get_ledger_changes` optimization class because these charges are included in protocol-visible budget accounting.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` unconditionally encodes every key, computes old-entry rent size by `metered_write_xdr`, looks up access type, sets `read_only`, and pushes every footprint entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — `invoke_host_function` constructs `storage_map`, clones `init_storage_map`, invokes the host, then calls `get_ledger_changes` before returning to the C++ bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1082` — input entries are decoded into `Rc<LedgerEntry>` values and inserted into `StorageMap`; the snapshot source clones the same `Rc`, so identity is preserved for unchanged entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28,252-390,431-514` — `StorageMap` stores `Option<(Rc<LedgerEntry>, Option<u32>)>`; reads clone the existing `Rc`, writes require `AccessType::ReadWrite`, and TTL extension can reinsert the same `Rc` with a changed live-until ledger, so `Rc::ptr_eq` alone is not a complete no-op test.
- `src/rust/src/soroban_proto_any.rs:391-506` — the bridge reads `cpu_insns` and `mem_bytes` after `e2e_invoke::invoke_host_function`, so `get_ledger_changes` metering is part of the observable output checked by stellar-core.
- `src/rust/src/soroban_proto_any.rs:261-301` and `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — Rust extracts only non-read-only `encoded_new_value` entries plus TTL changes for C++; C++ `recordStorageChanges` iterates only `out.modified_ledger_entries`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-68` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,353-371` — every XDR write callback charges `ValSer`, and `ValSer`/`MemCpy` have non-zero constant terms, making the number and shape of skipped charge calls budget-visible.
- `ai-summary/fail/soroban-env/summary.md:12` and `ai-summary/fail/soroban-env/001-cache-entry-size-in-storage-map.md:123-151` — prior investigations already rejected avoiding old-entry reserialization in `get_ledger_changes` because preserving exact p26 metering would require reproducing the same per-write budget charges.

### Why It Failed

This is not novel: it is a more aggressive form of the already-investigated `get_ledger_changes` old-entry serialization skip. The additional read-only no-op filter would also skip `metered_write_xdr` and map-lookup charges that are included in `cpu_insns`/`mem_bytes`; preserving those charges requires replaying the exact per-callback `ValSer` and `MemCpy` accounting, which is the same reason the prior optimization was rejected. The proposed `Rc::ptr_eq` condition is also incomplete by itself because TTL extension can leave the `Rc<LedgerEntry>` unchanged while changing the associated live-until ledger, so a safe no-op detector would need to compare TTL state as well.

### Lesson Learned

In p26 Soroban apply work, a ledger-change object can be semantically unused by C++ yet still have protocol-visible budget side effects from the Rust bridge path that produced it. Future `get_ledger_changes` hypotheses need to separate removable physical work from mandatory metering first; if exact metering requires rerunning or precisely emulating XDR writer callbacks and map lookups, the optimization is a duplicate of the prior failed serialization-skip class rather than a new Medium-severity candidate.
