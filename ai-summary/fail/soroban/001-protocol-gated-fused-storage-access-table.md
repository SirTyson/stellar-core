# H001: Protocol-Gated Fused Enforcing Storage Access Table

**Date**: 2026-05-23
**Subsystem**: soroban, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing duplicate enforcing footprint/storage binary searches and full-vector storage-map rebuilds with a single positional access table under a new protocol metering schedule
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a protocol greater than p26, enforcing-mode Soroban storage should validate a key against the transaction footprint, read or update its current entry, and preserve deterministic output ordering with one canonical per-footprint row. A `get`, `put`, `del`, or TTL extension should produce the same storage errors, ledger-entry changes, TTL behavior, rollback behavior, and event/result hashes as the current implementation under the new protocol's declared storage-metering schedule, while p26 ledgers continue to execute the exact released `FootprintMap` + `StorageMap` metering path.

## Mechanism

The current enforcing storage path pays two sorted-vector map lookups for most storage operations: one in `Footprint::enforce_access` and one in `StorageMap`, both through `MeteredOrdMap::find`. Writes then rebuild a whole immutable `StorageMap` vector through `MeteredOrdMap::insert` and `from_exact_iter`, cloning all keys and values for each changed entry. A protocol-gated fused access table built from the footprint and input ledger entries can store `{LedgerKey, AccessType, entry, live_until, dirty}` in footprint order, use the footprint row index for validation and access, and update the row in place; the final output walk can still emit deterministic sorted/footprint-ordered changes.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Every successful swap executes many SAC and contract storage calls under enforcing mode, especially through `SAC transfer`, `get_contract_data`, `put_contract_data`, and TTL extension. The current diagnostic trace's `applyLedger` windows contain 321,802 `storage get` calls, 39,431 `storage put` calls, 487,517 generic `map lookup` calls, 839,562 indexed `map lookup indexed` calls, and 181,114 `new map` calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956` — builds the enforcing `FootprintMap` one key at a time.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1025` — builds the initial `StorageMap` and TTL side map from encoded ledger entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-356` — `get_with_live_until_ledger` / `put_opt_helper` enforce footprint access and then perform separate storage-map access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-514` — TTL extension reads an entry and may rebuild the storage map to update live-until.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — `find`, `get`, and `insert` perform metered binary searches and full-vector rebuilds.

## Evidence

Timestamp filtering the current soroswap Tracy trace against the 71 `applyLedger` windows shows this storage/map family is in scope: `storage get` totals 672.085 ms over 321,802 calls, `storage put` totals 89.977 ms over 39,431 calls, `map lookup` totals 637.546 ms over 487,517 calls, `map lookup indexed` totals 585.969 ms over 839,562 calls, and `new map` totals 461.915 ms over 181,114 calls. The broader `charge` zone contributes another 1,740.102 ms over 19.68M calls, a meaningful part of which is the per-lookup/per-rebuild metering that a new p27 storage schedule could replace with one storage-access charge per public storage operation. Removing only the physical map duplication is too small; removing the duplicated internal map model and redefining the next-protocol metering around fused storage-access rows has a plausible 3-5% soroswap wall-time ceiling.

## Anti-Evidence

Prior p26-preserving storage-map indexing/in-place-update attempts failed because they either changed released metering or replayed enough exact charges to erase the speedup. This hypothesis is only viable as a new-protocol storage-metering design: p26 must keep the existing `MeteredOrdMap` charge sequence, and the PoC must show that the fused table's row-index bookkeeping does not reintroduce the same overhead through hash maps, side vectors, or output conversion.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate, but overlaps retained storage-map lookup/rebuild failures
**Failed At**: reviewer

### Trace Summary

The claimed duplicate enforcing-storage work exists: C++ `InvokeHostFunctionOpFrame` sends each Soroban transaction through the Rust bridge, `e2e_invoke::invoke_host_function` builds `FootprintMap` and `StorageMap`, and contract storage host functions then enforce the footprint before separately probing or rebuilding the storage map. The hot storage calls are descendants of `closeLedger` through the parallel Soroban apply path, so the target is in scope. However the measurable surface is the same storage-map lookup/rebuild family already shown to be either protocol-visible or sub-threshold, and the cited Tracy totals do not support a Medium projection after worker-parallel normalization and overlap between `storage`, `map`, and `charge` zones.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — serializes Soroban inputs and invokes the Rust host for each apply transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — constructs the per-invocation budget and delegates to protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-451` — decodes resources, builds the enforcing footprint, builds the initial storage/TTL maps, clones the initial storage map, and installs enforcing storage in a fresh host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — constructs `FootprintMap`, checks each supplied ledger entry against it, inserts entries into `StorageMap`, then inserts missing footprint keys as `None`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` performs a metered footprint-map lookup and rejects out-of-footprint or read-only-write accesses.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `try_get_full_helper` performs footprint access preparation and then a separate `StorageMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — writes enforce read-write access and then replace `self.map` with `MeteredOrdMap::insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-514` — TTL extension reads the current entry/live-until and rebuilds the storage map only when the TTL actually extends.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — output extraction iterates `storage.map` in canonical map order and performs another footprint lookup to classify read-only/read-write changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,168-242` — map construction charges/scans sorted vectors; `find` performs a charged binary search; `insert` clones prefixes/suffixes and rebuilds through `from_exact_iter`.
- `ai-summary/fail/soroban/summary.md:15,42` — prior retained failures cover in-place durable `StorageMap` upserts and indexed enforcing storage-map reads; both ran into metering semantics and/or benchmark regression.

### Why It Failed

The inefficiency is real, but the projected benefit does not clear this objective's Medium floor. The directly cited `map lookup` + `map lookup indexed` + `new map` totals are about 1.69s of aggregate worker time across the full diagnostic run; even treating all of that as removable, normalizing by `NUM_CLUSTERS=8` and comparing against the 71-ledger, ~218ms/ledger authoritative baseline yields roughly 1.4% wall-time. Adding the broader `storage get/put` spans double-counts child map/charge work, and the full `charge` zone cannot be attributed to storage or eliminated by this design without redefining much more than the storage access schedule.

A next-protocol metering schedule avoids the p26 observation-fixture blocker, but it does not by itself make the implementation surface small or the impact Medium. A fused table would have to replace the storage representation, preserve canonical sorted output order, keep rollback and missing-entry behavior, carry TTL side metadata, preserve p26 behavior in the same host crate, and avoid reintroducing index/hash/side-vector overhead. Given prior indexed/in-place storage attempts and the current trace sizing, this is a Low-tier or speculative redesign, which the optimize-soroswap reviewer objective rejects.

### Lesson Learned

For Soroban storage-map ideas, distinguish "protocol-visible metering blocker" from "severity blocker." Protocol-gating can make a metering change legal for a future protocol, but the review still needs a Medium-sized measured surface after subtracting overlap and parallel-worker aggregation; current enforcing-storage lookup/rebuild totals do not provide that evidence.
