# H002: Replace enforcing storage `MeteredOrdMap::insert` rebuilds with a mutable overlay journal

**Date**: 2026-05-01
**Subsystem**: ledger / Soroban host storage
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by avoiding full sorted-vector rebuilds on every host storage write and TTL extension
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When enforcing-mode host execution writes a ledger entry, deletes a key, or extends a TTL, the host should update the transaction-local storage value deterministically while preserving rollback and footprint enforcement. A write to one key should not allocate and clone a new sorted vector containing every storage-map entry unless the guest-visible ordering actually needs to be materialized.

## Mechanism

`Storage::put_opt_helper` updates `self.map` by assigning `self.map = self.map.insert(...)`. `MeteredOrdMap::insert` performs a binary search and then constructs a whole new map with `from_exact_iter`, which collects all entries into a fresh `Vec`, charges a deep clone, and revalidates sort order. `Storage::apply_ttl_extension` uses the same `insert` path for TTL-only updates. Soroswap repeatedly writes the same small read-write set across router/pair/token calls, so enforcing storage pays full immutable-map rebuild costs for per-key updates whose keys already exist in a fixed footprint. An enforcing-only mutable overlay or journal can keep the original sorted map immutable for reads, record per-key updates/deletes in an ordinal-indexed side vector or small delta map, and materialize the final sorted `StorageMap` only when `get_ledger_changes` consumes it.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the current baseline. Successful swaps execute SAC transfers and pair/router updates, producing `storage put` and TTL-extension operations inside `Host::invoke_function`. Each update to the transaction-local enforcing storage currently rebuilds a `MeteredOrdMap`, even though the footprint key set is fixed for the invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:179-183` — `Storage` stores a single immutable-style `StorageMap` today.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — `Storage::put_opt_helper` funnels writes and deletes into `self.map.insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — `Storage::apply_ttl_extension` updates TTL state through another `self.map.insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:532-642` — `extend_ttl` / `extend_ttl_v2` call `apply_ttl_extension` on hot Soroban paths.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `MeteredOrdMap::from_exact_iter`, the fresh-vector construction and deep-clone charge used by every insert.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — `MeteredOrdMap::insert`, the immutable-update path that rebuilds the map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:498-507` — after host execution, `get_ledger_changes` is the natural materialization point for any storage overlay because it compares final storage to the initial snapshot.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` shows these in-scope descendants of `applyLedger`:

- `new map` (`soroban-env-host/src/host/metered_map.rs:148`) = `225,573,670 ns` / 128,112 calls in self-time; timeline overlap shows `378,707,696 ns` total event time and 127,552 calls contained in `applyLedger`.
- `storage put` (`soroban-env-host/src/storage.rs:488`) = `54,008,999 ns` / 25,502 calls self-time, with nearly all events contained in `applyLedger`.
- `map lookup` + `map lookup indexed` together account for more than `1.02 s` of self-time in the trace, and `MeteredOrdMap::insert` performs a lookup before rebuilding.
- `charge` (`soroban-env-host/src/budget/dimension.rs:176`) fires 18,624,737 times for `1,747,927,342 ns` self-time. Immutable insert rebuilds trigger multiple metered copy/allocation charges per update, so reducing rebuilds also reduces budget-metering overhead while preserving exact per-operation metering if the overlay charges equivalent logical access/update costs.

This is not a construction-only issue: the accepted bulk-build optimization addressed building host footprint/storage maps at invocation ingress, but `Storage::put_opt_helper` and TTL extension still call immutable `insert` during contract execution. Soroswap's hot path writes and extends entries repeatedly, so replacing runtime writes with an overlay targets apply-time work inside `Host::invoke_function`, not TX-set construction.

## Anti-Evidence

- `MeteredOrdMap` immutability supports cheap rollback snapshots in `Frame::push_context` / `pop_context`. A mutable overlay must include a deterministic checkpoint journal so `with_frame` can restore prior values on contract errors exactly as today.
- Final ledger-change ordering must remain canonical. The overlay should materialize by iterating the original sorted footprint/storage order and applying per-key deltas, not by iterating an unordered map.
- Budget accounting is consensus-visible. The PoC must either preserve the current charged amounts for logical storage updates or update only exact budget-number tests if the implementation genuinely lowers metered CPU/memory work.
- Some `new map` calls come from host object maps and instance storage, not durable enforcing storage. A viable PoC needs narrower attribution to show that runtime durable-storage inserts account for enough of the zone to clear the Medium threshold.
- The overlay adds branching to read paths. If most soroswap time is read-only lookup rather than writes, the overlay must avoid slowing `Storage::try_get_full_helper`; pairing this with the unified-lookup hypothesis may be necessary.
