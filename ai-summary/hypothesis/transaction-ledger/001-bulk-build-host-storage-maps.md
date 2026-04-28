# H001: Bulk-build Soroban host footprint and storage maps instead of repeated `MeteredOrdMap::insert`

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban host storage initialization
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated clone-and-scan map construction before each host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each invoke-host-function transaction, the Rust host should construct the enforcing `FootprintMap` and initial `StorageMap` once from the footprint and C++-provided ledger-entry buffers. The efficient path should decode keys and entries, validate footprint membership and uniqueness, then build each sorted `MeteredOrdMap` with one allocation/scan rather than rebuilding a persistent vector map after every inserted key.

## Mechanism

`build_storage_footprint_from_xdr` starts with `FootprintMap::new()` and calls `MeteredOrdMap::insert` once for every read-write and read-only key. `build_storage_map_from_xdr_ledger_entries` repeats the same pattern for every decoded ledger entry and then again for every missing footprint key. Each `insert` calls `find`, allocates a new vector through `from_exact_iter`, deep-clone-charges the whole vector, and `from_map` scans and validates sort order, making setup effectively O(N^2) in footprint size even though the final map content is known up front.

A bulk constructor can collect `(Rc<LedgerKey>, AccessType)` and `(Rc<LedgerKey>, Option<EntryWithLiveUntil>)` pairs into vectors, sort/deduplicate them with the same host comparator, batch the equivalent metering, and call `MeteredOrdMap::from_map` once. This preserves deterministic map ordering and ledger effects while removing repeated vector reconstruction, repeated `new map` work, and many setup-time `map lookup`/budget-charge calls that occur before every soroswap host invocation.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) using the trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. Each parallel Soroban transaction enters `e2e_invoke::invoke_host_function`, decodes its footprint and ledger-entry buffers, and calls `build_storage_footprint_from_xdr` plus `build_storage_map_from_xdr_ledger_entries` before `Host::invoke_function`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-447` — invoke setup decodes resources, builds the footprint, and builds the initial storage map before host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-957` — `build_storage_footprint_from_xdr` repeatedly inserts each footprint key into an initially empty `FootprintMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` repeatedly inserts decoded entries, checks membership with `contains_key`, then inserts missing footprint keys one at a time.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_map` / `from_exact_iter` already provide the one-shot vector construction path, but current callers reach it once per insert.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-224` — `insert` performs a binary search and reconstructs the entire vector on each inserted key.

## Evidence

- Tracy self-time in the current soroswap trace shows `new map,soroban-env-host/src/host/metered_map.rs:148` at **130.563 ms self-time** over 64,552 calls, and `map lookup,soroban-env-host/src/host/metered_map.rs:173` at **411.627 ms self-time** over 382,266 calls. Timestamp filtering confirms 58,761 `new map` events totaling 182.222 ms and 348,072 `map lookup` events totaling 603.561 ms occur inside `applyLedger` windows.
- The longest `applyLedger` interval alone contains 57,926 `new map` events totaling 180.921 ms and 343,974 `map lookup` events totaling 600.152 ms, under the invoke-host-function apply path rather than TX-set construction.
- The setup source has a structural O(N^2) pattern: `MeteredOrdMap::insert` rebuilds a vector with `take(...) + new + skip(...)` and calls `from_exact_iter` for each footprint/storage entry, even though `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` know all entries before constructing the map.
- Soroswap invokes many small footprints through the same setup path. With 1,554 invoke-host-function events inside the current trace's `applyLedger` windows, eliminating even half of the repeated map-construction worker time is plausibly around 10-25 ms wall after T=8 normalization, enough to clear the 3% Medium threshold on the 596 ms headline soroswap median.

## Anti-Evidence

- `new map` is a generic `MeteredOrdMap` zone; not every call comes from initial footprint/storage construction. Contract `ScMap` conversions and object construction also use the same zone, so a PoC must add temporary counters or narrower Tracy spans to isolate the constructor share before claiming the full trace total.
- Budget accounting is protocol-visible. A bulk builder must preserve the same final CPU/memory budget totals, likely by applying exact batched charges equivalent to the current repeated inserts and scans; simply doing less charged work could change resource-limit outcomes.
- Sorting with the host comparator still costs O(N log N) comparisons and must reject duplicate/conflicting footprint keys exactly as today. The win depends on replacing repeated vector cloning/scanning with one sort/build pass, not on weakening validation.
- The change should remain local to enforcing invoke setup. Recording-mode footprint behavior has different cache/write-through semantics and should not be refactored unless equivalence is proven separately.
