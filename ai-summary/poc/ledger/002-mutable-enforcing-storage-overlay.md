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

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — distinct from prior `001-unify-enforcing-storage-footprint-lookups`, which removed a duplicate binary search but still left storage updates represented as immutable map replacement/rebuilds; no ledger success record confirms this overlay mechanism.

### Trace Summary

The in-scope path is `invoke_host_function` constructing enforcing `Storage`, then `Host::invoke_function` executing guest storage operations through `put_contract_data`, `del_contract_data`, and TTL-extension host functions. Durable writes and deletes call `Storage::put_opt_helper`, and TTL bumps call `Storage::apply_ttl_extension`; both assign the result of `StorageMap::insert`. `MeteredOrdMap::insert` searches the sorted vector and then rebuilds a complete new vector-backed map through `from_exact_iter`, while final output is consumed later by `Host::try_finish` and `get_ledger_changes`, which iterates the final `storage.map` in canonical order.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-507` — host execution happens inside `Host::invoke_function`; after `host.try_finish()`, `get_ledger_changes` consumes the finalized storage map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates `storage.map` in sorted order, encodes keys/new values, compares to the initial snapshot, and is the natural point to materialize an overlay.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:179-183` — `Storage` currently owns one `StorageMap`, so every accepted update mutates state by replacing this entire map value.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — `put_opt_helper` enforces read-write footprint access, then calls `self.map.insert(Rc::clone(key), val, host.budget_ref())` for writes and deletes.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:380-409` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — guest durable `put_contract_data` and delete paths funnel into `Storage::put` / `Storage::del` during contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515,532-642` — TTL extension computes the new live-until value and, when it extends, updates the same storage map via `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2292-2416` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-325` — contract-data and instance/code TTL host functions reach `extend_ttl` / `extend_ttl_v2`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,196-224` — `insert` calls `find`, clones prefix/suffix entries, collects a new `Vec`, charges deep clone, and rechecks sort order through `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-224,404-562` — rollback currently snapshots `storage.map` at frame push and restores it on frame error, so an overlay needs checkpoint/journal rollback semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:747-757` — `try_finish` returns the finalized `Storage` to the invoke wrapper, confirming overlay materialization can remain transaction-local.

### Findings

The inefficiency exists. In enforcing mode the footprint key set is fixed for the invocation, writes/deletes replace a key's value with `Some(...)` or `None`, and TTL extension only changes the live-until metadata for an existing entry. Despite that fixed-key behavior, each update uses `MeteredOrdMap::insert`, which allocates and clones a full replacement vector and revalidates ordering. This is more work than logically required for a per-key value replacement.

The path is hot enough to justify a Medium PoC. The current objective baseline already records a `new map` zone with roughly 225 ms self-time and 127k+ in-apply calls in the diagnostic soroswap trace, while durable `storage put` alone has 25k+ calls and TTL extension contributes additional update traffic outside the `storage put` span. Not every `new map` event is removable by this change, but runtime durable-storage updates are in `Host::invoke_function`, inside `closeLedger`, and the aggregate zone is large enough that avoiding the rebuild portion for writes/TTL updates can plausibly clear the 3% floor if the overlay does not add read-path overhead.

The proposed fix is conceptually correct if scoped narrowly to enforcing storage. Reads must still observe the latest write/delete in the current frame, deletes must remain as `None` values so the final key set and ordering are preserved, and final ledger changes must be emitted in the original sorted storage-map order. Rollback is the main implementation constraint: `with_frame` currently restores an earlier `StorageMap`, so a mutable overlay needs checkpoints that can truncate or undo journaled changes exactly when a frame exits with an error. Budget accounting must reflect the actual implementation cost and any test changes must be limited to exact lower budget/observation values caused by removed map rebuild work.

This is novel relative to the failed `001-unify-enforcing-storage-footprint-lookups` investigation. That prior PoC reused the enforcing footprint ordinal to avoid a duplicate lookup and ultimately regressed in benchmark, but it did not replace immutable value updates with a journal/overlay that avoids `from_exact_iter` rebuilds. A PoC for this hypothesis should not simply resurrect H001; it must isolate and remove the `new map` rebuild cost from runtime durable writes/TTL updates and measure that specific effect.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs`, and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`.
- **Change description**: Add an enforcing-only storage update representation that keeps the initial sorted `StorageMap` immutable for canonical iteration and records replacements/deletes/TTL live-until updates by stable ordinal or deterministic sorted key. `Storage::put_opt_helper` and `apply_ttl_extension` should update this overlay instead of calling `MeteredOrdMap::insert`; `try_get_full_helper` must read overlay state first without slowing the common read-only path, and `get_ledger_changes` or `try_finish` should materialize/iterate final values in canonical map order.
- **Correctness check**: Existing Soroban host storage, invoke-host-function, TTL extension, rollback/`try_call`, authorization, and budget/observation tests cover the relevant behavior. Pay special attention to frame rollback, nested calls, deletes represented as `None`, fixed footprint enforcement, and p26 observation/budget baselines.
- **Benchmark focus**: Add temporary counters or Tracy zones that separate `MeteredOrdMap::from_exact_iter` calls caused by enforcing durable `Storage` writes/TTL updates from footprint construction, object maps, instance storage, and recording-mode paths. The PoC should demonstrate a large drop in runtime durable-storage `new map` calls, no increase in read-path lookup time, and a reproducible 3-10% soroswap apply-time improvement across the required repeated non-Tracy matrix runs.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-01
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:387-408` — added `replace_at_known_position`, an indexed in-place value replacement for fixed-key sorted maps. It preserves the legacy logical budget charges while avoiding allocation and full vector reconstruction.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:442-452` — changed enforcing-mode `put`/`del` storage updates to use the indexed in-place replacement when the precomputed storage index is valid, falling back to immutable `insert` otherwise.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:605-617` — changed TTL extension updates to use the same indexed in-place replacement path for existing footprint keys.

### Demonstration

The optimization keeps enforcing storage key order fixed and replaces only the value at the precomputed storage-map ordinal for writes, deletes, and TTL extensions. This removes the hot `MeteredOrdMap::insert` vector rebuild and `from_exact_iter` allocation path for fixed-footprint enforcing storage updates while preserving canonical iteration, rollback behavior through existing storage-map snapshots, and the prior logical budget profile.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make check`. Final run passed: `test/selftest-nopg` and `test/check-nondet` passed; p26 `soroban-env-host` reported `750 passed; 0 failed; 2 ignored` plus all listed integration/doc tests passed.
