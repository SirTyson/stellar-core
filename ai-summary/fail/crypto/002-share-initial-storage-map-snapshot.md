# H002: Share the initial Soroban storage map snapshot instead of deep-cloning it

**Date**: 2026-04-29
**Subsystem**: crypto, rust, soroban-env
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by removing repeated deep clones and map rebuild work before host execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Enforcing-mode Soroban invocation needs both a mutable execution storage map and an immutable initial snapshot for post-execution ledger-change/rent computation. Creating that initial snapshot should not require deep-cloning every decoded ledger key and entry when the initial map is immutable until it is handed to `Storage`; the snapshot and execution storage should share the same initial backing data and diverge only for keys actually changed during execution.

## Mechanism

`invoke_host_function` decodes the footprint entries into `storage_map`, then immediately performs `let init_storage_map = storage_map.metered_clone(budget)?` before moving `storage_map` into `Storage::with_enforcing_footprint_and_map`. That clone duplicates the already-decoded `Rc<LedgerKey>` and `Rc<LedgerEntry>` map solely so `StorageMapSnapshotSource` can compare old values after execution. Reworking `Storage`/`StorageMapSnapshotSource` to share an immutable initial map backing (for example an `Rc`/`Arc` snapshot plus an overlay for writes) would preserve deterministic snapshot comparisons while avoiding a full per-invocation clone of the soroswap footprint.

## Trigger

Run the current soroswap apply-load Tracy benchmark (`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`) and inspect storage-map construction under `applyLedger`. `invoke_host_function` has 3335 in-apply calls and 355,077,158 ns self-time; storage-map construction and lookup zones in the same path include `new map` at `metered_map.rs:150` with 228,409,843 ns self-time, `map lookup` at `metered_map.rs:95` with 732,363,179 ns self-time, and `read xdr with budget` with 82,432,306 ns self-time. The deep clone is not separately zoned, but it is structurally on every successful invocation immediately after map construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-451` — builds `storage_map`, clones it to `init_storage_map`, then moves the original into enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-507` — wraps `init_storage_map` in `StorageMapSnapshotSource` for ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — snapshot source reads old entries from the cloned map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:26-27` — `StorageMap` stores `Rc<LedgerKey>` to optional `(Rc<LedgerEntry>, live_until)` values.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:357-366` — `MeteredOrdMap` clone charges and walks substructure for the whole map.

## Evidence

The clone is avoidable because the initial storage map is already composed of reference-counted keys and entries and is used read-only by `StorageMapSnapshotSource`. Soroswap invokes the host thousands of times per trace and each invocation has a non-trivial footprint, so duplicating the whole initial map before any contract code runs adds work proportional to total footprint size, not to actual writes. Sharing the initial backing map with an execution overlay should preserve deterministic ordering (`MeteredOrdMap` remains sorted), keep old-value lookup semantics unchanged, and reduce apply time by removing repeated map clone/allocation work in the hot host setup path.

## Anti-Evidence

`Storage` currently treats `StorageMap` as a value updated by functional `insert` calls, so introducing shared backing or an overlay is a larger refactor than a local clone removal. The existing clone may be mostly shallow because entries are already `Rc`, and the physical cost may be hidden inside broader budget/clone zones rather than large enough by itself. A PoC must preserve metered clone/budget behavior, rollback behavior around failed nested calls, and exact old-vs-new comparison semantics in `get_ledger_changes`; if only a small fraction of the `new map` and `invoke_host_function` self-time comes from this clone, the measured win may be below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The C++ Soroban op path calls `rust_bridge::invoke_host_function`, dispatches through the protocol-specific Rust host, and reaches p26 `e2e_invoke::invoke_host_function`. That function decodes the initial storage map, performs `storage_map.metered_clone(budget)?`, moves the original map into enforcing `Storage`, then later uses the clone as `StorageMapSnapshotSource` for `get_ledger_changes`. The snapshot clone is in the hot apply path, but the actual clone is shallow over a vector of `Rc`-backed entries, not a deep clone of `LedgerKey` or `LedgerEntry` XDR substructure.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply path constructs bridge buffers and calls `rust_bridge::invoke_host_function` for each host invocation.
- `src/rust/src/soroban_invoke.rs:7-38` — top-level Rust bridge dispatch selects the protocol host module and forwards buffers to the versioned host.
- `src/rust/src/soroban_proto_any.rs:310-452` — protocol wrapper catches panics, creates the budget, and calls `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-507` — builds `storage_map`, clones it as `init_storage_map`, runs the host, and uses the clone for ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates final `storage.map`, queries the initial snapshot for old values, and XDR-encodes old/new entries for rent and ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `StorageMapSnapshotSource::get` performs a map lookup and clones only the returned `Rc<LedgerEntry>` plus the live-until value.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27,178-183,332-357` — `StorageMap` is `MeteredOrdMap<Rc<LedgerKey>, Option<(Rc<LedgerEntry>, Option<u32>)>>`; writes replace `self.map` through functional `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:251-255,355-360,397-407,423-431` — `metered_clone` charges then calls `Clone`; `Rc` clone is explicitly treated as an O(1) refcount bump, while `Vec` clone allocates/copies elements and only recurses if element types are non-shallow.
- `src/rust/soroban/p26/soroban-env-host/src/host/declared_size.rs:271-329` — `Rc` is charged as a 16-byte shallow clone, `Vec` as a 24-byte header plus element allocation/copy, and `Option` adds only shallow declared-size overhead when its inner type is shallow.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:31-42,196-225,357-366` — `MeteredOrdMap::clone` clones the backing `Vec`; `insert` is the path that rebuilds whole maps and creates the cited `new map` zones, not the initial snapshot clone.

### Why It Failed

The optimization claim overstates the removable work. `storage_map.metered_clone` does allocate a second vector and copy all map pairs, but the map values are `Rc<LedgerKey>` and `Option<(Rc<LedgerEntry>, Option<u32>)>`, and `MeteredClone for Rc<T>` is explicitly shallow. The clone therefore does not deep-clone decoded ledger keys, ledger entries, or their XDR substructure.

The cited `new map` and `map lookup` self-times are also not eliminated by sharing the initial snapshot. `new map` is produced by `MeteredOrdMap::from_exact_iter`, especially through functional `insert` during map construction and storage writes; `map lookup` remains necessary for footprint checks, storage access, TTL lookup, and snapshot comparison. A snapshot-sharing change scoped to `init_storage_map` can recover only one shallow vector allocation/copy per successful invocation plus non-atomic `Rc` refcount bumps. With 3335 in-apply invocations, it would need to save roughly 173ms on the cited trace to meet the objective's 3% Medium floor, meaning the shallow clone would have to account for nearly half of the entire 355ms unzoned `invoke_host_function` self-time. The traced code does not support that: most nearby work is XDR decode/encode, host setup, budget charging, map lookup, and functional map rebuilds that this change leaves intact.

The broader overlay idea may be a separate storage-representation hypothesis if it targets `MeteredOrdMap::insert` rebuilds during writes and proves that those rebuilds dominate the `new map` zone. As written, however, this hypothesis targets an uninstrumented shallow snapshot clone and cannot plausibly reach Medium severity under the optimize-soroswap review threshold.

### Lesson Learned

For Soroban storage-map hypotheses, distinguish shallow `Rc`/`Vec` snapshot cloning from the much more expensive functional map rebuilds caused by `MeteredOrdMap::insert`. A viable Medium-tier storage refactor needs isolated measurements for the rebuild/write path, not attribution of all `new map` or `invoke_host_function` self-time to the initial snapshot clone.
