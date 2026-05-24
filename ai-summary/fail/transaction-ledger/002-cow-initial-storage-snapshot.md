# H002: Replace per-invocation initial `StorageMap` clone with a COW snapshot for ledger-change extraction

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban host ledger-change extraction
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing duplicated setup/finish work around the Rust host storage snapshot
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, `get_ledger_changes` should compare final storage against the exact initial entries and TTL metadata that were supplied to the host, compute the same rent sizes and TTL changes, emit the same modified ledger entries, and preserve protocol-visible resource accounting. It should not need to clone the entire initial `StorageMap` into a second `Vec` before execution when enforcing storage mutations already replace the map structurally rather than mutating entries in place.

## Mechanism

`invoke_host_function` bulk-builds the enforcing storage map, then immediately performs `let init_storage_map = storage_map.metered_clone(budget)?` before moving `storage_map` into `Storage::with_enforcing_footprint_and_map` (`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-516`). On success, `get_ledger_changes` uses that clone for position-based old-entry lookup (`e2e_invoke.rs:248-356`). A protocol-gated COW representation can let `Storage` and `StorageMapSnapshotSource` share the initial map allocation by `Rc`, with writes replacing only the final map; `get_ledger_changes` would still use the initial map by position, but would avoid cloning every `(Rc<LedgerKey>, Option<EntryWithLiveUntil>)` pair and recharging clone scaffolding for every invocation.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each successful Soroban swap enters `e2e_invoke::invoke_host_function`, builds `storage_map`, clones it as `init_storage_map`, executes the host, then calls `get_ledger_changes` to produce C++ bridge output.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — builds `storage_map`, clones it into `init_storage_map`, and constructs enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:565-580` — creates `StorageMapSnapshotSource` over the cloned map and calls `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-356` — scans final storage and uses `init_storage_map.get_at_known_position` for old entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:419-529,600-687` — storage writes and TTL updates replace `self.map`, making a shared immutable initial map feasible if writes detach before mutation.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:427-435` — `MeteredClone` charges/clones the underlying vector substructure today.

## Evidence

The current long-window trace shows a large Rust setup/finish envelope around actual Wasm execution. In the largest `applyLedger` window, `invoke_host_function` totals **1,993.501 ms** across **1,451** events, while the enclosed `Host::invoke_function` totals **1,529.233 ms**; the difference is about **464 ms aggregate worker time**, or roughly **58 ms** after `NUM_CLUSTERS=8` normalization in that window. The same window also shows `charge` at **324.386 ms**, `new map` at **86.506 ms**, `read xdr with budget` at **37.769 ms**, and `write xdr` at **33.327 ms**, confirming nontrivial setup/finish work remains after the accepted bulk-build and XDR-size metadata wins.

This target is different from dirty-output filtering: it preserves the existing full `get_ledger_changes` scan and old-entry semantics, but removes the duplicated initial-map ownership needed only because `Storage` currently consumes the map by value. Since enforcing storage updates already assign newly-built maps for `put`, `del`, and TTL extension, sharing the initial map until first write should not change final ledger order or mutation ordering.

## Anti-Evidence

Prior old-entry-output investigations found that metered serialization in `get_ledger_changes` is protocol-visible and cannot be skipped casually. This hypothesis must therefore preserve or protocol-gate the `MeteredClone` budget effects; it is a wall-time/COW allocation hypothesis, not permission to remove ValSer/ValDeser accounting. The initial `StorageMap` clone is shallow in ledger-entry payloads because keys and entries are `Rc`, so a PoC must isolate clone+position-snapshot cost specifically before claiming the entire setup/finish envelope. If the clone is only a small fraction of that envelope, this should be rejected below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — close to `fail/transaction-ledger` summary entry `001-carry-initial-storage-metadata.md`, but this version narrows the mechanism to preserving full ledger-change extraction while avoiding only the initial `StorageMap` clone
**Failed At**: reviewer

### Trace Summary

The Soroban apply path enters `InvokeHostFunctionOpFrame::doApply`, crosses the C++/Rust bridge, constructs a per-invocation `Budget`, and calls `e2e_invoke::invoke_host_function`. That function does build a `StorageMap`, takes `storage_map.metered_clone(budget)?` as the initial snapshot, moves the original map into enforcing `Storage`, executes the host, and later passes the cloned map to `get_ledger_changes` for position-based old-entry lookup. The proposed COW snapshot is mechanically plausible because enforcing writes replace `self.map` with a newly built `MeteredOrdMap`, so an initial shared map would remain immutable; however, the clone is shallow over `Rc<LedgerKey>` and `Rc<LedgerEntry>` payloads and is only one vector allocation/shallow copy per invocation. Preserving protocol-visible metering would keep the budget-charge work, while protocol-gating it would change resource accounting for a tiny component of the setup envelope.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-585` — builds auth/source/resource buffers and calls `rust_bridge::invoke_host_function` in the per-Soroban-operation apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1000` — `doApply` performs `addFootprint`, host invocation, then `recordStorageChanges`; the Rust host invocation is inside `closeLedger` apply.
- `src/rust/src/soroban_proto_any.rs:391-452` — constructs the `Budget`, then dispatches to the protocol-specific `e2e_invoke::invoke_host_function` while measuring invocation time.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — builds the enforcing storage map, clones it into `init_storage_map`, constructs `Storage`, and precomputes initial metadata by position.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:565-579` — wraps `init_storage_map` in `StorageMapSnapshotSource` and passes it into `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — scans final storage, uses `init_storage_map.get_at_known_position` when lengths match, and still performs metered XDR serialization for old/new rent sizing.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — enforcing `Storage` owns the passed map and precomputes position indices over fixed key sets.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457,600-687` — `put`, `del`, and TTL extension replace `self.map`; they do not mutate ledger entries in place.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:251-255,355-407` — `metered_clone` charges shallow copy plus substructure; `Rc<T>` clone is shallow/O(1), and `Vec<C>` cloning charges one heap allocation plus shallow element copies.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:31-42,427-435` — `MeteredOrdMap::clone` clones the underlying vector and `MeteredClone` delegates substructure charging to that vector.

### Why It Failed

The specific inefficiency exists, but it is too small for the optimize-soroswap objective. The clone is not a deep ledger-entry or key copy: `StorageMap` is `MeteredOrdMap<Rc<LedgerKey>, Option<(Rc<LedgerEntry>, Option<u32>)>, Budget>`, so cloning copies the vector of pairs and bumps `Rc` counts. If exact budget semantics are preserved, the proposal can only remove the actual vector allocation/shallow copy and reference-count bumps, not the visible `MeteredClone` charges. If the charges are protocol-gated away, the changed resource accounting is still limited to one small shallow map clone per invocation. Prior measurements already rejected larger storage-map update work after cluster normalization; this clone is a strict subset of that sort of vector-map overhead and cannot credibly reach the required 3% apply-time reduction. Therefore it is below the objective severity threshold (Low/Informational not accepted).

### Lesson Learned

The Rust setup/finish envelope is too broad to justify narrow storage-map ownership changes. For Soroban host storage hypotheses, isolate the exact metered operation and distinguish shallow `Rc`/vector clones from deep XDR traversal or map-rebuild work; only the latter have a plausible path to Medium severity.
