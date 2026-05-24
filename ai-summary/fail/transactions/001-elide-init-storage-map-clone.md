# H001: Elide Full Initial StorageMap Clone During Soroban Invoke

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction in Soroban invoke setup/diff
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For successful protocol-gated Soroswap invokes, apply should produce the same host result, modified ledger entries, rent-change inputs, event bytes, CPU/memory consumption, and C++ resource-limit checks as the current path. The initial ledger-entry snapshot used by `get_ledger_changes` should still reflect the exact pre-invocation entries and TTLs, but it should not require recursively cloning every entry in the enforcing storage map before the host call.

## Mechanism

`invoke_host_function` builds a `StorageMap` from the C++ footprint entries and then immediately does `let init_storage_map = storage_map.metered_clone(budget)?` before moving the original into `Storage::with_enforcing_footprint_and_map`. For soroswap this clone runs once per transaction over the same small but object-heavy footprint, including read-only contract instances/code and read-write pool/SAC entries that already have positional metadata. A next-protocol implementation could preserve an immutable initial snapshot as shared `Rc`/position metadata, or move `Storage` to a copy-on-write map that retains the original map for diffing, avoiding the full metered recursive clone while keeping deterministic output and explicit protocol-gated metering changes.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load Tracy scenario with protocol 27 enabled. Every successful `InvokeHostFunction` transaction enters `soroban-env-host/src/e2e_invoke.rs:488`, builds storage from XDR entries, clones the initial storage map at line 514, invokes the host, and diffs against that clone at lines 565-579.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-517` — builds `storage_map`, clones it into `init_storage_map`, and constructs enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:565-579` — wraps the cloned map in `StorageMapSnapshotSource` for ledger-change diffing.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1167-1181` — snapshot source only needs lookup access to the pre-invocation map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:26-28,323-352,418-489` — `StorageMap` is an immutable ordered map; enforcing `get`/`put` already replace maps on write, which is compatible with retaining the original map as a read-only snapshot.

## Evidence

The current soroswap apply-window Tracy exports show `invoke_host_function` at `soroban-env-host/src/e2e_invoke.rs:488` with 828,296,243 ns self-time and 10,781,064,987 ns total time, while its measured child `Host::invoke_function` at line 550 totals 8,276,651,656 ns. The roughly 2.50 s aggregate worker envelope around the host call is an upper bound for setup/finish work such as storage-map construction, the initial clone, auth/host-function decode, ledger-change extraction, and output encoding; divided by T=8 this is about 313 ms, or about 6% of the 5,092 ms apply-window total in the timestamp-filtered exports. The code contains a concrete full-map clone at line 514 that is not needed for mutation semantics if the initial map can be retained immutably.

## Anti-Evidence

The clone's exact share is not isolated by a dedicated Tracy zone, so a PoC should add temporary sub-zones or benchmark variants before assuming the entire invoke envelope is removable. The clone is metered today; removing or reducing it would change protocol-visible CPU/memory budget consumption and therefore must remain next-protocol gated or explicitly reproduce the old charges. The snapshot also feeds rent-size and TTL old-state calculations, so any COW/metadata representation must preserve positional old-entry metadata exactly.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transactions fail/success records; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The soroswap apply path runs `LedgerManagerImpl::applyThread`, calls `TransactionFrame::parallelApply`, dispatches the single Soroban operation through `OperationFrame::parallelApply`, and reaches `InvokeHostFunctionOpFrame::doParallelApply`. The helper serializes host inputs and calls `rust_bridge::invoke_host_function`, which dispatches to p26 `e2e_invoke::invoke_host_function`. That Rust path builds the enforcing `StorageMap`, performs `storage_map.metered_clone(budget)?`, moves the original into `Storage`, invokes the host, then uses the cloned map as the old-state source for `get_ledger_changes`.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2488-2511` — each cluster worker applies Soroban transactions and commits successful parallel effects.
- `src/transactions/TransactionFrame.cpp:2385-2430` — parallel apply rejects failed txs, asserts a single Soroban operation, and delegates to the operation frame.
- `src/transactions/OperationFrame.cpp:175-188` — `parallelApply` dispatches directly to `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ helper builds bridge buffers and calls `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017,1358-1377` — invoke-host apply sequence adds the footprint, invokes Rust host execution, records storage changes, collects events, consumes refundable resources, and finalizes success.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-579` — the Rust host builds `storage_map`, clones it into `init_storage_map`, invokes the host, and passes the initial clone into `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-357` — `get_ledger_changes` walks the final storage map, uses `init_storage_map.get_at_known_position(pos)` when lengths match, and only falls back to `StorageMapSnapshotSource::get` otherwise.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1167-1181` — `StorageMapSnapshotSource` only performs lookup and `Rc::clone` of old entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:26-28,245-267,323-352,418-489,600-627` — `StorageMap` stores `Rc<LedgerKey>` and `Rc<LedgerEntry>` values, builds enforcing side indices, and updates entries by replacing the ordered map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:251-256,355-356,397-407,423-431` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:31-42,427-435` — `MeteredOrdMap::metered_clone` clones the backing `Vec`, but `Rc<T>` cloning is explicitly just a refcount bump; ledger entries, contract code, and instance `ScVal` substructure are not recursively cloned.

### Why It Failed

The claimed inefficiency does not exist in the stated form. `StorageMap` is `MeteredOrdMap<Rc<LedgerKey>, Option<(Rc<LedgerEntry>, Option<u32>)>, Budget>`, and `MeteredClone for Rc<T>` is shallow: cloning the initial map allocates/copies the vector of map pairs and bumps `Rc` refcounts, but it does not recursively clone object-heavy `LedgerEntry`, contract code, contract instance storage, or `ScVal` contents. The broad 2.50 s aggregate `invoke_host_function` minus `Host::invoke_function` envelope includes storage-map construction from XDR, side-index construction, host-function/auth/source decoding, ledger-change extraction, rent-size work, result/event encoding, and bridge output preparation; it cannot be attributed to this one shallow vector clone. Even if a COW map or retained backing vector removed the shallow clone, the saving is bounded by one small-footprint `Vec` clone per invoke and falls well below the objective's Medium threshold after T=8 worker-time normalization.

### Lesson Learned

Before promoting storage snapshot hypotheses, verify whether cloned values are owned XDR payloads or `Rc` handles. In the enforcing Soroban apply path, the initial snapshot is a stable shallow map of shared ledger-entry handles, and `get_ledger_changes` already uses positional access for the common same-length map case; remaining clone-elision is a micro-optimization, not a Medium soroswap apply-time opportunity.
