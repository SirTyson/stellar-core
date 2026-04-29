# H002: Mutate internal Soroban storage maps in place while replaying existing charges

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing allocator churn and full-Vec cloning from hot internal storage-map updates without changing deterministic order or budget accounting
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Internal Soroban storage maps should remain sorted, deterministic, rollback-safe, and metered exactly as they are today, but successful writes should not physically rebuild an entire `Vec<(K, V)>` when the caller has exclusive mutable access to the map. The current immutable-style `insert` API is appropriate for host-visible map values, but internal `StorageMap` and `InstanceStorageMap` updates should be able to mutate their backing `Vec` in place while replaying the same access, clone, scan, and comparison charges currently paid by `MeteredOrdMap::insert`.

## Mechanism

`MeteredOrdMap::insert` in `host/metered_map.rs:196-224` builds a chained iterator over cloned prefix/new/suffix entries, calls `from_exact_iter`, allocates a fresh `Vec`, charges/clones the whole map, and then `from_map` scans every adjacent pair to prove sortedness. Internal storage call sites such as `Storage::put_opt_helper`, `Storage::apply_ttl_extension`, and instance `put_contract_data` assign the returned map back into a uniquely borrowed `Storage`/`InstanceStorageMap`, so the physical rebuild is unnecessary for these internal maps. A specialized `insert_in_place_preserving_metering` for internal maps could run the same binary-search and metering/validation charges, then use `Vec::insert`/replacement on the existing sorted vector, preserving deterministic ordering and observable budget totals while avoiding repeated full-map allocation and clone work.

## Trigger

Run the current soroswap apply-load scenario (`TX=2000, T=8`) and inspect the soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`. Soroswap performs persistent balance writes, TTL updates, and instance-storage mutations during SAC-heavy swaps; these funnel through `StorageMap` / `InstanceStorageMap` inserts and repeatedly hit `new map` in `MeteredOrdMap::from_exact_iter`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `from_exact_iter` allocates a fresh map and delegates to full validation.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — `insert` clones prefix/suffix into a new map for every update.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — persistent/temporary storage writes assign `self.map = self.map.insert(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-515` — TTL extension writes assign `self.map = self.map.insert(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2204` — instance storage writes assign `s.map = s.map.insert(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205` and `:556-562` — frame rollback snapshots require preserving old storage state on error, so any in-place mutation must pair with rollback-safe before-value tracking or keep the existing snapshot semantics until a full overlay design is implemented.

## Evidence

- Tracy scope check: the cited map-update zones occur under `applyLedger` through Soroban host invocation and SAC built-in storage calls, not under TX-set construction. The same trace reports `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484`.
- The current soroswap trace reports `new map` at `soroban-env-host/src/host/metered_map.rs:150` with 228.410 ms self-time over 110,705 calls, plus `new map` at `metered_map.rs:281` with 22.259 ms self-time over 16,705 calls. `storage put` at `storage.rs:393` has 21.765 ms self-time over 16,702 calls, and `put_contract_data` direct-env calls have 43.629 ms self-time over 6,686 calls.
- Source structure shows the physical O(n) rebuild on every insert: after a binary search, replacement and insertion both clone `self.map.iter().take(...)`, chain the new element, clone `skip(...)`, collect into a new `Vec`, charge deep clone, and scan adjacent pairs.
- Internal storage maps are not contract-visible host map objects. Their observable behavior is sorted key order, storage contents, rollback behavior, and budget usage; all can be preserved while changing the physical mutation strategy.
- The accepted storage-map lookup fast path already established that validated internal `LedgerKey` map paths can safely use specialized implementations when charges and comparison order are preserved. This hypothesis applies the same principle to writes rather than lookups.

## Anti-Evidence

- The existing immutable-style insert makes rollback simple because `push_context` clones the pre-frame `StorageMap`. In-place mutation without a rollback overlay would corrupt rollback behavior on failed frames. A viable implementation either keeps the existing snapshot initially, or redesigns rollback around per-frame before-values before enabling in-place mutation for storage maps.
- `MeteredOrdMap` is also used for host-visible `MapObject` values where immutable functional semantics are intentional. The optimization should be limited to internal `StorageMap`, `FootprintMap` construction paths, and `InstanceStorageMap` where exclusive mutable access is already required.
- A naive in-place insert that skips `from_map`'s scan/comparison charges or clone charges changes protocol-visible budget totals. The PoC must replay those charges exactly, even if it avoids the physical allocation and clone.
- Some `new map` time comes from public host maps/vectors or tests; the cited 228 ms is an upper bound. The Medium claim depends on the internal storage-map subset being a large enough fraction of those 110,705 calls, which should be verified with focused instrumentation or before/after non-Tracy apply-load runs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The physical inefficiency exists: `MeteredOrdMap::insert` rebuilds a fresh vector through `from_exact_iter`, and `Storage::put_opt_helper`, `Storage::apply_ttl_extension`, and instance `put_contract_data` assign that rebuilt map back into exclusively borrowed internal storage. The path is in scope because Soroban apply reaches these functions through `LedgerManagerImpl::applyLedger` / parallel Soroban stages, `InvokeHostFunctionOpFrame::invokeHostFunction`, the Rust bridge, and `e2e_invoke`. Rollback can remain correct if the existing `push_context` snapshot is kept, since errors still restore the pre-frame `StorageMap`. However, the removable production work is too small for this objective: exact metering still requires the same access, binary-search, clone-charge, scan, and adjacent-comparison charges, and the cited `new map` Tracy time is an aggregate upper bound over all map rebuilds, not just the targeted storage-write subset.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1488,2623-2670,2673-3030` — `applyLedger` enters the Soroban parallel apply stages that execute the benchmark's Soroban transactions during closeLedger.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — each Soroban transaction crosses into `rust_bridge::invoke_host_function` with serialized resources, ledger entries, TTL entries, and the shared module cache.
- `src/rust/src/soroban_proto_any.rs:310-354,391-448` — Rust dispatch builds the budget and calls protocol-specific `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:990-1052` — enforcing-mode storage and TTL maps are also built with repeated `MeteredOrdMap::insert`, so the `new map` trace count is broader than the storage-write call sites named in the hypothesis.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,196-224` — `insert` charges access, binary-searches, clones prefix/suffix into a chained iterator, collects a new `Vec`, charges deep clone, and calls `from_map`, which scans and compares every adjacent key.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:397-407` — the protocol-visible clone charge for `Vec` is a set of budget charges and, for shallow entries such as `Rc` pairs or `(Val, Val)`, not equivalent to the physical prefix/suffix clone that the optimization would remove.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357,500-515` — durable storage writes and TTL updates use `self.map = self.map.insert(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2204` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — instance storage and ledger contract-data writes funnel through the same map insertion pattern.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-205,522-562,1229-1278` — context push snapshots durable storage for rollback, successful frame pop persists modified instance storage, and error pop restores the snapshot.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:44-53,88-97` — the prior broader validated-key lookup optimization measured only Low severity, and this write-only allocation optimization has a smaller safely removable portion.

### Why It Failed

This is a real inefficiency but not a Medium-impact one. A correct in-place implementation cannot skip `insert`'s protocol-visible metering: it must still run the access charge, binary-search charge and comparisons, replay the whole-map clone charges, and preserve the full sortedness scan / adjacent-comparison behavior that `from_map` currently performs. That leaves only physical allocation, vector rebuilding, and shallow element cloning as removable work.

The saved work is also much smaller than the aggregate `new map` zone suggests. Exporting the current diagnostic soroswap trace shows `new map` at `metered_map.rs:150` with 228.410 ms self-time over 110,705 calls and deletion-related `new map` at `metered_map.rs:281` with 22.259 ms self-time over 16,705 calls. The targeted storage-write evidence accounts for 16,702 `storage put` calls and 6,686 direct-env `put_contract_data` calls, while the 110,705 `from_exact_iter` calls include broader e2e storage/TTL construction, footprint/restored-key maps, and other map users. Even removing all physical rebuild work from every targeted internal write would be a fraction of an already upper-bound Tracy self-time, and after keeping mandatory metering and validation it falls below the 3% objective floor.

### Lesson Learned

For Soroban map-write optimizations, `new map` self-time is only an upper bound. Exact budget compatibility preserves much of the O(n) scan/comparison and budget-charge work, and the storage-write subset must be separated from e2e construction, deletion, footprint, TTL, restored-key, and host-visible map rebuilds before projecting a Medium apply-time improvement.
