# H001: Add an immediate-key side index for instance-storage `get_contract_data`

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban host instance storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated `HostMap` binary-search/comparison work from hot instance-storage reads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Wasm contracts reading instance storage through `get_contract_data(k, Instance)` and `has_contract_data(k, Instance)` should observe the same map ordering, comparison semantics, budget accounting, missing-key errors, and frame rollback behavior as today. For exact immediate keys such as the Soroswap pool's `U32` instance keys and SAC metadata enum keys, the host should not need to re-run generic `MeteredOrdMap::find` binary search and host comparison for every read when the current frame's instance storage map is immutable between writes.

## Mechanism

`Host::get_contract_data` and `Host::has_contract_data` dispatch `StorageType::Instance` to `with_instance_storage`, then call `s.map.get(&k, self)` (`src/rust/soroban/p26/soroban-env-host/src/host.rs:2235-2248,2255-2287`). That path funnels through `MeteredOrdMap::find`, charging and executing a binary search plus host-level comparison on each read (`src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-239`). A frame-local side index for immediate, non-object `Val` payloads can map exact key payloads to positions and use a budget-equivalent `get_at_known_position` variant, falling back to the existing comparison path for object keys or after mutating instance storage.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect the long `applyLedger` windows in `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. Router/pair Wasm and SAC built-ins repeatedly read instance storage using immediate keys during each swap.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2235-2248` — `has_contract_data(..., StorageType::Instance)` currently performs a generic instance `HostMap` lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2255-2287` — `get_contract_data(..., StorageType::Instance)` currently performs the same generic lookup and copies out the `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-70` — `with_instance_storage` / `with_mut_instance_storage` frame access points where a read-only index can be attached or invalidated.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-239,317-348` — existing binary-search lookup and known-position fast-path pattern to reuse with equivalent charging.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837` — Wasm/SAC frame setup; the index must be per-frame and deterministic.

## Evidence

The candidate path is inside the measured apply subtree. In the largest current soroswap `applyLedger` window, timestamp-filtered descendants include `get_contract_data` at **128.500 ms total** across **14,555 events**, `has_contract_data` at **17.813 ms total** across **2,916 events**, generic `map lookup` at **118.861 ms total** across **90,387 events**, and `map lookup indexed` at **109.614 ms total** across **155,666 events**. These occur under `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`.

The prior generic `HostMap` exact-key side-index idea failed because object-keyed maps require full host comparison semantics. This candidate is narrower: only exact immediate `Val` payloads in contract instance storage use the index, while object keys keep the existing comparator path. Soroswap pool instance storage uses small `U32` keys, and SAC instance metadata keys are generated enum/symbol-shaped values with immediate components, so a substantial fraction of instance reads should be eligible without changing observable map order.

## Anti-Evidence

The broad `get_contract_data` and `map lookup` zones include persistent/temporary storage and non-instance maps, so a PoC must add a narrow counter for `StorageType::Instance` immediate-key hits before claiming the full category. `put_contract_data(..., Instance)` mutates the map through `with_mut_instance_storage`, so the index must either rebuild deterministically after writes or be invalidated for the rest of the frame. Budget accounting must remain equivalent to the legacy `find` path unless the optimization is explicitly protocol-gated.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact prior fail/success record for an instance-storage-only immediate-key index; related but narrower than `ai-summary/fail/transaction-ledger/summary.md` entry `002-hostmap-exact-key-side-index.md`
**Failed At**: reviewer

### Trace Summary

The instance-storage lookup path is real: `get_contract_data` and `has_contract_data` dispatch `StorageType::Instance` through `with_instance_storage`, lazily materialize an `InstanceStorageMap` from the current frame's `ScContractInstance`, and call `MeteredOrdMap<Val, Val, Host>::get`. Native Soroswap pool getters/swaps also read U32 instance keys through `soroswap_pool_instance_storage_get`, while SAC instance reads use the same generic instance storage API. The proposed immediate-key index would be correctness-preserving only if limited to non-object `Val` payloads and invalidated or updated on `with_mut_instance_storage`, but the cluster-normalized removable work is below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2213-2288` — instance `put`, `has`, and `get` use `s.map.insert`/`s.map.get` on `InstanceStorageMap`; reads perform the generic `MeteredOrdMap::find` path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2292-2310` — instance `del_contract_data` mutates the same map, so a side index would need deterministic update/rebuild/invalidation semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-70` — immutable and mutable instance-storage accessors lazily initialize frame-local storage and mark any mutable access as modified.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:30-68` — `InstanceStorageMap` is only a `MeteredOrdMap<Val, Val, Host>` plus `is_modified`; no existing instance-side index is present.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-239,317-348` — `get` performs a charged binary search and access charge; the existing known-position helper can charge equivalent lookup/access cost while skipping comparisons.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-170` — exact equal `Val` payloads return immediately and non-object immediate values compare by tag/wrapper, while object values delegate to host object comparison.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1011,1076-1176` — native Soroswap pool code repeatedly reads U32 instance keys for tokens/reserves before transfers and invariant checks.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/{admin.rs,asset_info.rs,metadata.rs,storage_types.rs}` — SAC instance keys such as `Admin`, `AssetInfo`, and `METADATA_KEY` use `get_contract_data`/`has_contract_data` with `StorageType::Instance`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:242-267,323-456` — enforcing persistent/temporary storage already has side indices for footprint/storage maps, so broad `storage get` and `map lookup indexed` totals are not available to this instance-storage proposal.

### Why It Failed

The inefficiency exists, but it does not meet the objective's Medium severity floor. The hypothesis's own largest-window numbers put all `get_contract_data` plus `has_contract_data` at about 146.3 ms aggregate worker time, before filtering to `StorageType::Instance`, immediate-key hits, and the subset of lookup time that a side index can remove. With `T=8` / `NUM_CLUSTERS=8`, the absolute upper bound is roughly 18 ms of critical-path time, under 0.5% of the cited 4.48 s `applyLedger` window and far below the required 3-10% apply-time reduction.

The remaining realistic opportunity is smaller. Instance maps are tiny in the relevant paths (for example, Soroswap pool U32 keys and SAC metadata/admin keys), `Compare<Val>` already has an exact-payload fast path for equal immediates, and object-keyed entries still require the legacy host comparison path. Existing side-index work already covers enforcing ledger storage maps, so this proposal only applies to frame-local instance `HostMap` lookups and cannot claim the broader `map lookup`/`storage get` totals. Under the optimize-soroswap criteria, this is a Low or sub-1% local optimization and must be rejected rather than promoted to PoC.

### Lesson Learned

Immediate-key instance-storage lookup is a valid micro-optimization shape, but HostMap lookup hypotheses must be sized from narrow instance-only counters and normalized by Soroban cluster parallelism. Broad `get_contract_data` or `map lookup` totals overstate the apply-time impact, especially after persistent storage-map lookup indexing is already in the current tree.
