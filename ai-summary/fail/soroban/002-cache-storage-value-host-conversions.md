# H002: Cache Host-Side Conversions of Unchanged Contract Storage Values

**Date**: 2026-05-03
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in repeated `get_contract_data` value conversion and host-object construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated reads of an unchanged contract-data value within one host invocation should return the same semantic `Val` content, enforce the same footprint/storage rules, preserve p26 metering unless explicitly protocol-gated, and invalidate any cached representation immediately when the entry is written or deleted. The host should not recursively rebuild the same `ScVal` map/vector into fresh host objects every time `get_contract_data` reads a storage entry that has not changed.

## Mechanism

`Host::get_contract_data` reconstructs the storage key from the guest key, reads the ledger entry from enforcing `Storage`, and converts `ContractDataEntry.val` through `Host::to_valid_host_val` on every successful read (`src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2242`). `to_valid_host_val` delegates to `to_host_val`, which enters the `ScVal to Val` zone (`src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443`) and recursively creates host vectors/maps/objects for object-valued storage (`src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-565`). The enforcing `StorageMap` already owns the ledger entry for the duration of the host invocation (`src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-329,380-389`), so a sidecar cache can remember the converted immutable host-object prototype or a per-entry conversion record until `put`/`del` invalidates it.

The current soroswap diagnostic trace shows this conversion family as first-order apply-path CPU: `ScVal to Val` at **429,988,065 ns / 691,521 calls**, `new map` at **331,023,872 ns / 170,072 calls**, `add host object` at **270,971,092 ns / 935,719 calls**, `storage get` at **215,980,007 ns / 305,065 calls**, and `get_contract_data` / `has_contract_data` dispatch-common wrapper zones totaling another **337,400,715 ns** process-wide. The optimization would cache only unchanged storage-value conversion work, not footprint lookup or storage access itself. On cache hit it can still allocate a fresh top-level object handle if p26 handle-identity compatibility requires it, but avoid recursive `ScVal` validation, sorted-map construction, and repeated conversion of the same ledger value.

## Trigger

Run the current soroswap apply-load benchmark. The router/pair contracts repeatedly call `has_contract_data` and `get_contract_data` for reserves, balances, and protocol state while applying each swap. Built-in helpers also use the `try_get_contract_data` shape (`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14`), where a found value commonly follows a `has` probe with a `get`; after the accepted typed SAC balance-storage fast path, the remaining opportunity is generic Wasm contract storage values and non-balance built-in state, not the already-optimized SAC balance helper.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2242` — `get_contract_data` converts every returned `ContractDataEntry.val` with `to_valid_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` — `to_host_val` starts the hot `ScVal to Val` recursive conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-565` — object-valued `ScVal::Vec` / `ScVal::Map` conversion builds host vectors/maps and adds host objects.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-329,380-389,401-409` — storage reads and writes are the natural cache lookup and invalidation points.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — representative has-then-get helper shape that amplifies repeated reads when a value exists.

## Evidence

The candidate zones are descendants of `applyLedger` in the current trace: `ScVal to Val`, `new map`, `add host object`, `storage get`, `has_contract_data`, and `get_contract_data` are all in the Soroban host invocation path rather than TX-set construction. The code has a clear repeated-work boundary: `StorageMap` stores immutable `Rc<LedgerEntry>` values until a write replaces the map entry, while `get_contract_data` performs a fresh `ScVal` to host-object conversion each time it reads the same `ContractDataEntry.val`. A sidecar cache keyed by storage-map entry/key plus a generation number can be invalidated by `Storage::put`/`del`, preserving correctness for writes while accelerating read-mostly state.

This is distinct from prior failures and successes. It does not re-propose a single-lookup `try_get_contract_data` change, which failed on p26 has/get metering semantics; it leaves storage lookup and has/get behavior intact. It also does not duplicate the accepted typed SAC balance-storage fast path, which targeted a specific built-in `DataKey::Balance` representation; this targets generic object-valued storage reads from Wasm contracts and other host paths that still route through `to_valid_host_val`.

## Anti-Evidence

Object-handle identity and metering are the main risks. If raw Wasm can observe that two reads return the same object handle rather than two distinct equal objects, the cache must allocate a fresh top-level host object on each hit or be protocol-gated to define interning as acceptable. Likewise, p26 resource accounting currently charges conversion and host-object construction on every read; a p26-compatible cache must replay equivalent charges on hit, which reduces the physical savings, while a charge-reducing cache should be next-protocol-only and tested like the accepted metering-coalescing work.

The trace totals include conversions unrelated to storage-value reads, such as event construction and argument/result conversion. A PoC must add a narrow span or counters around `get_contract_data`'s `to_valid_host_val` call and measure cache hit rate by key. If soroswap's remaining generic storage values are mostly read once per host invocation after the accepted SAC balance fast path, the optimization will fall below the Medium threshold and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior Soroban failures cover has/get lookup duplication, storage-key conversion caching, host-object read arenas, and p26 metering coalescing, but not this exact durable storage-value conversion cache
**Failed At**: reviewer

### Trace Summary

The durable `get_contract_data` path does perform a fresh conversion on every successful read: the host reconstructs the `LedgerKey`, reads an `Rc<LedgerEntry>` from enforcing `Storage`, and converts `ContractDataEntry.val` through `to_valid_host_val`. Writes and deletes also funnel through `Storage::put`/`del`, so a cache invalidation point exists. However, the main amplification evidence is over-broad: `has_contract_data` only checks presence and never converts the stored value, `try_get_contract_data`'s has-then-get shape therefore does not duplicate value conversion, and the cited `ScVal to Val` / `new map` / `add host object` zones include many non-storage conversions such as event, argument/result, address, and instance-storage work.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2213-2289` — `has_contract_data` builds a key and calls `Storage::has`; only `get_contract_data` calls `to_valid_host_val` on `ContractDataEntry.val`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` performs `has` followed by `get`, but the first probe does not convert the ledger value.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-389` — storage reads enforce footprint access and return cloned `Rc<LedgerEntry>` handles from `StorageMap`; the stored ledger entry is stable until replacement.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-529` — `put` and `del` replace the storage-map value and are the natural invalidation points for any per-entry cache.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-565,590-638` — `to_valid_host_val` delegates to recursive `ScVal` conversion; maps/vectors allocate new host containers and object-valued leaves call `add_host_object`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,324-335` — building a `HostMap` validates sorted keys and charges metered map work; storage-map lookup work is separate and not removed by value-conversion caching.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-535` — adding host objects allocates object handles, while visits/identity and p26 object-metering constraints remain correctness-sensitive for any cached object reuse.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-167,191-230,280-355` — the accepted typed SAC balance path reads and writes `DataKey::Balance` values directly from `ScVal`, so the largest built-in balance-storage opportunity is already not routed through generic `get_contract_data` value conversion.
- `ai-summary/CURRENT_STATE.md:41-64,71-84` — the current accepted baseline is about 272.9 ms median soroswap apply time, so Medium requires roughly an 8.2 ms/ledger improvement; the diagnostic trace is attribution-only, not the authoritative timing source.

### Why It Failed

The inefficiency exists, but the projected impact does not clear the optimize-soroswap Medium threshold. A value-conversion cache would not remove storage access, footprint checks, storage-key reconstruction, `has_contract_data`, most host-function dispatch wrapper cost, or the already-rejected has/get double-probe semantics. It also cannot count the full `ScVal to Val`, `new map`, and `add host object` totals because those zones are shared by storage, event construction, argument/result conversion, instance-storage setup, address conversion, and other host paths.

Even using the hypothesis's broadest conversion-family numbers, the ceiling is too small after parallel apply geometry and correctness constraints. The combined cited `ScVal to Val` + `new map` + `add host object` time is about 1.03 s of aggregate worker CPU across the diagnostic run; spread over 70 apply windows and 8 Soroban worker clusters, that is roughly 1.8 ms/ledger of wall-time-equivalent upper bound before excluding non-storage conversions, single-read storage values, mandatory p26 charge replay, and fresh-handle allocation requirements. The current soroswap Medium floor is about 8.2 ms/ledger, so the actual removable storage-value-conversion slice is below the objective severity threshold.

### Lesson Learned

Do not promote generic storage-value conversion caching from broad conversion Tracy zones. First isolate the `get_contract_data -> to_valid_host_val` slice and cache-hit rate by durable key; `has_contract_data` and `try_get_contract_data` do not by themselves imply repeated value conversion, and post-SAC-fast-path generic storage reads must be valued against the 3% apply-time floor rather than aggregate CPU totals from unrelated host conversion paths.
