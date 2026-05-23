# H002: Cache full `get_contract_data` results within a host invocation

**Date**: 2026-05-23
**Subsystem**: crypto, rust, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in host storage read, ScVal conversion, and object creation path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated `get_contract_data(k, durability)` calls for the same key within one
host invocation should return the same logical `Val` and charge the same
observable budget as today, but they should not repeatedly probe the host storage
map, clone the `Rc<LedgerEntry>` pair, convert the stored `ScVal` back into host
objects, and allocate fresh object-table entries when the value has not changed.
Writes or deletes to the key should invalidate the cached result immediately, so
contracts observe exactly the same state transitions and errors.

## Mechanism

`Host::get_contract_data` currently reconstructs the storage key, calls
`Storage::get`, and then calls `to_valid_host_val(&e.val)` on every read. That
means repeated soroswap reads of stable pool, pair, instance, reserve, and balance
entries pay both the ordered-map lookup and the full `ScVal` -> `Val` conversion
path again. A per-host-invocation cache keyed by `(Rc<LedgerKey>, StorageType)`
and storing the already-converted successful result can preserve metering by
charging the same `Storage::get` / conversion budget on hits while returning the
cached `Val`; `Storage::put` and `Storage::del` would clear the entry for that
key. This differs from prior storage-map-probe hypotheses because it skips the
complete get-result envelope, including `storage get`, `ScVal to Val`, and
`add host object`, rather than only one map lookup or one key conversion.

## Trigger

Run the current soroswap apply-load benchmark. The strongest trigger is a swap
path that repeatedly reads the same contract instance or pool/pair data within a
single invocation before writing final reserves and balances. Any repeated
successful `Host::get_contract_data` for a key not modified since the previous
read should become a cache hit; a `put_contract_data` or `del_contract_data`
against that key must invalidate the cached result before subsequent reads.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2243` —
  `Host::get_contract_data` performs `storage_key_from_val`, `Storage::get`, and
  per-read `to_valid_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-279` —
  `Storage::try_get_full_helper` / `try_get_full` perform the metered storage
  map access and clone the returned entry pair.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460` —
  `to_host_val` / `to_valid_host_val` enter the generic ScVal conversion path.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:521-600` —
  `TryFromVal<ScVal> for Val` classifies object values and constructs host
  objects for non-immediate values.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:443-458` —
  `add_host_object` allocates a new host object handle for converted object
  values.

## Evidence

The latest accepted soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` is
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
Timestamp-filtering unwrapped events to `applyLedger` windows confirms the
candidate zones are apply-contained: `storage get` contributes 672,084,842 ns
over 321,802 events, `ScVal to Val` contributes 1,144,488,055 ns over 800,217
events, and `add host object` contributes 373,380,488 ns over 996,931 events
inside `applyLedger`. These zones execute in Soroban worker clusters, so the
aggregate must be normalized by `T=8`, but the combined full-get envelope remains
about `(672 ms + 1,144 ms + 373 ms) / 8 = 274 ms` serial-equivalent over the
trace, above the 3% Medium floor of roughly 134 ms on the 4.476 s `applyLedger`
envelope.

The source supports a cacheable boundary: `Storage` is per host invocation, its
map is the authoritative enforcing-footprint view for that invocation, and all
writes funnel through `put_opt_helper` / delete helpers that can invalidate a
small result cache. Budget charging can remain unchanged by charging the same
components on cache hits before returning the cached result, preserving
contract-observable resource use while removing implementation overhead.

## Anti-Evidence

The hypothesis depends on actual repeated reads of unchanged keys within a host
invocation. If the current native Soroswap fast paths have already reduced the
swap path to mostly one read per key, the cache will miss and add overhead. It
also needs a careful object-identity audit: returning the same host-object handle
for repeated reads must be semantically equivalent for all immutable host object
types, or the cache must be limited to immediate `Val`s and explicitly copied
object values. A PoC must report hit rate and isolate savings after parallel
normalization; if hits are limited to scalar balance reads already covered by
the typed SAC balance fast path, the remaining gain will fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The local execution path exists: exported VM calls to `get_contract_data` enter
`Host::get_contract_data`, build a contract-data `LedgerKey`, read the enforcing
`Storage` map, then convert the stored `ScVal` into host `Val` objects. Writes
and deletes do funnel through storage mutation helpers that could invalidate a
cache. However, the cited Medium projection adds all in-apply `storage get`,
`ScVal to Val`, and `add host object` time, while the proposed cache can only
remove the implementation work for repeated successful `get_contract_data` reads
of unchanged persistent/temporary keys.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2264` — confirmed persistent/temporary `get_contract_data` reconstructs a ledger key, calls `Storage::get`, and converts `ContractDataEntry.val`; instance storage uses a separate in-frame map and is not covered by the proposed ledger-entry cache.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-290` — confirmed `Storage::get` charges/enforces footprint access, performs a metered ordered-map lookup, and clones the returned `EntryWithLiveUntil`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460` and `:543-658` — confirmed `to_valid_host_val` enters recursive `ScVal` conversion and object-valued cases allocate host objects and charge metered clone/allocation work.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:521-600` and `src/rust/soroban/p26/soroban-env-common/src/object.rs:124-199` — confirmed only object-classified `ScVal`s traverse host object construction; small scalar values do not hit `add_host_object`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-458` — confirmed returned absolute object handles are translated to fresh relative handles at the VM boundary, while `add_host_object` is the allocation being skipped by a cached object graph.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2268-2289` — confirmed persistent/temporary writes and deletes pass through `Storage::put`/`Storage::del`, so invalidation is possible but must cover every storage mutation path, not only `put_contract_data`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` and `:1301-1324` — confirmed exact metering is implemented as cost-type/input charges; preserving observable budget on cache hits would require replaying the same conversion/storage charges rather than simply returning the cached `Val`.
- `ai-summary/fail/crypto/summary.md:13-14` and `:72` — prior crypto reviews already bounded repeated storage-map and storage-key lookup optimizations below the objective threshold; this hypothesis is not a duplicate because it additionally targets conversion/object creation, but it inherits the need to isolate the hit subset rather than size against global zones.

### Why It Failed

The optimization claim overstates the targetable work. To preserve consensus
semantics, a cache hit must still charge the same storage lookup and conversion
budget; therefore the removable portion is the unmetered implementation overhead
of repeated successful reads, not the full `storage get`/`ScVal to Val`/`add host
object` aggregate. Those aggregate zones include first reads, instance-storage
reads, key conversion, map/vector construction, auth/event/object work, and many
object allocations unrelated to repeated persistent/temporary `get_contract_data`
results. Without measured repeated-read hit rate and per-hit removable overhead,
the projected savings do not clear the optimize-soroswap Medium floor; by the
objective rule, below-Medium optimization hypotheses are not viable.

### Lesson Learned

For Soroban host result caching, first isolate repeated unchanged-key hits and
separate budget charges from removable implementation work. Broad Tracy zones are
useful for finding candidate surfaces, but a Medium review needs a cache-hit
denominator and a targetable per-hit cost after parallel-worker normalization.
