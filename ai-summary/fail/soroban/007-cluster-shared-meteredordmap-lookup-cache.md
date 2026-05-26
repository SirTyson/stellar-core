# H007: Cluster-Shared MeteredOrdMap Lookup-Position Cache for Repeat Storage Probes

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-cluster reduction of `MeteredOrdMap` binary-search work for the
repeated soroswap pair storage map
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`MeteredOrdMap::get` / `get_at_index` perform an `O(log N)` binary search over
the sorted `Vec<(K, V)>` of key/value entries, charging `Compare<K>` per
comparison. For the soroswap workload, all transactions within a single
`Cluster` operate on the same Soroswap pair contract, so every Soroban
transaction's storage map has the same 6 persistent keys at the same indices
(token0, token1, factory, reserve0, reserve1, fee). Within a cluster of ~250
transactions, the host re-evaluates the same `(key → index)` mapping for every
`storage get` / `storage has` / `storage put` host call, yielding the same
positions modulo writes to the reserve slots.

Expected behavior of a *well-shaped* cluster apply: each unique storage key
encountered in a cluster's pair contract should incur its `Compare<K>` cost
once per cluster (as part of an initial probe), with subsequent same-key
lookups hitting a small cluster-local cache and skipping the binary-search
work. Across ~1.25k storage probes per cluster (~5 × ~250 txs) on 6 unique
keys, this reduces the per-probe work from `~log2(6) ≈ 2.6` `Compare<K>`
calls to a single hash/equality check.

## Mechanism

`map lookup indexed` self-time = 478 ms, `map lookup` = 381 ms across 861k +
427k = ~1.29M lookups in the soroswap trace. Of these, the dominant share
comes from enforcing-mode storage map binary searches inside
`Storage::try_get_full` / `Storage::put` and from invocation-storage map
operations.

The proposed cache would live on the worker's `ThreadParallelApplyLedgerState`
(or be threaded through the Rust `Host` via a side channel) and key on
`(contract_id, storage_key)` mapping to a cached `Vec` index plus a generation
counter invalidated on writes. The structural saving is the binary-search
comparator dispatch (`Compare<HostObject>` ~200 ms aggregate, `obj_cmp` ~141 ms
host + ~85 ms dispatch).

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap scenario. Each cluster
of ~250 transactions touches the same Soroswap pair's persistent storage map.
Per-tx storage probes (~5) all binary-search the same 6-entry `MeteredOrdMap`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:148,173,330`
  — `MeteredOrdMap::insert`, `get`, `get_at_index`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:329,488` — `Storage::try_get`,
  `Storage::put`.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:51` —
  `Compare<HostObject>` binary-search comparator.

## Evidence

- Tracy soroswap trace aggregate self-times: `map lookup indexed` 478 ms,
  `map lookup` 381 ms, `Compare<HostObject>` 200 ms, `obj_cmp` (host) 141 ms,
  `obj_cmp` (dispatch) 85 ms. Total ~1285 ms aggregate worker CPU.
- Soroswap pair storage layout has a fixed 6-key persistent map; clusters by
  construction contain conflicting transactions on the same pair, so within a
  cluster the map keys repeat across all txs.

## Anti-Evidence

- After 8-way cluster normalization and 71-ledger division:
  `1285 ms / 8 / 71 = 2.26 ms/ledger = 1.09 %` of the 207 ms soroswap baseline.
  Below the 1% Low noise floor when calculated against the median (and only
  marginally above it at the per-ledger arithmetic). This is the *upper bound*
  assuming full elimination of the binary-search comparator work; realistic
  cache-hit fraction would reduce the saving further.
- The metering contract is protocol-visible: each comparator call charges
  `Compare<HostObject>` against the budget. A correctness-preserving cache
  must *replay* the equivalent charges to keep `BudgetImpl::cpu_insns` and
  `mem_bytes` totals identical, which removes most of the recoverable work.
  This mirrors the rejection mechanism of fail
  `002-index-host-storage-map-lookups.md` (metering-equivalence requirement)
  and fail `002-cache-storage-value-host-conversions.md` (same-`Val`-handle
  reuse is the only safe lookup-cache hit class for soroswap, and it is a
  strict subset of the has-then-get pattern already addressed).
- Meta-Pattern #14 explicitly lists `MeteredOrdMap` specialization ceiling at
  0.33% (`fail/207-specialize-meteredordmap-insert.md`). The lookup side is
  similarly bounded by aggregate worker CPU after parallelism normalization.
- Per-tx invocation-storage maps (`InstanceStorageMap`) are not shared across
  txs even within a cluster — each tx re-creates the instance storage map
  from the persistent `ScContractInstance` entry, so the cluster-scoped cache
  would have to target only the *enforcing footprint* storage layer.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a cluster-scoped variant;
related but distinct from fail `002-cache-storage-value-host-conversions.md`
(generic same-Val-handle cache) and fail `002-index-host-storage-map-lookups.md`
(indexed read path with metering change).

### Why It Failed

Upper bound saving is 1.09% of the 207 ms baseline before subtracting
mandatory metering-replay overhead, placing this firmly in Low / sub-Low
territory regardless of cache implementation. The same metering-equivalence
constraint that rejected the indexed-lookup variant applies: removing
`Compare<HostObject>` charges is protocol-visible. A correct charge-replay
cache pays most of the comparator cost it tries to eliminate, leaving only
the residual `RefCell` borrow / vtable dispatch as actual savings.

Additionally, per Meta-Pattern #14, the parallel-worker normalization formula
shows this zone family cannot clear Medium without a structural redesign
that *eliminates* the lookups entirely, not merely caches their results.
Caching binary-search positions is structurally below the threshold given
the small map size (6 entries) — `log2(6) ≈ 2.6` comparator calls per probe
times the 6 unique keys means the per-probe binary-search work is already
small per call.

### Lesson Learned

For Soroban host storage caching hypotheses, three filters must be passed in
order: (1) aggregate worker CPU / NUM_CLUSTERS / N_ledgers must reach 3% of
the median baseline (Meta-Pattern #14); (2) the cache must preserve all
`Compare<K>`, `MemCpy`, and `VisitObject` charges deterministically across
hits and misses; (3) the cache must amortize across an access pattern dense
enough to actually save the comparator dispatch — small fixed-schema maps
(<10 entries) yield too few comparator calls per probe to make caching
worthwhile.
