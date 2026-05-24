# H008: Cache `LedgerKey` hash on `CONTRACT_DATA` keys via `ParallelApplyLedgerKey` to skip `xdrComputeHash` per `mGlobalEntryMap` operation

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban parallel apply state
**Severity**: Low (claimed); actually below threshold
**Impact**: Memoize the `std::hash<LedgerKey>` result for `CONTRACT_DATA` keys
inside `ParallelApplyLedgerKey` so `mGlobalEntryMap` lookups, the per-thread
`mEntryMap`, `mClassicEntries`, and the per-stage `ParallelApplyLedgerKeySet`
all skip the embedded `shortHash::xdrComputeHash` over the contract-data
`SCVal` key on every operation.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`std::hash<LedgerKey>::operator()` for `CONTRACT_DATA`
(`src/ledger/LedgerHashUtils.h:178-185`) mixes three components:
1. `std::hash<SCAddress>` over the contract address (fast, ~32 byte input)
2. `shortHash::xdrComputeHash(lk.contractData().key)` — XDR-serializes the
   `SCVal` key and hashes the bytes (variable size, can be large for vector or
   map keys)
3. `std::hash<int32_t>` over durability

In a parallel-apply ledger, the same `CONTRACT_DATA` key is hashed many times:
- `getReadWriteKeysForStage` builds a `ParallelApplyLedgerKeySet`
- `GlobalParallelApplyLedgerState::collectModifiedClassicEntries` filters and
  inserts into `mGlobalEntryMap`
- `fetchSorobanReadOnlyEntries` does `mGlobalEntryMap.find(lk)` lookups per
  footprint key (RW + RO)
- Each worker thread's `ThreadParallelApplyLedgerState::upsertEntry` /
  `flushRoTTLBumpsInTxWriteFootprint` / `commitChangesFromSuccessfulTx`
  rehash each key in its scoped state
- `commitChangesFromThreads`/`commitChangeFromThread` walk thread maps and
  rehash each key while merging to global

Each of these hashes pays the full `xdrComputeHash` cost on the SCVal key,
which for soroswap-shaped workloads is dominated by small `ScVec` keys (token
balance keys are typically `ScVec[Symbol("Balance"), Address(...)]` or
similar). Memoizing the hash on the wrapper that already exists for parallel
apply (`ParallelApplyLedgerKey`) would let every downstream container skip
re-serializing the SCVal.

## Mechanism

`ParallelApplyLedgerKey` is defined in `ParallelApplyUtils.h` and is the keyed
type for `mGlobalEntryMap`, `mEntryMap`, and the read-write key set. Its
hash currently delegates to `std::hash<LedgerKey>`. If `ParallelApplyLedgerKey`
captured the LedgerKey hash once at construction (during the
`getReadWriteKeysForStage` pass at `ParallelApplyUtils.cpp:104-130` and at
`GlobalParallelApplyLedgerState` setup), every downstream container operation
could read it from the wrapper instead of recomputing. Repeated `find`/`emplace`
across the 8 worker threads and the global commit phase would only pay
`xdrComputeHash` once per unique key per ledger.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8. Each soroswap pair
contract has ~6 unique `CONTRACT_DATA` entries (reserves, token instances,
balances) accessed per swap; with ~250 swaps per cluster × 8 clusters and
multiple stages, the same key is hashed dozens of times across `mGlobalEntryMap`
setup, thread-map operations, and post-stage commit merges.

## Target Code

- `src/ledger/LedgerHashUtils.h:140-202` — `std::hash<LedgerKey>::operator()`
  with the `xdrComputeHash` on the `CONTRACT_DATA` SCVal key.
- `src/transactions/ParallelApplyUtils.h:21-330` — `ParallelApplyLedgerKey`,
  `mGlobalEntryMap`, `mEntryMap` declarations; the wrapper that would carry
  the cached hash.
- `src/transactions/ParallelApplyUtils.cpp:104-130` —
  `getReadWriteKeysForStage`, the first place each RW/TTL key is wrapped and
  hashed.
- `src/transactions/ParallelApplyUtils.cpp:601-718` —
  `collectModifiedClassicEntries` and `fetchSorobanReadOnlyEntries`, which
  rehash each footprint key on `mGlobalEntryMap.find` / `emplace`.
- `src/transactions/ParallelApplyUtils.cpp:857-922` — `commitChangeFromThread`
  and `commitChangesFromThreads`, the serial post-stage rehash on merge.

## Evidence

- For `CONTRACT_DATA` keys, `shortHash::xdrComputeHash` traverses the SCVal
  XDR encoding, which for typical soroswap balance keys is a 30-80 byte
  serialization plus SHA256-style hash mixing — measurably more expensive
  than a fixed 32-byte uint256 hash.
- The same key is hashed many times: at `getReadWriteKeysForStage`, twice in
  `GlobalParallelApplyLedgerState::collectModifiedClassicEntries`/
  `fetchSorobanReadOnlyEntries`, on every per-tx `mThreadEntryMap.find`,
  on every `commitChangeFromThread` merge into `mGlobalEntryMap`, and on every
  subsequent stage's footprint walk.
- Repeated hash work scales linearly with `txs/cluster × clusters × stages`,
  not by `unique-keys` — clear amortization opportunity.

## Anti-Evidence

- `mGlobalEntryMap` is a `std::unordered_map<ParallelApplyLedgerKey, ...>`;
  carrying the hash in the wrapper does not let the standard library *use* the
  cached hash unless we provide a custom hasher that reads from the wrapper.
  The standard hasher recomputes regardless of any stored field, so the
  optimization requires a custom map type or a Boost-style transparent hasher.
- The `xdrComputeHash` cost per key is bounded by the SCVal size (typically
  <100 bytes for soroswap balance keys); shortHash's per-byte cost is ~1-2 ns,
  putting per-hash work at sub-microsecond. Even at thousands of hash
  operations per ledger, the absolute saving is sub-millisecond.
- Fail history (`007-thread-cached-key-hash-into-inmemory-bucket-scan.md`)
  rejected a similar threading-of-cached-hash optimization for
  `InMemoryBucketState::scan` because the actual hot path doesn't probe
  through `std::hash<LedgerKey>` enough to clear the threshold; the
  parallel-apply state path has a similar profile of small per-call overhead.
- `mGlobalEntryMap.reserve(estimatedEntries)` already pre-sizes the table to
  avoid rehashes during build (`ParallelApplyUtils.cpp:416`), eliminating the
  rebuild-on-grow cost that would have inflated this hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — Fail
`007-thread-cached-key-hash-into-inmemory-bucket-scan.md` targeted
`InMemoryBucketState::scan`; this hypothesis targets the *parallel-apply
state* path (`mGlobalEntryMap`, per-thread maps, RW key set). The code paths
are disjoint, so this is novel.

### Why It Failed

Quantified bounds keep the optimization sub-Medium and likely sub-Low. Per
ledger, soroswap touches roughly ~50-200 unique `CONTRACT_DATA` keys across
all stages. Each key is hashed roughly 10-20 times across the parallel-apply
control flow (RW key set, classic filter, RO preload, per-thread upsert,
per-thread RoTTLBump flush, per-stage commit merge, post-stage commit to
ltx). At ~600 ns per `xdrComputeHash` on a typical 50-byte SCVal key, the
addressable ceiling is approximately 200 keys × 15 hashes × 600 ns ≈ 1.8 ms
per ledger (~0.8% of the 218 ms apply-load median). That ceiling assumes
zero residual hash cost — in reality a custom hasher still indexes the
wrapper and hashes the cached value, so realistic savings are far below the
ceiling. The Medium floor of 6.5 ms is not reachable; even the Low 2.2 ms
floor is unlikely. Additionally, retrofitting a transparent hasher that
reads the cached hash off the wrapper without breaking lookups in
`std::unordered_map` requires either a custom map type or careful Boost
heterogeneous-lookup setup, adding non-trivial code surface for a sub-Low
return.

### Lesson Learned

LedgerKey hash memoization on parallel-apply wrappers is a real but
sub-threshold optimization: ~1-2 ms/ledger ceiling once amortized over
~10-15 hash operations per unique CONTRACT_DATA key across the parallel-apply
control flow. Future hash-memoization hypotheses must quantify (unique
keys/ledger) × (hash ops per key) × (per-hash cost) in absolute µs and
compare to the 6.5 ms Medium floor before drafting. Hash-cache designs that
require custom hashers on standard containers also pay implementation cost
that competes against the small savings.
