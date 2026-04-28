# H004: Cache LedgerKey hash across InMemoryBucketState `scan` calls in BucketListSnapshot::getBucketEntry

**Date**: 2026-04-29
**Subsystem**: bucket / soroban
**Severity**: Low
**Impact**: Sub-1% reduction in soroswap apply time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `SearchableBucketListSnapshot::getBucketEntry` walks the bucket list
from level 0 down to find a key, the `std::hash<LedgerKey>` of the query
key should be computed **once** for the whole walk, not once per bucket
level. The `success/soroban/004` optimization already cached
`ParallelApplyLedgerKey` hashes for the parallel-apply *map* lookups
(`mTxEntryMap`/`mThreadEntryMap`/`mGlobalEntryMap`), but the *bucket
list snapshot* lookup path still recomputes the hash on every level.

## Mechanism

`SearchableBucketListSnapshot::getBucketEntry`
(`src/bucket/BucketListSnapshot.cpp:170-201`) calls `bucket->getIndex().lookup(k)`
which dispatches to `InMemoryIndex::scan` →
`InMemoryBucketState::scan(start, searchKey)`
(`src/bucket/InMemoryIndex.cpp:251-262`). That method does
`mEntries.find(searchKey)`, which invokes
`InternalInMemoryBucketEntryHash::operator()(LedgerKey const&)`
(`src/bucket/InMemoryIndex.h:57-61`), which calls
`std::hash<stellar::LedgerKey>{}(key)` (declared in
`src/ledger/LedgerHashUtils.h:136-203`).

A single `getBucketEntry` call typically walks 1–3 bucket levels searching
for the key. For each visited level, the same hash is recomputed on the
same query key. A trivial optimization is to precompute the hash once at
the top of `getBucketEntry` and pass it to each `scan` call (e.g., via a
`Hashed<LedgerKey>` adaptor or a `find` overload accepting a precomputed
hash).

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py
--tracy`, soroswap TX=4000, T=8). The accepted baseline trace
(`/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/...02-soroswap-tx-4000-t-8.tracy`)
shows:

| Zone | Source | Total ns | Calls | Mean ns |
|------|--------|---------:|------:|--------:|
| `getBucketEntry` | `bucket/BucketListSnapshot.cpp:174` | 3,187,677,224 | 1,147,168 | 2,778 |
| `scan` (in-mem) | `bucket/InMemoryIndex.cpp:253` | 3,069,760,564 | 1,447,169 | 2,121 |
| `load` | `bucket/BucketListSnapshot.cpp:317` | 3,548,241,204 | 670,130 | 5,294 |

`1.45M scan / 670k load ≈ 2.16` levels visited per load. The redundant
hash count is `(2.16 - 1.0) × 670k ≈ 776k` extra hash computations.

## Target Code

- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` could
  precompute `std::hash<LedgerKey>{}(k)` once per outer call.
- `src/bucket/InMemoryIndex.cpp:251-262` — `scan` would need a
  precomputed-hash overload.
- `src/bucket/InMemoryIndex.h:47-74` — `InternalInMemoryBucketEntryHash`
  / `InternalInMemoryBucketEntryEqual` already use heterogeneous lookup;
  a `Hashed<LedgerKey>` wrapper could plug in alongside.

## Evidence

- The hash function for `CONTRACT_DATA` keys traverses an `SCVal`
  recursively (`src/ledger/LedgerHashUtils.h:178-185`) and is genuinely
  expensive; for `ACCOUNT`/`TRUSTLINE` keys it is a single `uint256`
  hash.
- The parallel-apply map lookup path **already** caches hashes via
  `ParallelApplyLedgerKey` (see `success/soroban/004`), confirming that
  hash recomputation across multiple lookups against immutable keys is
  worth caching.

## Anti-Evidence

- For soroswap, contract-data lookups are served from
  `InMemorySorobanState` (per the project memory and `LedgerTxn.cpp:3695`),
  so most bucket-snapshot loads are for cheap `ACCOUNT`/`TRUSTLINE` keys
  where the hash is a single `uint256` (~50 ns). The redundant cost is
  `~776k × 50 ns ≈ 39 M ns ≈ 0.9 %` of `applyLedger` zone time —
  **below the 1 % objective floor and well below the Medium severity
  threshold (3 %)**.
- The success-record `001-inmemory-bucket-scan-polymorphic-wrapper` was
  the previous big win on this code path. Most of the remaining
  `scan` mean-time is Tracy `ZoneScoped` overhead and `unordered_set`
  bucket traversal, not hash recomputation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — `success/004` cached hashes for `ParallelApplyLedgerKey`
in the parallel-apply map paths, not for the bucket-list snapshot
`getBucketEntry` walk; this lookup path is distinct and not previously
optimized.

### Why It Failed

The expected wall-clock benefit on the soroswap benchmark is
sub-1 % — below the project's noise floor and below the objective
severity scale's Low cut-off (1–3 %). For soroswap the bucket-snapshot
hot path mostly serves cheap `ACCOUNT`/`TRUSTLINE` keys whose
`std::hash` is a single `uint256` shorthash; redundant recomputation
across ~2 levels per load saves only ~30–50 ns × 776 k extra calls
≈ 30–40 M ns aggregated. With `applyLedger` at 4.33 B ns total, this is
under 1 %, below the objective hypothesis stage threshold.

A larger win in this code path would require reducing the **number of
bucket levels visited per load** (e.g., a snapshot-wide bloom filter or
key-to-level cache), not simply caching the per-key hash. That is a
different, more invasive design.

### Lesson Learned

When a previous success record (`success/004`) caches hashes for one
*kind* of key/map combo, do not assume the same fix has the same
magnitude of impact for a different lookup path; the cost of
`std::hash<LedgerKey>` varies by an order of magnitude depending on
`LedgerEntryType` (`SCVal` vs `uint256`), and the workload determines
which type dominates the lookup mix.
