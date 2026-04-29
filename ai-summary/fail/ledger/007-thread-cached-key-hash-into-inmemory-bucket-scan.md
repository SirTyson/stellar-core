# H007: Thread cached LedgerKey hashes through BucketList lookup so InMemoryBucketState::scan stops recomputing std::hash<LedgerKey>

**Date**: 2026-04-29
**Subsystem**: ledger / bucket lookup on parallel apply hot path
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by removing per-probe XDR-walking hash computation from the highest-call-count zone descended from `applySorobanStageClustersInParallel`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

During parallel Soroban apply, every footprint `LedgerKey` lookup that misses the per-thread / per-tx maps and falls into `InMemorySorobanState` or the `LiveBucketList`'s `LiveBucketIndex::lookup` should pay at most one XDR-key-hash computation per unique key per ledger. The query side of `InMemoryBucketState::scan` (a transparent `std::unordered_set` lookup) should accept the precomputed hash that already lives on the matching `ParallelApplyLedgerKey` (cached on `TxBundle` since success/004), instead of recomputing `std::hash<LedgerKey>{}(searchKey)` inside `InternalInMemoryBucketEntryHash::operator()(LedgerKey const&)` on every probe of every bucket level.

## Mechanism

`success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md` cached `ParallelApplyLedgerKey` (with its hash) on each `TxBundle` and threaded it through `mTxEntryMap` / `mThreadEntryMap` / `mGlobalEntryMap`. But once a lookup escapes those maps it lands in `LiveBucketIndex::lookup(LedgerKey const& k)` (`src/bucket/LiveBucketIndex.cpp:223-240`), which discards any caller-side hash and calls `InMemoryBucketState::scan(start, k)` (`src/bucket/InMemoryIndex.cpp:249-262`) -> `mEntries.find(k)` -> `InternalInMemoryBucketEntryHash::operator()(LedgerKey const&)` (`src/bucket/InMemoryIndex.h:57-61`) which executes `std::hash<LedgerKey>{}(key)` -- a fresh XDR walk over the entire `LedgerKey`, including the inner `SCVal` key for `CONTRACT_DATA`. Each soroswap parallel-apply tx probes the BucketList via descents through ~22 levels (`scan` is called once per level until a hit), and 70 ledgers in the current trace fire `scan` 857,848 times for 1.73 s of self-time -- making `scan` the third-largest self-time zone in the entire Tracy trace and the largest one that lives strictly inside `applySorobanStageClustersInParallel`. The cached hash on `ParallelApplyLedgerKey` is the same value the hash functor would compute, so threading it down skips the entire XDR walk on the query side without changing any observable behavior.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). Soroswap transactions probe each footprint key against many bucket levels per ledger (RW + RO writeback / reads in the parallel cluster path). With ~145 tx/ledger x ~30 footprint keys x ~22 bucket levels per descent (early-exits on hit) and additional probes from `getBucketEntry` / `loadKeysFromBucket`, `InMemoryBucketState::scan` is called ~12,250 times per ledger on the parallel apply hot path, each currently paying a full XDR `std::hash<LedgerKey>` recompute on the `CONTRACT_DATA` key.

## Target Code

- `src/bucket/InMemoryIndex.h:22-74` -- `InternalInMemoryBucketEntry` already stores `mHash` per entry and exposes `keyEquals(LedgerKey const&)`; the heterogeneous `InternalInMemoryBucketEntryHash::operator()(LedgerKey const&)` recomputes `std::hash<LedgerKey>{}(key)` on every probe -- this is the one functor that needs a sibling that consumes a precomputed hash.
- `src/bucket/InMemoryIndex.cpp:198-238` -- `InternalInMemoryBucketEntry`'s constructor caches `mHash`; the heterogeneous comparator equality is already cheap (`bucketEntryKeyEqual` short-circuits on type), so the only remaining per-probe cost is the query-side hash.
- `src/bucket/InMemoryIndex.cpp:249-262` and `InMemoryIndex.h:162-166` -- `InMemoryBucketState::scan` and `InMemoryIndex::scan` ignore `start` and forward `searchKey` straight into the `unordered_set`; they need an overload that also accepts a precomputed hash and forwards a wrapper type the functor recognizes.
- `src/bucket/LiveBucketIndex.cpp:223-257` -- `LiveBucketIndex::lookup` / `scan` are the entry points from `SearchableBucketListSnapshot::getBucketEntry`; they currently take `LedgerKey const& k` only and need a sibling that takes a `(LedgerKey const&, size_t precomputedHash)` pair.
- `src/bucket/BucketListSnapshot.cpp:166-201` -- `SearchableBucketListSnapshot::getBucketEntry` is the loop that probes every bucket level for a single key; this is where the cached hash from `ParallelApplyLedgerKey` should be injected and forwarded into every level's `lookup`.
- `src/transactions/ParallelApplyStage.h:18-245` and `src/transactions/ParallelApplyUtils.cpp:104-1457` -- `TxBundle` already carries cached `ParallelApplyLedgerKey` values (success/004); the parallel-apply ledger-access helpers need to thread the cached hash into the bucket lookup whenever they fall through `InMemorySorobanState` into the live bucket list.
- `src/ledger/InMemorySorobanState.cpp` -- `InMemorySorobanState::get` is the first fall-through layer; if the entry is not in memory, the caller proceeds to BucketList -- at that exact handoff the cached hash from `ParallelApplyLedgerKey` is in scope and should be passed down, not dropped.

## Evidence

- Tracy soroswap trace zone summary (current baseline):
  - `applyLedger` 5.77 s / 69 calls.
  - `applySorobanStageClustersInParallel` 4.13 s / 41 calls (40.4% of trace, dominant subtree of `applyLedger`).
  - `scan` (`bucket/InMemoryIndex.cpp:253`) self-time 1.73 s / 857,848 calls (16.9% of trace, mean 2.0 us / call) -- third-highest self-time in the entire trace, and the largest in-scope self-time zone descended from `applySorobanStageClustersInParallel`.
  - `getBucketEntry` (`bucket/BucketListSnapshot.cpp:174`) 105 ms / 707,847 calls -- confirms the per-call wrapper around `lookup`/`scan` is also high-frequency.
  - `load` (`bucket/BucketListSnapshot.cpp:317`) 193 ms / 462,865 calls -- secondary entry point that flows through the same `LiveBucketIndex::lookup`.
- The query-side hash is currently a full `std::hash<LedgerKey>` walk that for `CONTRACT_DATA` includes the inner `SCVal` (often a vector / map of typed values), which is the most expensive variant; the entry-side hash is precomputed once at insert (`InMemoryIndex.cpp:198-204`) so eliminating the query-side walk leaves both sides O(1) hash + cheap typed equality.
- The hash that lives on `ParallelApplyLedgerKey` (success/004) is the *same* `std::hash<LedgerKey>` value, so substituting it preserves bucket lookup correctness and observable behavior; no protocol-visible state changes.
- Cache effects: removing the XDR walk also eliminates pointer-chasing through `SCVal` discriminants on each probe, so wall-time savings amplify under cache pressure during 7-way parallel cluster execution.

## Anti-Evidence

- The savings are amortized across ~7 cluster threads in `applySorobanStageClustersInParallel`, so the wall-time delta is the per-thread fraction of the CPU savings; the realized speedup will be a fraction of the 1.73 s self-time, not the whole thing.
- Some `scan` callers do not have a cached hash (e.g., catchup / startup index loads, eviction scans, history publishing); those paths must keep working with the existing `LedgerKey`-only overload, requiring two API surfaces to coexist.
- A subset of `scan`'s 2 us/call cost is `unordered_set` bucket traversal + key-equality (`bucketEntryKeyEqual`), which remains; only the query-side hash recompute is removable.
- Threading a `(key, hash)` pair through `SearchableBucketListSnapshot` and the bucket index APIs touches several headers and adds template surface, so the diff is non-trivial even though every call site is structural.
- If `std::hash<LedgerKey>` is already cheap for small classic keys (account/trustline), savings concentrate on `CONTRACT_DATA`-heavy footprints; the soroswap workload satisfies this, but the change won't materially help classic-only ledgers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL -- duplicate of `ai-summary/fail/ledger/summary.md` entry `005-bucket-lookup-aggregate-out-of-scope.md`
**Failed At**: reviewer

### Trace Summary

The concrete `InMemoryBucketState::scan` inefficiency exists: heterogeneous lookup of a plain `LedgerKey` does recompute `std::hash<LedgerKey>` before probing the in-memory bucket index. However, the claimed soroswap parallel-apply `CONTRACT_DATA` path does not fall through to `LiveBucketIndex`; both global read-only preloading and thread/tx live reads route Soroban `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys to `InMemorySorobanState` instead. BucketList lookup is still used for non-Soroban keys and generic snapshot users, but that is substantially the same BucketList lookup hotspot already rejected as an aggregate/out-of-scope profile artifact, and the remaining in-apply classic-key share cannot plausibly reach the objective's Medium threshold.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:646-714` -- global parallel state preloads Soroban read-only footprint entries and TTLs from `mInMemorySorobanState.get(...)`; `mLCLSnapshot.loadLiveEntry(...)` is only the non-in-memory fallback.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` -- thread-level `getLiveEntryOpt` first checks `mThreadEntryMap`, then sends `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys to `InMemorySorobanState`; only non-Soroban keys use the live BucketList snapshot.
- `src/ledger/InMemorySorobanState.cpp:206-238` and `src/ledger/InMemorySorobanState.h:246-270` -- `InMemorySorobanState::get` handles Soroban keys through its contract-data/code/TTL maps, using TTL-key hashes for contract data rather than `LiveBucketIndex::lookup`/`InMemoryBucketState::scan`.
- `src/bucket/BucketListSnapshot.cpp:313-345` -- `SearchableBucketListSnapshot::load` loops buckets and calls `getBucketEntry`, but this path is reached from parallel apply only for non-Soroban live keys after the `InMemorySorobanState` routing decision.
- `src/bucket/LiveBucketIndex.cpp:223-257` -- `lookup`/`scan` forward to `mInMemoryIndex->scan` for small buckets and would discard any caller-side `ParallelApplyLedgerKey` hash today.
- `src/bucket/InMemoryIndex.h:47-61` and `src/bucket/InMemoryIndex.cpp:249-262` -- the in-memory bucket index stores per-entry hashes but recomputes a query-side `std::hash<LedgerKey>` for plain-key finds.
- `ai-summary/fail/ledger/summary.md:18` -- prior investigation `005-bucket-lookup-aggregate-out-of-scope.md` already rejected `InMemoryIndex::scan`, `getBucketEntry`, and `BucketListSnapshot::load` as a soroswap apply-path bottleneck after timeline overlap analysis.

### Why It Failed

This is not a novel viable Medium optimization. It targets the same BucketList lookup zones already rejected in ledger failure 005, and the source trace contradicts the central `CONTRACT_DATA` mechanism: Soroban footprint reads in parallel apply do not probe every live bucket level through `InMemoryBucketState::scan`; they use `InMemorySorobanState`. Threading `ParallelApplyLedgerKey::hash()` into BucketList lookup might save some query-side hashing for non-Soroban snapshot loads, but that is not the claimed high-frequency soroswap path and is below the objective severity threshold.

### Lesson Learned

For Soroban apply performance, distinguish the live BucketList snapshot from `InMemorySorobanState`: the latter is the intended fast path for `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` during parallel apply. Aggregate Tracy zones for bucket lookup must be timeline-checked against `applyLedger` and then traced through the actual key-type dispatch before projecting soroswap apply-time savings.
