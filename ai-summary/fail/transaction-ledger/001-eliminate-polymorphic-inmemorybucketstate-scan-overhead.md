# H001: Eliminate per-query heap allocation, virtual dispatch and `LedgerKey` copies in `InMemoryBucketState::scan`

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (`bucket/InMemoryIndex` ↔ `BucketListSnapshot` lookups)
**Severity**: Medium
**Impact**: Apply-time reduction; classic-account lookups during `prefetch` and per-tx fee processing
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A bucket-index lookup keyed on a `LedgerKey` should be a single hash-table
probe: hash the (small, plain-old-data) key, look it up in a flat hash
container, return either the entry pointer or "not found". No heap
allocation, no virtual dispatch, no copies of the `LedgerKey` should be
required on the lookup path. This is the universal expectation for a hot
read-through index used on every classic-entry load.

## Mechanism

`InMemoryBucketState::scan` (`src/bucket/InMemoryIndex.cpp:64-76`)
constructs a query wrapper on every call:

```cpp
auto it = mEntries.find(InternalInMemoryBucketEntry(searchKey));
```

`InternalInMemoryBucketEntry` (`src/bucket/InMemoryIndex.h:26-133`) is a
type-erased wrapper: it holds a `std::unique_ptr<AbstractEntry>` and
dispatches `hash()` and `operator==` through virtual functions. The query
constructor does `std::make_unique<QueryKey>(ledgerKey)` — **a heap
allocation per lookup**. The hash table's `operator==` resolves to
`AbstractEntry::operator==` which calls **`copyKey()` on both sides** —
each `copyKey()` returns a `LedgerKey` *by value*, copying the entire
XDR `LedgerKey` (≈80–200 bytes for ACCOUNT/CONTRACT_DATA). For
`ValueEntry::copyKey()` this also calls `getBucketLedgerKey(*entry)` which
walks the stored `BucketEntry` to extract its key.

Every lookup therefore performs: 1 heap allocation (QueryKey), 1 virtual
hash, and on each hash-bucket comparison, 2 virtual `copyKey()` calls
plus 2 `LedgerKey` value copies plus a deep `==` on the resulting copies.
Tracy reports `scan` at 3,139 ms total / 1,445,421 calls / 65 measured
ledgers ≈ **22.2 K scans/ledger at 2.17 µs each ≈ 48 ms/ledger**, a large
fraction of which is on the apply critical path (prefetch passes during
`applyLedger` and source-account loads during `processFeesSeqNums`).

The expected one-probe behavior can be achieved by replacing the
`std::unordered_set<InternalInMemoryBucketEntry>` with a flat
`std::unordered_map<LedgerKey, IndexPtrT>` (or a
`folly::F14ValueMap` / heterogeneous-lookup-enabled set) keyed directly
on `LedgerKey`. The wrapper class, the heap allocation, the virtual
dispatch, and the `copyKey()` machinery all disappear; lookup becomes a
single hash + compare.

## Trigger

Reproduces on every soroswap apply ledger via
`scripts/run_apply_load_matrix.py` with the standard
`docs/apply-load-benchmark-sac.cfg`. No special workload required —
`InMemoryBucketState::scan` is exercised by every classic source-account
prefetch and load. Tracy will show `scan` self-time drop and
`applyLedger` total drop after the change.

## Target Code

- `src/bucket/InMemoryIndex.h:26-150` — `InternalInMemoryBucketEntry`
  hierarchy, `InMemoryBucketState::InMemorySet` typedef
- `src/bucket/InMemoryIndex.cpp:54-76` — `InMemoryBucketState::insert`
  and `scan` (the per-query allocation site)
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` calls
  `bucket->getIndex().lookup(k)` which forwards to `scan`
- `src/bucket/BucketListSnapshot.cpp:208-260` — `loadKeysFromBucket`
  bulk path that drives most prefetch scans
- `src/ledger/LedgerHashUtils.h:136-203` — `std::hash<stellar::LedgerKey>`
  used by both old and new container

## Evidence

1. **Tracy self-time**: `scan` (`src/bucket/InMemoryIndex.cpp:67`) is the
   #4 self-time consumer in the trace at 3,139 ms with 1.4 M calls
   (mean 2.17 µs). Even excluding the calls that occur on background
   bucket worker threads, the apply-path share dominates because
   `scan` is the inner kernel of the two prefetch passes
   (`prefetchTxSourceIds` + `prefetchTransactionData`, totaling
   ~377 ms / ledger group) and the per-tx classic source-account
   loads done by `processFeesSeqNums`.
2. **Per-call cost is anomalous for a small unordered-set lookup**:
   `std::hash<LedgerKey>` for an ACCOUNT key is a single
   `std::hash<uint256>` (~20 ns); the rest of the 2.17 µs measured
   per scan is dominated by the heap allocation + virtual dispatch +
   `LedgerKey` copies described in the mechanism. Removing those
   should cut per-call cost to the 200–400 ns range.
3. **The `ParallelApplyLedgerKey` precedent**
   (`src/transactions/TransactionFrameBase.h:47-86`) shows the project
   already recognized that wrapping `LedgerKey` and caching its hash is
   worthwhile; the bucket-index path predates that work and never got
   the same treatment.
4. **`InMemoryIndex` is built once at bucket creation and never
   mutated** (`src/bucket/InMemoryIndex.h:147` is `NonMovableOrCopyable`
   and `mEntries` is only populated via `insert` during
   `InMemoryIndex` construction at `InMemoryIndex.cpp:78-117`). A flat
   `unordered_map` keyed on `LedgerKey` is therefore drop-in safe.

## Anti-Evidence

1. The `InternalInMemoryBucketEntry` design exists for a reason: the
   value-side stores `IndexPtrT` (= `std::shared_ptr<BucketEntry>`)
   whose key has to be extracted via `getBucketLedgerKey`, while the
   query side starts from a bare `LedgerKey`. Switching to
   `unordered_map<LedgerKey, IndexPtrT>` requires explicitly storing
   the key alongside the entry pointer, which costs a small amount of
   per-bucket memory (key already lives inside the entry, so it is
   slight duplication of XDR data). Acceptable for the in-memory
   bucket size cap (BUCKETLIST_DB_INDEX_CUTOFF = 20 MiB).
2. Some scans occur on background bucket-merge worker threads
   (e.g., during merge progress reporting / index queries from
   `BucketManager::forgetUnreferencedBuckets` paths). Those are
   off the apply critical path. The total 3.14 s figure overstates
   the apply-path savings; the realistic ceiling is the portion
   triggered by `LedgerTxnRoot::Impl::loadFromBucketList` and
   `loadKeysFromBucket` invocations rooted under `applyLedger`.
   Even at half (≈1.5 s / 65 ≈ 23 ms / ledger ≈ 3.7 % of soroswap
   apply) this clears the Medium threshold.
3. Concurrent reads on `mEntries` from many threads must remain safe.
   The current `unordered_set` is read-only after construction; a
   replacement `unordered_map` would maintain the same invariant
   (no inserts after the index is published), so concurrent reads
   stay well-defined.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The local inefficiency in `InMemoryBucketState::scan` is real: each lookup constructs a heap-allocated `QueryKey` wrapper and performs virtual hash/equality through copied `LedgerKey` values. However, the SAC benchmark path warms the root account cache before the measured `closeLedger` timer, and that warming loop loads all benchmark accounts through this same bucket-list path. During measured apply, source-account prefetch skips already-cached accounts, fee processing hits the root entry cache, and `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` adds no Soroban footprint keys to the classic bucket-list prefetch path.

### Code Paths Examined

- `src/bucket/InMemoryIndex.h:26-150` — confirmed `InternalInMemoryBucketEntry` stores a `std::unique_ptr<AbstractEntry>`, constructs query/value wrappers, and compares by `copyKey()` on both sides.
- `src/bucket/InMemoryIndex.cpp:55-76` — confirmed insert stores `BucketEntry` pointers in the wrapper set and scan constructs `InternalInMemoryBucketEntry(searchKey)` for every lookup.
- `src/bucket/LiveBucketIndex.cpp:223-256` — confirmed live-bucket lookup/scan forwards to `InMemoryIndex::scan` only for buckets below the in-memory-index cutoff.
- `src/bucket/BucketListSnapshot.cpp:171-201,210-277,315-345,446-453` — confirmed point and bulk bucket-list loads call index lookup/scan through `getBucketEntry` and `loadKeysFromBucket`.
- `src/ledger/LedgerTxn.cpp:3101-3155` — confirmed root `prefetch` filters out keys already present in `mEntryCache` before calling `loadLiveKeys`.
- `src/ledger/LedgerTxn.cpp:3670-3728,3779-3813` — confirmed immediate account loads populate and subsequently hit the root entry cache.
- `src/ledger/LedgerManagerImpl.cpp:1655-1688,2443-2480,2823-2829` — confirmed source-account and transaction-data prefetch are inside `closeLedger`, but source-account prefetch delegates to root cache filtering and transaction-data prefetch receives no keys from InvokeHostFunction ops.
- `src/transactions/TransactionFrame.cpp:1777-1817,2026-2043` — confirmed fee processing loads the source account and fee-prefetch keys are source account keys.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1421-1424` — confirmed Soroban invoke ops do not contribute ledger keys to classic `prefetchTransactionData`.
- `src/simulation/ApplyLoad.cpp:2068-2086,2261-2310,2368-2441` — confirmed `warmAccountCache()` loads all generated accounts before `timeBefore` is sampled, then measured SAC close uses distinct source accounts per tx.
- `src/main/Config.cpp:213-214,322-323` and `docs/apply-load-benchmark-sac.cfg:26-55` — confirmed the benchmark has enough root entry-cache capacity for the generated accounts and does not override prefetch/cache defaults.

### Why It Failed

The hypothesis attributes the reported `scan` total to measured apply, but the traced benchmark driver explains most of that count outside the apply-time metric. `benchmarkModelTxTpsSingleLedger` calls `warmAccountCache()` before sampling the close/apply timer; `warmAccountCache()` loads every generated account through `stellar::loadAccount`, which reaches `LedgerTxnRoot::Impl::getNewestVersion`, `LedgerStateSnapshot::loadLiveEntry`, `BucketListSnapshot::load`, and ultimately `InMemoryBucketState::scan`. With SAC benchmark settings this can account for tens of thousands of account bucket-list scans per ledger while contributing zero to the measured `closeLedger` delta.

Inside measured `closeLedger`, the same warmed entries make `LedgerTxnRoot::Impl::prefetch` skip source-account bucket-list loads via `mEntryCache.exists`, and `processFeesSeqNums` then hits the entry cache for source-account loads. The SAC invoke-host-function operation also has an empty `insertLedgerKeysToPrefetch`, so Soroban footprint data is not routed through this classic bucket-list prefetch path. A direct-map replacement may still be a reasonable bucket-index cleanup, but for this objective its measured SAC/soroswap apply-time impact is below the Medium threshold and likely below noise.

### Lesson Learned

Tracy zone totals gathered over an apply-load run must be checked against the benchmark timer boundaries. Work done by benchmark scaffolding, especially `warmAccountCache()`, can produce hot-looking bucket-list samples without affecting the objective metric reported by `scripts/run_apply_load_matrix.py`.
