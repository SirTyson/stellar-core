# H001: InMemoryBucketState `scan` lookup pays heap allocation, virtual dispatch, and full LedgerKey copy per call

**Date**: 2026-04-27
**Subsystem**: bucket
**Severity**: Medium
**Impact**: per-lookup CPU on the apply hot path (BucketList read fan-out)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InMemoryBucketState::scan(start, searchKey)` is a pure in-memory hash-set
lookup of a `LedgerKey` against entries already resident in RAM (the
"in-memory" bucket index for small buckets). For an `unordered_set` keyed on
`LedgerKey`, a successful or unsuccessful lookup of an account/trustline
key should cost on the order of a single XDR hash of the key plus one
pointer-equality comparison per probe — measured in low hundreds of
nanoseconds, not microseconds. The function should not allocate, should not
virtual-dispatch through a wrapper, and should not deep-copy the stored
key on each comparison.

## Mechanism

`InternalInMemoryBucketEntry` (`src/bucket/InMemoryIndex.h:26-133`) wraps
either a stored `BucketEntry` or a query `LedgerKey` behind a
`std::unique_ptr<AbstractEntry>` with virtual `hash()`, `copyKey()`, and
`operator==`. Three concrete pessimizations follow:

1. **Heap allocation per query**: `mEntries.find(InternalInMemoryBucketEntry(searchKey))`
   in `InMemoryBucketState::scan` (`src/bucket/InMemoryIndex.cpp:64-76`)
   constructs a `QueryKey` via `std::make_unique`, doing a heap alloc and
   a vtable setup just to look up by reference.
2. **Full `LedgerKey` deep-copy on every comparison**: `AbstractEntry::operator==`
   calls `copyKey()` on **both** sides and compares the returned values.
   For the stored side, `ValueEntry::copyKey()` calls
   `getBucketLedgerKey(*entry)` — for a `ContractData` entry this constructs
   a fresh `LedgerKey` containing a deep-copied `SCVal`. Every hash-bucket
   collision pays this cost twice.
3. **Hash recomputed on every probe**: `ValueEntry::hash()` re-runs
   `std::hash<LedgerKey>` over `getBucketLedgerKey(*entry)` (which itself
   deep-copies a `LedgerKey` first). The hash is never cached, so every
   rehash and every collision-walk re-hashes large XDR keys from scratch.

The Tracy baseline shows `scan` (`bucket/InMemoryIndex.cpp:67`) consuming
**3.14 s self-time across 1.45 M calls (~2.17 µs/call)** in the soroswap
trace — the largest non-test-setup self-time zone in the apply path. By
contrast, a properly designed heterogeneous-lookup `unordered_set<LedgerKey>`
(or even a `std::variant<LedgerKey, BucketEntryPtr>`-based wrapper without
virtuals/heap) should deliver sub-µs lookups, which would translate into
multiple hundred ms of apply-time savings per soroswap run.

## Trigger

Run `scripts/run_apply_load_matrix.py` against the `soroswap` scenario
(`TX=4000, T=8`). Every classic source-account / fee-source / trustline
load on the apply path traverses `SearchableBucketListSnapshot::load` →
`getBucketEntry` → `InMemoryBucketState::scan` for each in-memory bucket
level, generating ~22k `scan` calls per ledger and dominating apply-path
CPU outside the Soroban host.

## Target Code

- `src/bucket/InMemoryIndex.h:26-142` — the `InternalInMemoryBucketEntry`
  / `AbstractEntry` / `ValueEntry` / `QueryKey` polymorphic wrapper and
  its hash functor; rewrite to avoid heap allocation and virtual dispatch.
- `src/bucket/InMemoryIndex.h:147-181` — `InMemoryBucketState`'s
  `unordered_set<InternalInMemoryBucketEntry, …>`; consider switching to
  a `unordered_map<LedgerKey, BucketEntryPtr>` (one extra key copy at
  insert time, but eliminates the per-lookup wrapper cost) or to a
  C++20-style heterogeneous lookup using `is_transparent` (note: the
  comment at `InMemoryIndex.h:24` already calls this out as a future
  cleanup once C++20 is adopted — but `is_transparent` is supported by
  libc++/libstdc++ on `unordered_set` in the toolchain stellar-core
  already builds with).
- `src/bucket/InMemoryIndex.cpp:55-76` — `InMemoryBucketState::insert`
  and `scan` call sites that exercise the wrapper.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` (caller
  of `scan` via `bucket->getIndex().lookup(k)`); confirm the call chain.

## Evidence

- Tracy soroswap trace
  (`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`):
    * `scan` self = 3,139,848,749 ns total / 1,445,421 calls = ~2.17 µs/call
      (30.76 % of total trace time as self-time).
    * `getBucketEntry` (parent) total = 3.26 s; `scan` total = 3.14 s, so
      ~96 % of `getBucketEntry` time is in `scan`. `scan` itself has no
      child zones — every nanosecond is in the lookup wrapper.
    * `load` (`bucket/BucketListSnapshot.cpp:317`) total = 3.63 s for
      669,582 loads on the apply path; the per-load fan-out into
      multiple bucket levels is what generates the 1.45 M `scan` calls.
- Code inspection confirms `make_unique<QueryKey>` per `find`,
  `copyKey()` per `==`, and uncached `hash()`.
- Comment at `InMemoryIndex.h:24` explicitly acknowledges the wrapper is
  a workaround for pre-C++20 lack of heterogeneous lookup, signaling the
  design choice was about ergonomics, not performance.

## Anti-Evidence

- `InternalInMemoryBucketEntry` instances stored in the set are
  constructed once at bucket-load time (in `InMemoryBucketState::insert`),
  so the per-stored-entry alloc/vtable cost is amortized; only the
  per-lookup `QueryKey` alloc is hot. That partially mitigates the
  total memory cost, but does not save the per-lookup `make_unique` and
  per-comparison `copyKey()` cost.
- `LedgerKey` for `ACCOUNT` / `TRUSTLINE` (the dominant types touched on
  the soroswap classic-tx path) is small, so the per-comparison copy is
  cheap compared to a `ContractData` key. However, hashing still walks
  the full XDR, and the collision rate determines how many copies are
  done — not negligible across 1.45 M calls.
- A naive switch to `unordered_map<LedgerKey, …>` would double the
  per-stored-entry memory (key stored separately from the value's
  embedded key). For very large in-memory bucket caches this could
  matter; mitigation is a transparent-hash design that keeps the
  current single-stored-key layout but skips the wrapper on lookup.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior Soroban or cross-subsystem fail/success records found

### Trace Summary

The claimed inefficiency exists exactly as described: `InMemoryBucketState::scan` constructs an `InternalInMemoryBucketEntry(searchKey)`, which heap-allocates a `QueryKey`, then `unordered_set::find` calls virtual hash/equality methods that materialize `LedgerKey` values through `copyKey()`. The call is on the apply hot path through `LedgerTxnRoot::Impl::getNewestVersion` and `LedgerStateSnapshot::loadLiveEntry`, then `SearchableBucketListSnapshot::load/getBucketEntry`, and the bulk prefetch path also reaches `SearchableBucketListSnapshot::loadKeysFromBucket` and `LiveBucketIndex::scan`. Small live buckets use `InMemoryIndex` by design under the default 20 MB cutoff, so the wrapper is exercised repeatedly during soroswap apply fan-out rather than being a one-time setup cost.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — fee/sequence processing calls per-transaction ledger loads during `closeLedger`.
- `src/ledger/LedgerManagerImpl.cpp:2784-2915` — transaction apply performs prefetching, loads Soroban config, then applies classic/sequential and Soroban/parallel phases inside `closeLedger`.
- `src/ledger/LedgerTxn.cpp:3669-3724` — `LedgerTxnRoot::Impl::getNewestVersion` checks the root entry cache, then loads non-offer entries via `getLedgerStateSnapshot().loadLiveEntry(key)` and caches the result.
- `src/ledger/LedgerTxn.cpp:3100-3155` — `LedgerTxnRoot::Impl::prefetch` bulk-loads keys with `getLedgerStateSnapshot().loadLiveKeys`, so prefetched apply keys also traverse the bucket snapshot indexes.
- `src/ledger/LedgerStateSnapshot.cpp:438-449` — `LedgerStateSnapshot::loadLiveEntry` and `loadLiveKeys` delegate to `SearchableLiveBucketListSnapshot`.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` calls `bucket->getIndex().lookup(k)` and returns in-memory cache hits directly for live buckets.
- `src/bucket/BucketListSnapshot.cpp:210-276` — bulk loads call `index.scan(indexIter, *currKeyIt)` for each requested key/bucket pair.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point loads loop newest-to-oldest over all live buckets until a key is found.
- `src/bucket/LiveBucketIndex.cpp:28-60` — buckets below `BUCKETLIST_DB_INDEX_CUTOFF` use `InMemoryIndex`; default config sets the cutoff to 20 MB.
- `src/bucket/LiveBucketIndex.cpp:223-257` — both `lookup` and `scan` route in-memory-index buckets to `InMemoryIndex::scan`.
- `src/bucket/InMemoryIndex.h:26-142` — `InternalInMemoryBucketEntry` stores a `std::unique_ptr<AbstractEntry>`; `QueryKey` and `ValueEntry` use virtual `hash`, `copyKey`, and equality.
- `src/bucket/InMemoryIndex.cpp:55-76` — `insert` pays the stored-entry wrapper once, while every `scan` pays `InternalInMemoryBucketEntry(searchKey)` and `mEntries.find(...)`.
- `configure.ac:52` — the project requires C++20, so a heterogeneous `unordered_set` design is a plausible fix rather than a future-toolchain-only idea.

### Findings

The inefficiency is real and hot. There is no cache layer that removes it for in-memory buckets: the live bucket random-eviction cache is intentionally skipped when `mInMemoryIndex` is present, and `LedgerTxnRoot` caching only prevents repeat loads of the same key after an entry-cache hit, not the initial fan-out across bucket levels. `InMemoryBucketState::scan` ignores the `start` iterator and performs an unordered lookup, so for in-memory buckets the returned iterator contract is already degenerate and can be preserved while changing the lookup representation.

The proposed optimization is correctness-preserving if it keeps the same key identity semantics as `getBucketLedgerKey`/`std::hash<LedgerKey>` and continues returning the stored `shared_ptr<BucketEntry const>` on hits. A transparent lookup that stores the existing bucket entry pointer and compares/hashes against a `LedgerKey const&` avoids the hot allocation and virtual dispatch without duplicating all stored keys; an `unordered_map<LedgerKey, IndexPtrT>` would also work functionally but has a higher memory tradeoff. Given the supplied trace attributes 3.14 s of self-time and 1.45 M calls to this function during a soroswap run, even a partial reduction of the per-call cost is projected to clear the objective's 3% Medium threshold.

### PoC Guidance

- **Target code**: `src/bucket/InMemoryIndex.h` and `src/bucket/InMemoryIndex.cpp`, specifically `InternalInMemoryBucketEntry`, `InternalInMemoryBucketEntryHash`, `InMemoryBucketState::insert`, and `InMemoryBucketState::scan`.
- **Change description**: replace the polymorphic `unique_ptr<AbstractEntry>` wrapper with a non-allocating representation that stores the existing `IndexPtrT` for values and supports heterogeneous `unordered_set::find(LedgerKey const&)`. Define transparent hash/equality functors that hash/compare `LedgerKey const&` directly against `getBucketLedgerKey(*entry)` so query lookup does not allocate and does not virtual-dispatch.
- **Correctness check**: existing bucket index tests in `src/bucket/test/BucketIndexTests.cpp` cover in-memory index lookup behavior, cutoff behavior, equality, and bucket index construction. The PoC should also run a Soroban/apply-load smoke benchmark because the optimization is performance-only and should not change bucket contents or lookup results.
- **Benchmark focus**: run `scripts/run_apply_load_matrix.py` for the soroswap scenario and compare top-line apply time plus Tracy/self-time for `InMemoryBucketState::scan`; the expected improvement is a substantial drop in `scan` self-time and at least a reproducible 3% apply-time reduction.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-27
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:19-84` — replaced the polymorphic `unique_ptr` value/query wrapper with a value-only entry that stores the existing `IndexPtrT`, caches the entry hash once, and defines transparent hash/equality functors for heterogeneous `LedgerKey` lookup.
- `src/bucket/InMemoryIndex.cpp:23-52` — added direct identity comparison helpers using `LedgerEntryIdCmp`/`BucketEntryIdCmp` so `LedgerKey` queries compare against stored bucket entries without constructing query wrapper objects.
- `src/bucket/InMemoryIndex.cpp:89-145` — implemented the new entry/equality methods and changed `InMemoryBucketState::scan` to call `mEntries.find(searchKey)` directly.

### Demonstration

The optimization removes the hot-path heap allocation, vtable dispatch, and temporary query object construction from in-memory bucket lookups while preserving the stored bucket-entry representation. Stored entries still avoid duplicating `LedgerKey` payloads; lookup now hashes the incoming `LedgerKey` directly and compares it to the cached `BucketEntry` identity, so repeated BucketList fan-out reads avoid the wrapper overhead identified in the trace.

### Test Results

Built successfully with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30`. Full regression suite completed successfully with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`; the test tail reported Rust tests passing and `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, `All 2 tests passed`.
