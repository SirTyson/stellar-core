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
