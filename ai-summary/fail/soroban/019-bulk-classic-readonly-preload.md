# H019: Bulk-resolve classic readonly footprint preload via single BucketListSnapshot loadKeys call

**Date**: 2026-04-30
**Subsystem**: soroban / ledger
**Severity**: Low
**Impact**: Reduce per-key bucket scans during sequential preload prior to parallel apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState::collectModifiedClassicEntries`
(`src/transactions/ParallelApplyUtils.cpp:600-644`) walks the union of
classic-footprint keys for the entire stage and resolves each key against
the current `LedgerTxn` parent chain. For N unique classic keys, the
sequential preload should require O(N) total work — one logical lookup
per unique key — and not redo any per-key bucket-level scan beyond the
first hit.

Conceptually a single bulk call into `BucketListSnapshot::loadKeys(keys)`
should be cheaper than N point lookups when N is large, because the bucket
list can be walked once and intersected with the key set instead of being
re-walked per key.

## Mechanism

Today each unique classic key calls `ltx.getNewestVersionBelowRoot(lk)`,
which falls through `LedgerTxn` parents and eventually into
`BucketListSnapshot::load(k)` for misses
(`src/bucket/BucketListSnapshot.cpp:315`). That function loops up to 22
bucket levels and calls `index.scan(iter, k)` per level. For the
soroswap workload the InMemoryIndex variant of `scan`
(`src/bucket/InMemoryIndex.cpp:253`) ignores the iterator and does a
plain `mEntries.find(searchKey)` hash-map lookup — there is no scanning
state shared across keys that a bulk call could amortize.

I traced `loadKeysFromBucket` (`src/bucket/BucketListSnapshot.cpp:210`)
and confirmed it also calls `index.scan(iter, key)` per key per bucket
internally. So bulk vs per-key has identical algorithmic complexity for
in-memory buckets (which dominate the soroswap workload — buckets ≤20MB
use `InMemoryIndex` per `BUCKETLIST_DB_INDEX_CUTOFF`).

## Trigger

Run soroswap apply-load. Per-ledger preload performs ~22 levels × ~1k
unique classic keys = ~22k InMemoryIndex hash lookups. Each lookup is
sub-microsecond. Total preload work is in the low-single-digit milliseconds
per ledger — well under the 1% benchmark-noise floor.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:600-644` — `collectModifiedClassicEntries`
- `src/bucket/BucketListSnapshot.cpp:315` — `BucketListSnapshot::load`
- `src/bucket/BucketListSnapshot.cpp:210` — `loadKeysFromBucket`
- `src/bucket/InMemoryIndex.cpp:253` — `InMemoryIndex::scan` (single-key)

## Evidence

`load` zone Tracy total: 212ms (2.06%) over 509718 calls = 0.4µs/call.
That is the *post*-LedgerTxn-miss bucket cost across ALL apply-thread
loads (not just preload). The preload-attributable share is a small
fraction of this.

## Anti-Evidence

`InMemoryBucketState::scan` is already a single hash-map lookup (per
success #1). There is no shared traversal state to amortize across keys
in a bulk loader for in-memory buckets, so a bulk API would just be a
loop over the same per-key lookups with an extra layer of indirection.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a fail/hypothesis/poc record

### Why It Failed

For the soroswap workload all classic-footprint reads terminate at
`InMemoryIndex` buckets (≤20MB, success #1 made these O(1) hash lookups).
A bulk API has no algorithmic win over the existing per-key path: both
internally call `mEntries.find` per key per bucket level. The realistic
ceiling is sub-1% even before accounting for the bulk-API overhead of
allocating a temporary key-set and per-bucket result merging. Below the
objective severity threshold (Low not accepted at hypothesis stage).

### Lesson Learned

After success #1 (InMemoryBucketState polymorphic wrapper), per-key vs
bulk bucket lookups are algorithmically equivalent for in-memory buckets.
Bulk-loader hypotheses must target only the disk-index path
(`>BUCKETLIST_DB_INDEX_CUTOFF` buckets) — and the soroswap apply path
rarely hits that path because hot soroban entries are served from
`InMemorySorobanState` rather than from `BucketListSnapshot`.
