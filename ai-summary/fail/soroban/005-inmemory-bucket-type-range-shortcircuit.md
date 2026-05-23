# H005: Short-circuit `LiveBucketIndex::lookup` Using `mTypeRanges` Before `InMemoryIndex::scan`

**Date**: 2026-05-23
**Subsystem**: bucket (soroban-adjacent)
**Severity**: Low
**Impact**: apply-time reduction via fewer hashtable probes
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucketIndex::lookup(k)` should avoid hashing/probing the in-memory
hashtable when the bucket provably contains zero entries of the
queried `LedgerEntryType`. `InMemoryIndex` already tracks per-type
key-offset ranges in `mTypeRanges` (used by `scanForEviction` and disk
range queries); a constant-time absence check would let `lookup` early-out
without paying the ~1.5–2.5µs `unordered_set::find` cost.

## Mechanism

`LiveBucketIndex::lookup` unconditionally delegates to
`mInMemoryIndex->scan(...)`, which calls `mInMemoryState.scan(searchKey)`
performing a hash + `unordered_set` probe regardless of whether the bucket
holds any entries of that type. For soroswap apply, the `scan` zone shows
21.83% of Tracy trace time across 956k calls (mean 2.3µs). Many in-memory
buckets that get probed during source-account loads (`processFeesSeqNums`)
or during worker-thread classic-entry fetches contain only soroban
contract-data/contract-code entries and no ACCOUNT/TRUSTLINE entries.
A `mTypeRanges`-based short-circuit would skip the hash+probe for
type-absent buckets.

## Trigger

Run `apply-load` soroswap. The pre-apply serial `processFeesSeqNums` phase
plus worker-thread classic loads cumulatively pay ~2.2s of `InMemoryIndex::scan`
across the trace.

## Target Code

- `src/bucket/LiveBucketIndex.cpp::lookup:220-310` — delegates to
  `mInMemoryIndex->scan` without consulting type metadata
- `src/bucket/InMemoryIndex.h::scan:162-166` — forwards to `mInMemoryState.scan`
- `src/bucket/InMemoryIndex.h` `mTypeRanges` — already maintained per-type

## Evidence

- `scan` is the #1 in-scope self-time zone at 21.83% of trace.
- `mTypeRanges` already exists, populated in the index constructor.
- `getRangeForType` is the existing public accessor.
- Soroswap workload has many "soroban-only" buckets where ACCOUNT lookups
  are guaranteed misses.

## Anti-Evidence

- The `unordered_set::find` body is genuinely ~1µs in production; Tracy
  `ZoneScoped` overhead inflates it ~50-100% in instrumented builds.
- `processFeesSeqNums` self-time is only 1.58% of trace, suggesting most
  `scan` calls do NOT come from the serial pre-apply phase but from worker
  threads where they are parallel (÷8 to wall clock).
- The `mLatestLiveEntryCache` already short-circuits repeated hot keys per
  bucket.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PARTIAL — covered by meta-pattern 25 / fail 029
  (`inmemory-index-bloom-filter`); type-range short-circuit is functionally
  equivalent (cheaper absence check) and shares the same sizing problem.

### Why It Failed

Prior investigation (fail 029, bloom filter for `InMemoryIndex`) established
that `scan`'s Tracy self-time is heavily inflated by `ZoneScoped` overhead
because each scan body is sub-µs in production. The type-range short-circuit
is structurally the same optimization: replace a fast hashtable probe with
an even faster constant-time absence check. After correcting for:

1. `ZoneScoped` overhead removal in production builds (~30-40% of measured cost),
2. 8-worker normalization for the parallel portion (most `scan` calls during
   worker apply),
3. The fact that `mLatestLiveEntryCache` already handles repeated hot keys,

the projected wall-clock saving is well below the 1% noise floor and far
below the Medium 3% threshold for this objective.

### Lesson Learned

Any optimization targeting `InMemoryIndex::scan` (bloom filter, type-range
short-circuit, alternative hashtable) is bounded by Tracy ZoneScoped
overhead in the measurement and by the ÷8 worker normalization. To move
the needle measurably, the cost must come from a SERIAL phase (e.g.,
`processFeesSeqNums` or a single-threaded pre-apply step), not from
worker-parallel apply.
