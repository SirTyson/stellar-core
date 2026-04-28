# H014: Replace BucketEntryCounters std::map with std::array<size_t, NUM_TYPES>

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / bucket utilities
**Severity**: Low
**Impact**: Allocation/copy overhead in per-ledger counter aggregation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketEntryCounters` aggregates per-bucket entry counts and sizes by
`LedgerEntryTypeAndDurability`. The set of keys is a fixed small enum
(currently 10 values), so the data structure should be a contiguous
`std::array<size_t, NUM_TYPES>` (or equivalently a tiny POD struct) with no
heap allocation, O(1) lookup, and trivial value-copy / `operator+=`. The
serialize/deserialize path should round-trip the same on-disk and protocol
representation as today.

## Mechanism

Today `BucketEntryCounters` (`src/bucket/BucketUtils.h:197-216`) holds two
`std::map<LedgerEntryTypeAndDurability, size_t>` fields. Every
`sumBucketEntryCounters` walk constructs an empty `BucketEntryCounters`,
calls `operator+=` on each bucket's counters (each `+=` iterates two
`std::map`s — `src/bucket/BucketUtils.cpp:339-351`), and returns the
result by value. Each ledger's reporting path also returns the aggregated
`BucketEntryCounters` by value to the caller. Replacing the maps with
contiguous arrays would eliminate per-walk red-black-tree node allocations
and the full-map value-copy on return, plus give better cache locality.

## Trigger

Run the soroswap apply-load benchmark using the trace at
`/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`.
The map-based counters are exercised once per ledger close inside
`maybeInitializeCaches` and `reportBucketEntryCountMetrics`, plus at index
build time during background bucket merges.

## Target Code

- `src/bucket/BucketUtils.h:197-216` — `BucketEntryCounters` definition with two `std::map`s.
- `src/bucket/BucketUtils.cpp:326-387` — `operator+=`, `operator==`, `markEntry` and the cereal/XDR serialize hooks.
- `src/bucket/LiveBucketList.cpp:14-68` — `sumBucketEntryCounters` returns by value.
- `src/bucket/BucketManager.cpp:1930-1963` — second `sumBucketEntryCounters` invocation.

## Evidence

`std::map` of 10 enum keys is structurally wasteful: each insert allocates
a tree node; copy-on-return duplicates the entire tree; iteration is
pointer-chasing. The struct is a tight per-bucket aggregate exercised on
every ledger close and every background merge, so the constant factor
matters in principle.

## Anti-Evidence

- Tracy self-time of the consuming functions (`addLiveBatch` 7.5 µs/call,
  `addBatch` 13 µs/call) shows that the entire counter-aggregation cost
  per ledger is under 100 µs — most of that is in the subprocess calls
  themselves, not in `std::map` iteration.
- `BucketEntryCounters` participates in the on-disk index format and the
  XDR protocol surface (cereal `serialize` + XDR conversion). Changing the
  in-memory representation requires preserving the wire format exactly,
  including iteration order; even a "drop-in" array swap requires custom
  serialize logic that converts to the `std::map` form on the wire,
  negating any allocation savings on the hot path that touches
  serialize.
- The same counters are also rebuilt at index-build time during bucket
  merges, which run on background threads and are out of scope for the
  apply window per the objective's bucket-merge guidance.
- Best-case projected apply-time savings: <0.05% (well below the 3%
  Medium severity floor and below the 1% benchmark noise floor).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — prior bucket-related failures targeted async addLiveBatch
(001-async-addlivebatch) and InMemoryIndex polymorphic scan
(001-eliminate-polymorphic-scan); the in-memory representation of
`BucketEntryCounters` itself has not been investigated.

### Why It Failed

The `std::map` cost only matters in proportion to how often the maps are
iterated/copied on the apply path. Self-time profiling shows the entire
addLiveBatch reporting/counter-aggregation path consumes well under
100 µs of apply window per benchmark run (≈0.02% of 596 ms baseline) —
two orders of magnitude below the 3% Medium threshold and below the 1%
noise floor. Additionally, `BucketEntryCounters` participates in the
on-disk index format and the XDR protocol surface, so an array-based
in-memory representation must still serialize to the existing map form,
which forces an internal conversion that erases most of the projected
allocation savings.

### Lesson Learned

Tight per-element data-structure micro-optimizations are only worth
pursuing when (a) the structure is hot enough that copy/allocation cost
shows up in self-time, and (b) it is not pinned by an external
serialization contract. Both gates must be checked before opening a
hypothesis on a "wrong container choice" angle.
