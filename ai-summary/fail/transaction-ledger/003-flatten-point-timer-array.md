# H003: Replace `BucketListSnapshot::mPointTimers` UnorderedMap With `std::array` Indexed By LedgerEntryType

**Date**: 2026-05-03
**Subsystem**: transaction-ledger (bucket lookup hot path)
**Severity**: Low
**Impact**: Per-call overhead in `BucketListSnapshot::load`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketListSnapshot::load` (`src/bucket/BucketListSnapshot.cpp:315`) is called
on the order of 521 k times per soroswap trace. The per-entry-type `medida`
point timer it scopes should be selected via O(1) indexed array access keyed
by `LedgerEntryType` enum value, not via a hash-based
`UnorderedMap<LedgerEntryType, ...>::find` (which incurs hashing, bucket walk,
and at minimum one cache miss per call).

## Mechanism

`mPointTimers.find(k.type())` runs on every single point load. With
`LedgerEntryType` being a small dense enum (8 values in current protocol), an
`std::array<medida::Timer*, NUM_LEDGER_ENTRY_TYPES>` would be a single load
instruction instead of a hash + probe + dereference. The proposed change is a
trivial structural swap of the storage container plus an enum-to-index helper.

## Trigger

Any apply-load run; soroswap exercises the `load` path most heavily because
of per-tx classic key reads from `mLCLSnapshot`.

## Target Code

- `src/bucket/BucketListSnapshot.h` — `mPointTimers` member declaration
- `src/bucket/BucketListSnapshot.cpp:315` — `load` (where `find` is called)
- `src/bucket/BucketListSnapshotBase` constructor — where the map is
  populated; trivially convertible to populating an array slot per enum
  value.

## Evidence

- `load` count = 521 k in the soroswap trace.
- An `UnorderedMap` lookup costs roughly 50–200 ns vs. ~5 ns for an indexed
  array dereference. Upper-bound saving: 521 k × 200 ns = ~104 ms aggregate
  Tracy total.

## Anti-Evidence

- Aggregate saving 104 ms ÷ 8 clusters ÷ 71 ledgers ≈ 0.18 ms/ledger ≈
  **0.07%** of the 272 ms median apply window.
- The 521 k count is across the whole trace, including 320k+ calls outside
  `applyLedger` (TX-set construction validates the same source accounts).
  Apply-window-only `load` calls per H010 are ~107 ms total for the whole
  body of work; the proposed micro-optimization can recover at most a
  fraction of a single millisecond per ledger.
- `mPointTimers` lookup is inside a `medida::TimerContext` scope that itself
  costs more than the map find; the find is not the dominant per-call cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from prior bucket
hypotheses which targeted scan/getBucketEntry rather than the timer container.

### Why It Failed

Below objective severity threshold. Best-case saving ≈ 0.07% of apply window;
well under the 1% benchmark noise floor and an order of magnitude below the
3% Medium threshold. The map-find cost is also subordinate to the
`medida::TimerContext` construction it sits inside, so even eliminating the
find entirely wouldn't recover the full theoretical saving.

### Lesson Learned

Per-call container-flavor micro-optimizations on `BucketListSnapshot::load`
are hard-bounded by the apply-window-only call count, which is small
(~107 ms total, per H010). Any future `load`-targeting hypothesis must
address the actual bucket traversal (`scan` / `getBucketEntry`) at scale,
not its surrounding instrumentation.
