# H007: Replace per-load `mPointTimers.find(LedgerEntryType)` UnorderedMap lookup + `SimpleTimer::Update` mutex with a fixed-size per-type array on the `BucketListSnapshot::load` hot path

**Date**: 2026-05-02
**Subsystem**: bucket / util
**Severity**: Low (sub-medium)
**Impact**: Apply-time reduction in the per-load timer-instrumentation overhead
**Hypothesis by**: claude-opus-4.7, low

## Expected Behavior

Instrumentation overhead on `SearchableBucketListSnapshot::load` should be
zero or near-zero per load. The zone wraps every individual key load on the
soroban storage path; the timer accounting machinery itself should not
contribute measurable CPU. Specifically, looking up which `SimpleTimer`
to update should be O(1) array index (LedgerEntryType is a tiny enum with
~7 values), and updating the timer's max-tracking should not require a
`std::mutex` acquisition (a `std::atomic<int64_t>` CAS loop would suffice
for the rarely-changing `mMax` field).

## Mechanism

Each `BucketListSnapshot::load(k)` call enters two layers of
instrumentation before doing real work:

1. `mPointTimers.find(k.type())` against an `UnorderedMap<LedgerEntryType,
   SimpleTimer>` to pick the correct per-type timer. This is a hash + bucket
   walk for every load, even though `LedgerEntryType` is a small enum where
   a `std::array<SimpleTimer, NUM_LEDGER_ENTRY_TYPES>` would be O(1).
2. A `TimeScope` RAII object that records `Clock::now()` at construction
   and at destruction, then calls `SimpleTimer::Update(elapsed)`. `Update`
   atomically increments a count + sum, then takes a
   `std::lock_guard<std::mutex>` to update `mMax` (only ever touched on
   `cur > current_max`).

For the soroswap trace, `BucketListSnapshot::load` runs ~509 k times. The
per-call overhead is ~30 ns for the hash-map lookup + ~50–80 ns for the
mutex acquisition (uncontended) + RAII setup/teardown ≈ 110–150 ns/call.
Total CPU savings if both are eliminated: ~60–80 ms aggregated across
worker threads.

## Trigger

Run soroswap apply-load matrix; inspect Tracy zone `load`
(`bucket/BucketListSnapshot.cpp:313`) self-time and call count.

## Target Code

- `src/bucket/BucketListSnapshot.cpp:313-346` — `load`; per-call
  `mPointTimers.find` + `TimeScope` instrumentation.
- `src/bucket/BucketListSnapshot.h` — `mPointTimers` member; would change
  from `std::unordered_map<LedgerEntryType, SimpleTimer>` to
  `std::array<SimpleTimer, NUM_LEDGER_ENTRY_TYPES>` indexed by enum value.
- `src/util/SimpleTimer.h:1-80` and `src/util/SimpleTimer.cpp` — `Update`;
  the `std::mutex` for `mMax` would become a CAS loop on `std::atomic<int64_t>`.

## Evidence

- Tracy trace `…02-soroswap-tx-2000-t-8.tracy`, csvexport-release -e
  output: the `load` zone is invoked ~509 k times in the soroswap trace
  and ~622 k times in the SAC trace.
- `SimpleTimer::Update` (`src/util/SimpleTimer.cpp`) currently uses a
  `std::lock_guard<std::mutex>` to maintain `mMax`. Even uncontended,
  acquiring a `std::mutex` costs ~25–50 ns plus a memory barrier.
- `std::unordered_map::find` for a small fixed key set is ~20–40 ns
  per call vs. a single load+index for an array lookup.
- Existing pattern: `InternalInMemoryBucketEntry::mHash` is precomputed
  once (line 200) precisely because per-call hashing on small key sets is
  measurable. The same logic applies to the per-type timer dispatch.

## Anti-Evidence

- Total CPU saving estimate: 509 k loads × ~150 ns = **76 ms** aggregated
  across worker threads. With NUM_CLUSTERS=8 and 70 ledgers in the trace,
  that's `76 ms ÷ 8 ÷ 70 ≈ **0.14 ms/ledger** ≈ **0.05 %** of the 278 ms
  soroswap baseline. Three orders of magnitude below the 3 % Medium floor
  and well below the 1 % Low noise floor.
- The `mMax` mutex is uncontended in practice: `mMax` is only updated on
  the (rare) `cur > current_max` path inside the lock. The lock acquisition
  itself happens unconditionally, but its cost is ~50 ns even uncontended,
  amortized over ~509 k loads = 25 ms.
- Fail #007 (`bucket-pointload-histogram-mutex-contention`) already
  documented that the medida histogram path was replaced with `SimpleTimer`
  to remove a much larger contention problem. The remaining `mMax` lock
  is what's left after that optimization landed; it is structurally smaller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — distinct from fail #007 (which targeted the medida
histogram already replaced) by targeting the residual `SimpleTimer` cost
post-conversion.

### Why It Failed

Per-load `BucketListSnapshot::load` instrumentation overhead aggregates
to ~76 ms total CPU across the 70-ledger soroswap trace, i.e.
~0.14 ms/ledger ≈ 0.05 % of the 278 ms baseline. This is two orders of
magnitude below the Medium 3 % threshold and below benchmark noise.
Replacing the `UnorderedMap` with a fixed-size array and the
`std::mutex` with a `std::atomic` CAS would be a clean refactor on its
own merits, but the optimize-soroswap objective only accepts Medium and
High severity hypotheses (Low and sub-1 % are explicitly rejected at the
hypothesis stage).

### Lesson Learned

The `SimpleTimer` per-load instrumentation in `BucketListSnapshot::load`
is below Medium threshold even with optimistic per-call cost assumptions.
Future apply-path-instrumentation hypotheses should multiply
(per-call ns saving × call count) before writing — and only proceed if
the wall-clock per-ledger saving (after dividing by NUM_CLUSTERS=8 for
parallel-apply paths) exceeds ~8 ms (3 % of 278 ms).
