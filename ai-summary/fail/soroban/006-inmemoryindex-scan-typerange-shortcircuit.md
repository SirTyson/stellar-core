# H006: Type-range short-circuit in `InMemoryIndex::scan`

**Date**: 2025-12-03
**Subsystem**: soroban (bucket subsystem, affects soroswap apply)
**Severity**: Low (rejected: below objective Medium threshold)
**Impact**: bucket lookup CPU during serial apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `InMemoryIndex::scan(searchKey)` is called for a `LedgerKey` whose
`type()` is **absent from this bucket** (the bucket contains no entries of
that ledger-entry type), the scan SHOULD return immediately without
performing any hash computation or hash-table lookup, because the answer
is known to be "not present" purely from the type alone.

`InMemoryIndex` already maintains a member `mTypeRanges`
(`std::map<LedgerEntryType, std::pair<streamoff,streamoff>>`, populated
by both the in-memory and disk constructors in
`src/bucket/InMemoryIndex.cpp` lines 264 and 305). The expected fast
path is:

```cpp
auto it = mTypeRanges.find(searchKey.type());
if (it == mTypeRanges.end())
    return { IndexReturnT(), mInMemoryState.end() };
// fall through to existing hash-lookup path
```

## Mechanism

`InMemoryIndex::scan` (`src/bucket/InMemoryIndex.h:162-166`) delegates
straight to `InMemoryBucketState::scan` (`InMemoryIndex.cpp:250-262`),
which constructs a `BucketEntry` shim and does an
`std::unordered_set::find` requiring a full `std::hash<LedgerKey>` over
the key (and for `CONTRACT_DATA`, the more expensive
`xdrComputeHash`). For any bucket that does not contain entries of the
searched type, the hash-lookup is wasted work: an `mTypeRanges`
membership check would be ~10ns versus the hash+probe at ~2300ns mean
(observed in the trace, `scan` self-time 2347ns/call mean).

The deviation from expected behavior: the scan does the full work even
when a single map probe would prove non-presence.

## Trigger

Soroswap benchmark `closeLedger` flow. The serial apply phase performs
classic ledger-entry lookups for fee processing and prefetch:

- `prefetchTxSourceIds` (`processFeesSeqNums` upstream): one
  `ACCOUNT`-key bucket walk per tx source.
- `prefetchTransactionData`: walks for footprint-listed classic keys
  (empty for pure-Soroban soroswap tx-set).
- `preParallelApply`: classic side-effect loads.

Each walk iterates ~22 live-bucket levels. Levels that contain only
`CONTRACT_DATA` / `CONTRACT_CODE` / `TTL` (typical for lower levels of
a Soroban-heavy mainnet snapshot) would short-circuit immediately
instead of doing the hash probe.

## Target Code

- `src/bucket/InMemoryIndex.h:162-166` — `InMemoryIndex::scan` inline
  delegates without type-range check
- `src/bucket/InMemoryIndex.cpp:250-262` — `InMemoryBucketState::scan`
  hash-table probe
- `src/bucket/InMemoryIndex.cpp:264-302` — in-memory ctor populates
  `mTypeRanges` via `updateTypeBoundaries`
- `src/bucket/InMemoryIndex.cpp:305-345` — disk ctor populates
  `mTypeRanges`
- `src/bucket/LiveBucketIndex.cpp:238` — `LiveBucketIndex::lookup`
  caller
- `src/bucket/LiveBucketIndex.cpp:256` — `LiveBucketIndex::scan` caller

## Evidence

- `scan` (InMemoryIndex.cpp:253) is the single largest self-time zone
  in the trace at **21.8%** with 956,502 calls × 2347ns mean.
- `mTypeRanges` is already maintained — no new bookkeeping needed.
- The existing `LiveBucketIndex::scan` path already supports a separate
  "lower/upper-bound" range parameter, so type-bound short-circuiting
  is structurally aligned with existing design.
- Prior success #1 (`001-inmemory-bucket-scan-polymorphic-wrapper.md`)
  trimmed per-call overhead but did NOT add this short-circuit.

## Anti-Evidence

- The dominant share of `scan`'s 21.8% trace self-time is in **TX-set
  construction** zones (`commonValidPreSeqNum`, `verifySig` paths),
  NOT inside `applyLedger`. See the OUT_OF_SCOPE and Tracy Trap notes
  in the objective skill.
- `mTypeRanges.find` itself adds a constant-time `std::map` walk
  (red-black tree, ~5-10ns) even on the cache hit path; for hot
  in-cache types like `ACCOUNT`, this adds overhead without saving
  anything.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2025-12-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Apply-window bucket-scan cost is well below the Medium threshold (3%):

1. **Most scan calls are in TX-set construction (out of scope).** The
   trace's 21.8% `scan` self-time is dominated by `commonValidPreSeqNum`
   (66% trace) and `verifySig` (50% trace) call sites, both of which
   are explicit Tracy Traps per the skill and live outside `applyLedger`.

2. **In-apply scan share is small.** The serial apply zones that
   actually invoke bucket scans are:
   - `prefetchTxSourceIds`: 53.6ms total / 71 ledgers = ~745µs/ledger
     = 0.34% apply
   - `prefetchTransactionData`: 118.5ms total / 71 = ~1.62ms/ledger
     = 0.74% apply (but most footprint keys are Soroban → no scan
     after meta-pattern 2)
   - `preParallelApply`: ~2.46ms/ledger = 1.13% apply (only a fraction
     is bucket scan; most is classic side-effect plumbing)
   - `processFeesSeqNums`: bucket scans largely cache-hit because
     prefetch ran first

   Upper bound on apply-window scan cost: ~3-5ms/ledger ≈ 1.4-2.3% of
   apply.

3. **Parallel-apply normalization further deflates parallel-side
   savings.** Any classic loads inside parallel Soroban apply are
   normalized by 4.18× effective parallelism (per CPU vs wall in
   `applySorobanStageClustersInParallel`), so even an in-cluster scan
   reduction returns ~24% of its raw saving as wall-time.

4. **Type-range hit rate is moderate, not 100%.** Soroswap-heavy levels
   contain a mix of `CONTRACT_DATA`, `CONTRACT_CODE`, `TTL`, and
   `ACCOUNT` entries; only the lowest levels (oldest data) are
   purely-classic or purely-Soroban. Realistic short-circuit rate per
   classic-account walk: 30-50% of the 22 bucket levels. Realistic
   savings: 0.5-1.1% apply, below the 1% noise floor.

5. **Adjacent rejection.** `ai-summary/fail/ledger/summary.md` entry
   `007-thread-cached-key-hash-into-inmemory-bucket-scan.md` rejected a
   nearby BucketList-lookup optimization, citing that "Soroban
   footprint reads in parallel apply do not probe every live bucket
   level through `InMemoryBucketState::scan`; they use
   `InMemorySorobanState`". Confirms the classic-only attack surface
   is even narrower than my upper bound.

Projected apply-time impact: **0.5-1.5% (Low)**, well below the
objective's 3% Medium minimum.

### Lesson Learned

The dominant trace zone is not the dominant apply-window zone. Always
back out the **in-`applyLedger` share** of a hot zone before drafting
a hypothesis: subtract TX-set construction call sites and normalize
parallel-zone wins by `total_cpu / wall` (effective parallelism). For
bucket scan specifically, the in-apply ceiling is ~2% — type-range
short-circuit is structurally sound but cannot clear Medium.
