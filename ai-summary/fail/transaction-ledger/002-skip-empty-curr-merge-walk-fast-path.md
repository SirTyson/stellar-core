# H002: Skip merge walk in `mergeInMemory` when curr is empty (level-0 fast path)

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (bucket / apply)
**Severity**: Low (sub-threshold)
**Impact**: apply-time reduction (avoid redundant merge over empty curr)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketListBase<LiveBucket>::prepareFirstLevel`
(`src/bucket/BucketListBase.cpp:193-238`) decides between two paths when
producing the new level-0 curr from this ledger's init/live/dead entries:

1. If `shouldMergeWithEmptyCurr` is true (the existing curr is empty, e.g.
   because it was just snapped), the code first calls
   `LiveBucket::freshInMemoryOnly(init, live, dead)` to build a "snap" bucket
   from the new entries, then calls
   `LiveBucket::mergeInMemory(emptyCurr, snap, ...)` to produce the new
   curr.
2. Otherwise it calls `mergeInMemory(curr, snap, ...)` with a non-empty curr.

In path (1), `mergeInMemory(empty, snap, ...)` is semantically equivalent to
`snap` itself — the merge walk over an empty curr just re-emits every entry
from snap. The expected optimization is to skip the redundant
`mergeInMemory` call in path (1) and either (a) return the `freshInMemoryOnly`
snap bucket directly as the new curr, or (b) build a single "fresh curr"
bucket that goes straight to disk via one output-iterator pass instead of
two (`freshInMemoryOnly` then `mergeInMemory`).

## Mechanism

When `shouldMergeWithEmptyCurr` is true, the current code performs
`freshInMemoryOnly` (sorts + builds in-memory snap) and then immediately
performs `mergeInMemory(empty_curr, snap, ...)` which walks every entry in
snap and re-writes it via a fresh `BucketOutputIterator`. The merge walk is
linear in the entry count and produces a result identical (up to
representation) to snap itself. The actual deviation from expected behaviour
is that the apply thread spends `mergeInMemory` time doing zero-information
work: the input is empty, the output is the snap entries.

## Trigger

Run the soroswap apply-load benchmark; profile with Tracy; count how many of
the 73 `mergeInMemory` zone calls were taken with `shouldMergeWithEmptyCurr`
returning true.

## Target Code

- `src/bucket/BucketListBase.cpp:193-238` —
  `prepareFirstLevel<LiveBucket>`: the branch that calls
  `freshInMemoryOnly` then `mergeInMemory(empty_curr, snap, ...)`.
- `src/bucket/LiveBucket.cpp:613-528` — `mergeInMemory`: the merge walk
  whose work is redundant when curr is empty.
- `src/bucket/LiveBucket.cpp:530-562` — `freshInMemoryOnly`: the
  "shell-bucket" path that already returns an in-memory-only bucket.

## Evidence

- Tracy CSV (`/tmp/soroswap_self.csv`):
  - `freshInMemoryOnly@bucket/LiveBucket.cpp:538` = 483µs / 73 = 6.6µs/ledger
  - `mergeInMemory@bucket/LiveBucket.cpp:621` envelope = 3.04ms / 73 =
    41.7µs/ledger
  - `mergeInMemory merge@bucket/LiveBucket.cpp:655` = 20.9ms / 73 =
    286µs/ledger (the inner merge walk)
  - `mergeInMemory put loop@bucket/LiveBucket.cpp:678` = 2.85ms / 73 =
    39µs/ledger
- Comment in `freshInMemoryOnly` (line 557-559) confirms the intent of a
  cheaper in-memory-only path that "forgo[es] the expensive
  `BucketOutputIterator` construction".

## Anti-Evidence

- `mergeInMemory` produces a disk-backed `LiveBucket` (via
  `out.getBucket(...)`), required for crash recovery and for future
  `FutureBucket` higher-level merges. `freshInMemoryOnly` deliberately
  *does not* produce a disk-backed bucket. So skipping the
  `mergeInMemory` step means the level-0 curr would not be persisted; this
  is a correctness/durability regression that cannot be accepted as-is.
  A correct version of the optimization would have to build a fresh
  on-disk bucket from the snap entries via a SINGLE output-iterator pass
  (replacing both `freshInMemoryOnly` and `mergeInMemory`), not skip the
  disk write.
- The semantic equivalence claim — that `mergeInMemory(empty, snap)`
  produces the same bucket as `snap` — only holds if both sides agree on
  shadow handling, init/live promotion, and tombstone elision. The
  merge-walk logic does additional `maybe_drop` work that
  `freshInMemoryOnly` does not duplicate.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — neither "shouldMergeWithEmptyCurr fast path" nor
"empty-curr merge skip" appears in `summary.md` (verified via grep for
`shouldMergeWith`, `empty curr`, `freshInMemoryOnly`, `prepareFirstLevel`).

### Why It Failed

Two independent reasons:

1. **Sub-threshold magnitude.** Tracy CSV measures `mergeInMemory` (envelope
   zone) at 41.7µs/ledger and the inner `mergeInMemory merge` zone at
   286µs/ledger on the apply path. Even the optimistic ceiling — eliminating
   the entire `mergeInMemory` envelope on every ledger — caps at
   ~327µs/ledger = **0.16% of the 211ms soroswap baseline**. That is two
   orders of magnitude below the Medium (3%) threshold and well below the
   1% benchmark-noise floor. Realistic savings (only the fraction of ledgers
   where `shouldMergeWithEmptyCurr` is true) are smaller still.

2. **Disk-durability requirement.** Returning the `freshInMemoryOnly`
   in-memory shell bucket directly skips the on-disk write that
   `mergeInMemory` performs via `BucketOutputIterator::getBucket`. The
   level-0 curr MUST be persisted (it is referenced by `bucketListHash` and
   needed for crash recovery + higher-level `FutureBucket` merges that
   consume it as a disk reader). A correct variant would have to fold
   `freshInMemoryOnly` + `mergeInMemory` into a single
   in-memory-build-and-write pass, which is a real refactor — but the
   magnitude analysis above rules out the savings being worth the
   refactor's risk.

### Lesson Learned

Bucket-merge level-0 work on the soroswap apply path is bounded above by
~2.1% (whole `addLiveBatch` ≈ 4.5ms/ledger), and individual sub-zones inside
`prepareFirstLevel` / `mergeInMemory` are sub-1%. Future optimization
hypotheses in this area must propose changes that subsume MULTIPLE sub-zones
(e.g., fold sort + merge + disk-write into a single linear pass over the
input vectors) AND quantify the combined critical-path saving at >6.3ms/ledger
(3% of 211ms) before being viable. Single-zone deletions in
`mergeInMemory` / `freshInMemoryOnly` are not viable at the current
baseline.
