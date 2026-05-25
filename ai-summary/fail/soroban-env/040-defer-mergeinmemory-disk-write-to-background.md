# H040: Defer `mergeInMemory` Disk Put-Loop and `BucketOutputIterator` File Write to Background

**Date**: 2026-05-25
**Subsystem**: bucket (level-0 in-memory merge during `addLiveBatch`)
**Severity**: Low
**Impact**: Apply-time reduction (move sync per-level disk-write of merged bucket off the apply critical path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::mergeInMemory` should only block the apply path for work
that is required before the next ledger close:
- The in-memory sort/merge of `oldEntries` + `newEntries` (needed because
  the returned `LiveBucket` carries `mergedEntries` for the next merge).
- The pre-built `LiveBucketIndex` (also needed for in-memory lookups).

Writing the merged entries to a `.bucket` file on disk is needed for
**durability and future recovery**, not for the in-memory bucket state
that the next ledger will consult. The file write could be deferred to
a background task awaited at a later checkpoint boundary.

## Mechanism

In `src/bucket/LiveBucket.cpp:613-698` (`mergeInMemory`), after the
in-memory merge into `mergedEntries`, the function:
1. Spawns `indexFuture` for index construction (✓ already async).
2. Constructs `LiveBucketOutputIterator out(...)` (opens a file).
3. Runs the **`mergeInMemory put loop`** (`for e in mergedEntries: out.put(e)`).
4. Joins `indexFuture`.
5. Returns the in-memory bucket.

Steps 2–3 (file open + serialize-and-write all merged entries to disk)
run synchronously on the apply thread. Since the returned bucket carries
the full in-memory entries (line 696), neither the next ledger's apply
nor any in-memory lookup requires the on-disk file to exist before the
next close.

A correctness-preserving variant would: launch the put loop and
OutputIterator construction in a separate `std::async` future stored on
the BucketManager, return the in-memory bucket immediately, and join
that future at the next checkpoint boundary (or at the next bucket
operation that could observe the file).

## Trigger

Soroswap benchmark — `mergeInMemory` runs once per ledger per affected
bucket level during `addLiveBatch`.

## Target Code

- `src/bucket/LiveBucket.cpp:613-698` (`mergeInMemory`): the `out.put(e)`
  loop at lines 678-683 and `LiveBucketOutputIterator` construction at
  lines 673-675 are synchronous on the apply path.
- `src/bucket/BucketOutputIterator.cpp:39` (`BucketOutputIterator`
  constructor): opens a temp file.

## Evidence

Tracy soroswap trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`:
- `mergeInMemory` total = 137.2 ms / 72 calls = 1.91 ms per call
- `mergeInMemory put loop` total = 70.3 ms / 72 calls = 0.98 ms per call
  (= ~51% of `mergeInMemory` total)
- `BucketOutputIterator` ctor total = 6.2 ms aggregate (file open)
- `mergeInMemory merge` (sort/merge) total = 18.8 ms = 0.26 ms per call
  (this is the actually-required pre-publish work)
- `mergeInMemory index future wait` total = 1.3 ms (already async)
- Aggregate removable disk-write work: ~76 ms / 71 ledgers = **~1.07
  ms/ledger** wall-time.

## Anti-Evidence

- The deferred file write must complete before the bucket can be
  rehydrated from disk after a crash/restart, before any background merge
  reads it, or before the file is consulted by historical replay. The
  scheduler that awaits the deferred futures must guarantee this without
  reintroducing the wait on the apply path.
- `mergeInMemory` is called from `addBatch` and may run at multiple
  levels per close; some levels' results feed the next level's merge
  immediately (chained calls within a single `addBatchInternal`). The
  next-level merge consumes `oldBucket`/`newBucket` as `shared_ptr<LiveBucket>`
  via `hasInMemoryEntries()`/`getInMemoryEntries()`, so it does not need
  the prior file write to complete — the in-memory representation is
  sufficient.
- The benchmark's `ApplyLoad::benchmarkModelTxTpsSingleLedger` calls
  `resolveAllFutures()` before each timed close (see fail #001-prewarm
  meta-pattern), but does *not* force completion of the bucket file
  writes — so deferring those writes would not be hidden by benchmark
  drainage.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail/001-prewarm-blocking-bucket-resolves
(which targeted `FutureBucket::resolve` blocking time before commit) and
from fail/009-preallocate-vec-write-xdr-bytes (which targeted XDR
serialization buffer growth). No prior investigation has targeted the
`mergeInMemory put loop` / `BucketOutputIterator` write path during
in-memory merges.

### Why It Failed

Quantification:
- Removable wall-time per ledger: ~76 ms / 71 = **1.07 ms/ledger**
- Soroswap baseline median: 207.6 ms/ledger
- Projected impact: 1.07 / 207.6 ≈ **0.52%**

This is below the 1% Low noise floor and three orders of magnitude
below the 3% Medium severity threshold this objective requires.

Additionally:
- Deferring file writes introduces non-trivial correctness risk: the
  next checkpoint/restart/historical-replay path must wait on every
  in-flight future, and the synchronization layer must track per-bucket
  futures across multiple `addBatch` invocations and bucket levels.
- The `LiveBucketOutputIterator` constructor opens a file with `fopen`
  and writes a metadata header; deferring just this part risks
  file-descriptor exhaustion under high load if many merges queue up.
- Per soroswap-objective rules, async work that the apply path
  synchronously waits on **at any later point inside the benchmark's
  measured window** would simply move the wait, not remove it. The
  benchmark's window includes the entire `closeLedger` call chain; if
  the deferred future is awaited before `closeLedger` returns, the
  saving evaporates.

### Lesson Learned

For bucket-write optimizations during `addLiveBatch`, the removable
work is the *disk-write portion* of `mergeInMemory`, which is captured
by the `mergeInMemory put loop` Tracy zone (~1 ms/ledger). This is
similar to the sub-Medium ceilings of native-pool micro-optimizations
(Meta-Pattern 14): individual per-ledger sub-2 ms wall-time savings
cannot clear the 3% Medium floor on the 207 ms soroswap baseline.
Future bucket-write hypotheses need either a larger removable surface
(e.g., redesigning how the on-disk format is constructed for fresh
in-memory buckets, eliminating the file write entirely for short-lived
level-0 merges that will be re-merged before any disk consumer reads
them) or to be combined with a coordinated change to `BucketManager`'s
file lifecycle.
