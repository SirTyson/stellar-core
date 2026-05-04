# H003: Defer addLiveBatch XDR Encoding and SHA256 Hashing to Background Thread

**Date**: 2026-05-04
**Subsystem**: transaction-ledger (bucket boundary)
**Severity**: Low
**Impact**: Apply-time reduction via off-thread bucket encoding
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges` already launches `addHotArchiveBatch` and
`updateInMemorySorobanState` as `std::async` tasks because they touch
data structures (mHotArchiveBucketList, mInMemorySorobanState) that are
independent of the live BucketList. Symmetrically, the synchronous
`addLiveBatch(mApp, lh, initEntries, liveEntries, deadEntries)` call at
LedgerManagerImpl.cpp:3356 should be the smallest possible critical-path
contribution: only the work whose outputs are observed by the rest of
`closeLedger` should remain on the apply thread.

In particular, the `mergeInMemory` path inside `addLiveBatch` performs:
1. `mergeInternal` — produces `mergedEntries` (the next-level bucket's
   in-memory entry vector). This output is observable: subsequent ledgers
   read these entries via `BucketListSnapshot`.
2. A `BucketOutputIterator::put` loop that for each entry serializes XDR
   (`xdr_to_msg`), updates a running SHA256, and writes to a temporary
   file on disk. This output (the bucket file + hash) is **not** observed
   by anything else in `closeLedger`; it's only consumed by future ledgers
   for merge candidates and crash recovery.

Therefore the encoding/hashing/disk-write stage could be deferred to a
background thread, with the apply thread only synchronously running
`mergeInternal` to make `mergedEntries` available.

## Mechanism

`mergeInMemory` (src/bucket/LiveBucket.cpp ~line 530-698) currently runs
the put loop synchronously on the apply thread. Tracy zones for `put`
(67 ms self-time across 72 ledgers) and `writeOne`
(75 ms self-time across 72 ledgers, src/util/XDRStream.h:481) plus
`add` (SHA256 incremental hashing, 294 ms self-time across all callers)
contribute roughly 2 ms/ledger of synchronous work that is not depended
on by the rest of the apply path. Deferring this stage to a background
thread (joined at the start of the next ledger's `addLiveBatch`, which
already serializes on `mLedgerStateMutex`) would remove this from the
critical path.

## Trigger

Run `apply-load --mode soroswap` and measure `closeLedger` wall time
before and after deferring the encoding/disk-write portion of
`mergeInMemory`. Compare against baseline 272.9 ms.

## Target Code

- `src/bucket/LiveBucket.cpp:mergeInMemory:~530-698` — split
  `mergeInternal` (synchronous) from the `BucketOutputIterator::put` loop
  (deferrable).
- `src/bucket/BucketOutputIterator.cpp:put,getBucket` — encoding +
  SHA256 finish + adopt path that produces the bucket identity hash.
- `src/bucket/BucketListBase.cpp:BucketLevel<LiveBucket>::commit` — the
  join point that would need to wait on the previous ledger's deferred
  encoding before computing a new merge.
- `src/ledger/LedgerManagerImpl.cpp:3356` — the synchronous
  `addLiveBatch` call to be split.

## Evidence

- Tracy: `put` self 67 ms / 72 ledgers ≈ 0.93 ms/ledger.
- Tracy: `writeOne` self 75 ms / 72 ledgers ≈ 1.04 ms/ledger.
- Tracy: SHA256 `add` self 294 ms across all callers / 72 ledgers, of
  which the bucket-write portion is a meaningful (but not dominant)
  fraction.
- Two of three sibling tasks in `finalizeLedgerTxnChanges`
  (`addHotArchiveBatch`, `updateInMemorySorobanState`) are already
  asynchronous, so the precedent for off-thread bucket work is well
  established.

## Anti-Evidence

- The bucket file's content hash is the bucket identity, used as the key
  in the `BucketManager` map and as input to the next-ledger merge that
  picks a bucket-by-hash. Deferring the hash means the next ledger may
  see a partially identified bucket; care is required to ensure the
  apply path can continue without the hash.
- `addLiveBatch` also performs `InvariantManager::checkOnBucketApply`,
  which inspects the entries and potentially the new bucket; deferring
  the invariant check changes when failures surface (post-commit instead
  of pre-commit), which is a design change.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — this is a more specific variant of the previously
rejected H001-async-addlivebatch (which proposed deferring the entire
`addLiveBatch` call). This narrower variant defers only the encoding +
hash + disk write inside `mergeInMemory`, keeping `mergeInternal` and
in-memory entry availability synchronous.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
The synchronous work that this hypothesis would defer is bounded by
`put` + `writeOne` + the bucket-write portion of SHA256 `add`, totaling
roughly 2 ms/ledger ≈ 0.74% of the 272.9 ms soroswap apply baseline. Even
under the optimistic assumption that the entire 2 ms is critical-path and
can be hidden behind subsequent independent work, the projected gain
falls below the 3% Medium floor and inside the benchmark noise band.

The deferral also requires non-trivial design changes: the bucket
identity hash and `InvariantManager::checkOnBucketApply` must either be
made tolerant of an unfinished bucket, or the join point must occur
before any consumer in the next ledger reads the hash. The complexity
risk is disproportionate to the projected gain.

The closely related H001-async-addlivebatch (the broader variant) was
already rejected at ~0.8% (~5 ms), confirming the entire `addLiveBatch`
call is sub-threshold; carving out a strict subset of that work cannot
exceed the parent's measured impact.

### Lesson Learned

When a parent hypothesis (deferring the whole of `addLiveBatch`) was
rejected as sub-threshold, narrower variants that defer a strict subset
of the same work cannot break the parent's impact ceiling. Don't propose
strict-subset variations of already-rejected sub-threshold hypotheses;
instead, look for entirely different code paths whose self-time is
larger, or for redesigns that fold the work into an existing
non-blocking stage.
