# H003: Eliminate redundant `xdr::xdr_size(be)` walk in `InMemoryIndex` constructor by capturing per-entry sizes from `BucketOutputIterator` write pass

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / bucket index construction on the seal/finalize path
**Severity**: Low
**Impact**: Apply-time reduction by removing duplicate XDR size walks during bucket index construction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a fresh level-0 bucket is constructed during
`finalizeLedgerTxnChanges -> addLiveBatch -> LiveBucket::mergeInMemory`,
the bucket entries are serialized exactly once by
`BucketOutputIterator::put -> XDROutputFileStream::writeOne`, which
already knows the exact on-disk byte size of each entry (it writes a
4-byte length prefix followed by the serialized entry, tracking
`mBytesPut`). The `InMemoryIndex` constructor that follows
(`InMemoryIndex.cpp:264`) should reuse those sizes when computing
`typeStartOffsets`/`typeEndOffsets`, not call `xdr::xdr_size(be)` a
*second* time per entry.

## Mechanism

`InMemoryIndex::InMemoryIndex(BucketManager&, std::vector<BucketEntry>
const&, BucketMetadata const&)` (`InMemoryIndex.cpp:264-303`) iterates
`inMemoryState` and, for every entry, calls
`lastOffset += xdr::xdr_size(be) + xdrOverheadBetweenEntries`.
`xdr::xdr_size` performs a recursive serialization walk over every leaf
of the `BucketEntry` (which for `CONTRACT_DATA` includes a full `ScVal`
walk). The same serialization work was already performed moments earlier
inside `BucketOutputIterator::put -> writeOne`. For the soroswap
benchmark every fresh level-0 bucket pays this redundant walk; the
mergeInMemory helper at `LiveBucket.cpp:667-690` runs index construction
on a worker thread parallel to the put loop, so the redundant walk only
hurts when the index path is the slower side of the future race.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, `soroswap, TX=4000, T=8`) and
inspect zones in the existing baseline trace. Each `applyLedger` window
that produces a non-empty level-0 bucket via `addLiveBatch` triggers an
`InMemoryIndex` constructor at `InMemoryIndex.cpp:82` (the
`std::vector<BucketEntry> const&` overload at the trace commit).

## Target Code

- `src/bucket/InMemoryIndex.cpp:264-303` — `InMemoryIndex` constructor:
  drop the per-entry `xdr::xdr_size(be)` call; instead accept a
  precomputed `std::vector<std::streamoff>` of per-entry sizes from the
  caller.
- `src/bucket/BucketOutputIterator.cpp:78-165` —
  `BucketOutputIterator::put` / `writeOne`: capture each entry's
  serialized size as it is written (`mBytesPut` delta) and accumulate
  into a `std::vector<std::streamoff>` if an in-memory state vector is
  also being built.
- `src/bucket/BucketOutputIterator.cpp:167-247` —
  `BucketOutputIterator::getBucket`: when `inMemoryState` is non-null,
  pass the recorded sizes to the `InMemoryIndex` constructor (or
  construct the index inline using already-known offsets).
- `src/bucket/LiveBucket.cpp:667-697` — `LiveBucket::mergeInMemory`:
  no functional change; the optimization is invisible at this layer
  but the async `indexFuture` either becomes faster or the put loop
  takes over the slow side.

## Evidence

Tracy soroswap baseline (whole trace):

- `InMemoryIndex,bucket/InMemoryIndex.cpp,82` (the in-memory state
  constructor at trace commit 51a6d449b): 76.3 ms total / 66 calls
  (~1.16 ms per construction). This is worker-thread time off the apply
  critical path, masked by the parallel put loop.
- `addLiveBatch,bucket/BucketManager.cpp:1031`: 520.7 ms total /
  66 calls (≈ 7.9 ms per call inclusive). The InMemoryIndex
  construction is contained within this zone.
- `xdr::xdr_size(be)` for `CONTRACT_DATA`-heavy buckets is the dominant
  per-entry cost in the constructor's loop (the only other work is
  `processEntry` which inserts into the in-memory state set).

## Anti-Evidence

- **Async overlap caps the saving**: `mergeInMemory` runs the
  `InMemoryIndex` constructor inside `std::async` (`LiveBucket.cpp:667`)
  in parallel with the `BucketOutputIterator::put` loop, then awaits
  the future at `LiveBucket.cpp:689`. Apply only blocks if the index
  future is the slower side. Trace shows the constructor at ~1.16 ms
  per call; the put loop is likely longer per call (writeOne does
  serialize + hash + write), so on most ledgers index construction
  finishes first and the optimization saves no apply-window time.
- **Total impact below threshold**: even in the worst case where index
  construction is on the critical path 100 % of the time, removing
  half the constructor cost saves ≈ 38 ms across the whole trace, far
  below the 3 % Medium floor on a 4.59 s `applyLedger` total. This
  finding is recorded as Low; the PoC could measure exact hit rate but
  the upper bound makes it unlikely to clear the objective bar.
- **The file-loading constructor at `InMemoryIndex.cpp:123` (762 ms /
  30 calls) is *not* on the apply path**: it is the
  `std::filesystem::path` overload used by `createIndex` for cold-load
  paths (startup, restart-merges), not by the per-ledger
  `addLiveBatch`. Confirmed by reading the source at the trace commit
  (`git show 51a6d449b:src/bucket/InMemoryIndex.cpp`).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — the existing fail entry `001-async-addlivebatch.md`
covers async overlap of `addLiveBatch` as a whole; this hypothesis
covers a different mechanism (eliminate the redundant xdr_size walk
inside the InMemoryIndex constructor itself).

### Why It Failed

The optimization targets a worker-thread zone that is already hidden
behind a `std::async` future race in `LiveBucket::mergeInMemory`. The
in-memory `InMemoryIndex` constructor totals only 76 ms across the
whole 9.4 s trace (~1.16 ms per call) and is run concurrently with the
`BucketOutputIterator::put` loop, which performs comparable
serialize+hash+write work per entry. Removing the redundant
`xdr::xdr_size(be)` walk would, in the worst case (index always on the
critical path), save ~38 ms across the trace — well below the
objective's 3 % Medium floor (~138 ms on a 4.59 s `applyLedger` total)
and below the 1 % noise floor for the apply window. The big-looking
`InMemoryIndex,bucket/InMemoryIndex.cpp,123` zone (762 ms / 30 calls)
is the *file-loading* constructor used during cold-load paths, not the
per-ledger apply hot path. There is no plausible path to Medium
severity on the soroswap or max-sac benchmark from this change.

### Lesson Learned

`mergeInMemory` already runs `InMemoryIndex` construction in a worker
thread parallel to the `BucketOutputIterator::put` loop; further
optimization of the constructor only helps when the index future is
the slower side of the race. The 762 ms `InMemoryIndex` zone visible
near the top of the self-time list is the file-loading constructor
used by `createIndex` during cold loads (startup, restart-merges) and
is not exercised on the per-ledger apply hot path. Always confirm
which constructor a Tracy zone refers to by checking the source line
at the trace's commit — file-loading bucket constructors look hot in
aggregate but are not part of `addLiveBatch`.
