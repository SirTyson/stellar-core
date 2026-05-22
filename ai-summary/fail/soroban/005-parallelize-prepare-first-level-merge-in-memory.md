# H005: Parallelize Level-0 `mergeInMemory` During `prepareFirstLevel`

**Date**: 2026-05-22
**Subsystem**: soroban (bucket / apply path)
**Severity**: Low
**Impact**: serial bucket-merge wall-time inside `addLiveBatch` -> `BucketLevel::commit`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketLevel::prepareFirstLevel` (`src/bucket/BucketListBase.cpp:196`) runs on
the apply thread inside `addLiveBatch` and synchronously merges the new live
batch with the existing level-0 `curr` bucket via
`LiveBucket::mergeInMemory`. For a benchmark like soroswap that produces a
large per-ledger write set, the in-memory merge does (a) a flat-map merge of
two pre-sorted entry vectors, (b) a re-sort/de-dup pass, and (c) a single-pass
serialized write of the merged vector to a new bucket file. The expected
correct-and-fast behavior is that this synchronous critical-path work is
proportional to `O(new_batch + level0_curr)` per ledger and is performed
serially because it produces a deterministic, ordered output that the next
ledger must observe.

A correct optimization would shard the merge/sort/encode/write across multiple
worker threads while preserving the exact bit-identical merged bucket bytes
(determinism). The thread count would be capped at `NUM_CLUSTERS` and the
shards would be partitioned by a deterministic key range so every node
produces the same shard boundaries.

## Mechanism

Tracy self-time on the current trace shows `merge,bucket/BucketBase.cpp,351`
at 52.7 M ns and the put-loop work inside it
(`put,bucket/BucketOutputIterator.cpp,80` 63.0 M ns +
`writeOne,./util/XDRStream.h,485` 73.9 M ns +
`writeBytes,./util/XDRStream.h,410` 47.6 M ns) is the dominant cost. These
fire during the on-apply-thread synchronous portion of `addLiveBatch`. A
shard-parallel merge writer would, in principle, cut wall time by `NUM_CLUSTERS`
on this portion. The deviation from a parallel implementation is the current
single-thread loop in `BucketOutputIterator::put` and the serial XDR-encode/
flush inside `XDRStream::writeOne`.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap scenario (TX=2000, T=8). The
zones above are descendants of `addLiveBatch,bucket/BucketManager.cpp,...`
which is itself called inside `applyLedger` -> `sealLedgerTxnAndStoreInBucketsAndDB`.

## Target Code

- `src/bucket/BucketListBase.cpp:196` — `BucketLevel::prepareFirstLevel` and
  call into `LiveBucket::mergeInMemory`
- `src/bucket/LiveBucket.cpp` — `mergeInMemory` implementation
- `src/bucket/BucketOutputIterator.cpp:80` — serialized per-entry put-loop
- `src/util/XDRStream.h:410,485` — `writeBytes` / `writeOne`

## Evidence

- Tracy self-time in `addLiveBatch` subtree totals ~290 M ns across 71
  ledgers = ~4 ms/ledger.
- Output-writer serial loop dominates the merge cost (XDR encode + file
  write, single thread).
- `NUM_CLUSTERS=8` worker pool is already available on the apply thread,
  so spawning N shards has no extra cost.

## Anti-Evidence

- The merged bucket file is a single ordered XDR stream; producing it from
  N shards requires either (a) writing N segment files and concatenating
  with an extra pass (defeats the parallel win), or (b) a coordinated
  shared writer (defeats the parallelism). Both add overhead that erodes
  the projected savings.
- Determinism requires byte-identical output across nodes, including the
  precomputed bucket hash. Sharded merging must produce identical bytes,
  not just identical entries.
- `addLiveBatch` total across 71 ledgers is ~293 M ns wall-clock = 4.1 ms
  per ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a parallelization angle.
The closest priors are fail
`011-async-add-live-batch.md / 002-async-level0-bucket-file-write.md /
003-async-addLiveBatch.md` (async-with-immediate-join — wrong perf model)
and fail `028-mergeinmemory-single-pass-merge-and-write.md` (cache-cold
reread fusion). Neither investigated true shard-parallel merge.

### Why It Failed

Sizing the proposed savings against the authoritative baseline:

- `addLiveBatch` total self-time across 71 ledgers ≈ 293 M ns wall = 4.1 ms
  per ledger.
- Authoritative soroswap baseline median = 230.225 ms/ledger.
- Theoretical maximum gain if `addLiveBatch` went to 0 ms = 4.1 / 230.225
  = **1.78% of apply time** — below the **Medium (≥3%)** floor.
- Practical achievable gain is far smaller because (a) the parallel-merge
  scheme requires either a coordinated writer or a concatenation pass,
  both of which add overhead, and (b) determinism constraints force a
  serializable final-write phase. Realistic best case is 50% of the
  4.1 ms = **0.89% of apply** — sub-Low, below the 1% noise floor stated
  in the objective.
- This is the same meta-pattern as fail entries
  `011-async-add-live-batch.md / 002-async-level0-bucket-file-write.md /
  003-async-addLiveBatch.md`: `addLiveBatch` is simply too small a slice
  of apply to clear the threshold, regardless of how it is parallelized.

### Lesson Learned

Before proposing parallelization of any apply-thread serial subroutine,
size its **wall-time fraction of the authoritative
`scripts/run_apply_load_matrix.py` median** (not its Tracy self-time
fraction). The 230 ms soroswap baseline means any work-slice under
~7 ms/ledger cannot, even at 100% gain, clear the Medium 3% bar. The
`addLiveBatch` family of optimizations is permanently capped below
Medium at the current baseline; further investigation of bucket-thread
parallelism on this path is not worthwhile until a higher-level redesign
makes `addLiveBatch` a larger slice of apply.
