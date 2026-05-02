# H006: Parallelize per-entry XDR encode + SHA256 in `LiveBucket::fresh` / `BucketOutputIterator::put`

**Date**: 2026-05-02
**Subsystem**: bucket
**Severity**: Low (sub-medium)
**Impact**: Apply-time reduction in the synchronous `addLiveBatch` post-apply phase
**Hypothesis by**: claude-opus-4.7, low

## Expected Behavior

`addLiveBatch` runs synchronously on the apply thread between
`applySorobanStageClustersInParallel` finishing and `finalizeLedgerTxnChanges`
returning. The per-entry work it does — XDR-serialize each `BucketEntry`
into the level-0 file via `mOut.writeOne(*mBuf, &mHasher, &mBytesPut)` and
incrementally feed the SHA256 hasher — is independent across entries up to
the final hash combine and the file-write order. A reasonable design would
shard the encode-and-hash phase across worker threads (chunked, with
deterministic per-chunk hashes combined in order at the end), then write
the bytes serially in entry order on the apply thread.

## Mechanism

`BucketOutputIterator::put` (`src/bucket/BucketOutputIterator.cpp:78`) calls
`mOut.writeOne(*mBuf, &mHasher, &mBytesPut)` (line 153). `writeOne` in
`src/util/XDRStream.h:485` performs an `xdr::xdr_to_msg` encode + a
`SHA256::add(bytes)` + a `write` to the underlying file. For
`LiveBucket::fresh` writing 8000 sorted entries per ledger, the encode and
hash dominate. In principle these could run on N parallel workers (each
hashing its slice with a fresh SHA256 then combining via Merkle-style
chaining — which would change the bucket hash format and is therefore a
non-starter), or the encode-only step could be sharded with a single-thread
hash pass. Either way, the encode work could overlap with hash work via a
producer/consumer pipeline.

## Trigger

Run the soroswap apply-load matrix and inspect Tracy zones for
`addLiveBatch`, `BucketOutputIterator::put`, and `writeOne`.

## Target Code

- `src/bucket/LiveBucket.cpp:510-528` — `LiveBucket::fresh`; the per-batch
  entry loop.
- `src/bucket/BucketOutputIterator.cpp:78-165` — `put`; calls `writeOne`
  for every flushed entry.
- `src/util/XDRStream.h:485` — `writeOne`; encode + hash + file write.
- `src/bucket/BucketManager.cpp:1026` — `addLiveBatch` entry point;
  currently serial on the apply thread (after fail #021 the third async
  future was rejected as too small).

## Evidence

- Tracy trace
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`,
  measured via `csvexport-release -e`.
- `addLiveBatch` (BucketManager.cpp:1031): **522,860 ns total / 71 calls /
  mean 7,364 ns** ≈ **0.5 ms total across the entire 70-ledger benchmark**.
- `addBatch` (LiveBucketList.cpp:21): **979,127 ns total / 71 calls** ≈
  **1.0 ms total across the benchmark**.
- `BucketOutputIterator::put` aggregated over the level-0 fresh path:
  **60,231,236 ns / 566,087 calls / mean 106 ns** ≈ **60 ms total**.
- `writeOne` (XDRStream.h:485): **70,809,115 ns / 566,087 calls / mean 125
  ns** ≈ **71 ms total across the 70-ledger benchmark**.

## Anti-Evidence

- The per-entry encode + hash work is genuinely parallelizable, but **the
  total time is sub-noise**: the entire `BucketOutputIterator::put` self-time
  for the fresh path is 60–71 ms across **70 ledgers**, i.e.
  ~0.86–1.0 ms/ledger ≈ **0.31–0.36 % of the 278 ms soroswap baseline**.
  Even removing 100 % of this work leaves a gain well below the 1 % Low
  noise floor and an order of magnitude under the 3 % Medium threshold.
- Bucket hash determinism requires entries to be hashed in sorted order
  with a single SHA256 stream — sharding the hash itself would change the
  bucket hash format and is out-of-scope. Only the encode could be sharded,
  which is half of the already-tiny budget.
- Fail meta-pattern #6 ("Async With Immediate Join Is Neutral") and fail
  #011/#021 already established that async dispatch around `addLiveBatch`
  is neutral or below threshold; this hypothesis is the same family.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — angle is parallelizing the synchronous slice itself
(distinct from the async-future approach in #011/#021), but the measurement
that motivated those rejections also kills this one.

### Why It Failed

Direct Tracy measurement on the current trace shows
`BucketOutputIterator::put` + `writeOne` for the level-0 fresh path totals
**~70 ms across all 70 ledgers** (~1 ms/ledger), i.e. 0.36 % of the 278 ms
soroswap baseline. Even 100 % elimination would not clear the 1 % Low
noise floor, let alone the 3 % Medium threshold required by the
optimize-soroswap objective. Bucket-hash determinism additionally
constrains the parallelizable surface to roughly half (encode only, not
hash). The `addLiveBatch` zone has shrunk dramatically since fail #011
estimated ~1.3 % — the path is no longer a candidate.

### Lesson Learned

`addLiveBatch` and the `LiveBucket::fresh` per-entry encode/hash slice are
no longer measurable bottlenecks on the soroswap workload. Future
hypotheses targeting the post-apply-thread work should pick a zone whose
trace self-time exceeds at least ~9 ms/ledger (3 % of baseline) before
considering parallelism. Re-measure before writing.
