# H031: Defer SHA256 hashing of level-0 bucket file off the apply thread

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / bucket finalize hashing on apply thread
**Severity**: Low
**Impact**: Moves the per-byte SHA256 incremental hashing performed inside `XDROutputFileStream::writeOne` off the synchronous apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::freshInMemoryOnly` (`src/bucket/LiveBucket.cpp:648`) builds the
new level-0 bucket by walking the merged entry vector, encoding each entry
to XDR via `LiveBucketOutputIterator::put` →
`XDROutputFileStream::writeOne`, and incrementally hashing the encoded byte
stream into a `SHA256` hasher attached to the iterator. The bucket file's
final SHA256 hash is consumed at end of merge by `out.getBucket(...)` to
identify the new bucket. The efficient apply path should run only the
work strictly needed to transition apply state and externalize meta on the
critical path, and defer post-state-transition CPU bookkeeping (such as
SHA256 hashing of an already-written bucket file) onto a worker thread that
joins only at the next synchronization point.

## Mechanism

`XDROutputFileStream::writeOne` (`src/util/XDRStream.h:507-510`) calls
`hasher->add(ByteSlice(mBuf.data(), toWrite))` synchronously for every
emitted entry inside the put loop. This adds incremental SHA256 work to the
apply thread for ~600 entries/ledger. Tracy shows `SHA256::add`
self-time of 294 ms over 1.5 M calls trace-wide; cross-referenced against
`writeOne` self/inclusive time, the apply-window share of bucket-file
SHA256 add is roughly 1-2 ms/ledger. A reorganization of the put loop that
captures the encoded bytes into an in-memory buffer (or copies them as the
XDR stream writes them), then hands the buffer off to a worker thread that
computes SHA256 and stores the result on the new `LiveBucket`, would let
apply continue past the put loop without paying the per-entry hashing cost.

## Trigger

Run the soroswap apply-load benchmark (`apply-load --mode soroswap-tps`).
Inside `finalizeLedgerTxnChanges` → `addLiveBatch` →
`prepareFirstLevel` → `freshInMemoryOnly`, the put loop synchronously
invokes `writeOne` 600+ times per ledger, hashing each emitted XDR record
inline.

## Target Code

- `src/bucket/LiveBucket.cpp:677-683` — `mergeInMemory put loop` walks
  `mergedEntries` and calls `out.put(e)` on the apply thread.
- `src/bucket/BucketOutputIterator.cpp:153,177` — `writeOne` invocation
  passes the per-iterator `SHA256* &mHasher` so hashing is inline with
  encoding.
- `src/util/XDRStream.h:483-515` — `writeOne` calls `hasher->add(...)` after
  `writeBytes`.
- `src/crypto/SHA.cpp:65` — `SHA256::add` is the per-block SHA256 update
  whose Tracy zone shows 294 ms self-time over 1,511,955 calls trace-wide.

## Evidence

- Tracy self-time of `SHA256::add` is 294 ms (2.86% of trace) over ~1.5 M
  calls, including all add sites: bucket-write, tx hashing, and TX-set
  construction. Filtering to apply-window `writeOne`-driven adds yields a
  share roughly proportional to `writeOne`'s 76 ms self-time + 128 ms
  descendants — i.e., a single-digit ms per ledger.
- The hash result is only consumed at end of `freshInMemoryOnly` via
  `out.getBucket(...)`; downstream consumers do not need the partial hash
  to be available mid-loop. The hashing is already structurally separable
  from the put loop.
- The index-construction `std::async` task at line 667 demonstrates that
  the apply path already overlaps post-merge bookkeeping (index build) with
  the put loop on a worker thread.

## Anti-Evidence

- The apply-thread share of bucket-file SHA256 hashing is bounded by the
  ~204 ms inclusive `writeOne` time minus the ~76 ms `writeOne` self-time
  minus `xdr_argpack_archive` time minus `writeBytes` time. The pure
  hashing portion is at most ~50-80 ms across the 71-ledger trace, or
  ~0.7-1.1 ms/ledger (~0.3-0.4% of the 273 ms soroswap median).
- Deferring the hash requires either buffering the entire encoded bucket
  file in memory (extra ~3 MB transient allocation per ledger) or sharing
  the file descriptor with a worker thread that mmap-reads the just-written
  bytes after fsync — both add complexity and resource pressure that may
  exceed the saved CPU.
- The `freshInMemoryOnly` already runs the index construction on a worker
  thread and joins at end-of-merge. Adding a second fan-out for hashing
  competes with that worker for the same CPU; if the worker thread pool is
  saturated by the parallel Soroban cluster threads (NUM_CLUSTERS = 8),
  there is no spare capacity for a hashing worker without contending with
  Soroban execution.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior bucket-write deferral hypotheses
(H001-async-addlivebatch, H003-defer-addlivebatch-encoding-to-background,
H017-poststamp-encoded-bytes-in-addlivebatch). Those proposed deferring the
entire `addLiveBatch` or caching the entire encoded byte stream; this
hypothesis isolates only the SHA256 hashing component of `writeOne`.

### Why It Failed

Below the objective severity threshold by an order of magnitude. The
per-ledger SHA256 hashing of bucket-write bytes is ~0.3-0.4% of the
soroswap apply-time median, deep below the Medium 3% floor and below the
1% Low minimum. This matches meta-pattern #18 in
`fail/transaction-ledger/summary.md`: bucket-write refinements are bounded
by `finalizeLedgerTxnChanges`'s ~1.3-2% share of `closeLedger`, and a
sub-component (just the hashing inside `writeOne`) cannot exceed that
ceiling. Additionally, deferring the hash to a worker thread competes with
the existing index-construction `std::async` worker and with
NUM_CLUSTERS = 8 Soroban worker threads, with no spare capacity.

### Lesson Learned

When a parent zone (e.g., `finalizeLedgerTxnChanges`) is itself bounded
sub-Medium, no sub-component of that zone can reach Medium severity by
isolated deferral. Bucket-write apply-path optimizations need to either
remove the entire bucket-write commit pipeline from the synchronous
apply window (rejected by H001-async-addlivebatch and
H003-defer-addlivebatch-encoding-to-background), or replace the bucket
representation altogether — a sub-step like hashing alone is far below
threshold.
