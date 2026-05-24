# H001: Defer `BucketOutputIterator::getBucket` disk-finalize to background thread

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (bucket / apply)
**Severity**: Low (sub-threshold)
**Impact**: apply-time reduction (bucket merge disk finalize on critical path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::mergeInMemory` (`src/bucket/LiveBucket.cpp:613-528`) is invoked
synchronously from the apply thread inside `addLiveBatch ->
prepareFirstLevel`. After it builds the merged in-memory entries (the
in-memory `mEntries` vector that is consumed by the NEXT ledger's merge), the
expected critical-path work is bounded by the in-memory operations. The
on-disk persistence of the level-0 bucket — flushing the temp file, finalizing
the SHA256, renaming/adopting the file under `BucketManager` — is only needed
for (a) crash-recovery durability and (b) future higher-level
`FutureBucket::resolve` merges that need a disk reader. Neither dependency is
synchronous with the apply path's publication of the new ledger state.

The correct (and minimal) apply-path cost should therefore be the in-memory
merge + sort + entry materialisation, with all disk finalization deferred to
a background task that completes before the bucket is needed at a higher
level (typically many ledgers later).

## Mechanism

`BucketOutputIterator::getBucket` (`src/bucket/BucketOutputIterator.cpp:174`)
currently performs `mOut.close()`, hash finalisation, and
`bucketManager.adoptFileAsBucket` synchronously inside `mergeInMemory` at line
527. On a fast NVMe machine with fsync disabled (apply-load default) this is
small, but in principle it is unrelated to the apply critical path — the
returned bucket's *in-memory* contents are what the next ledger needs; the
disk file is only consumed by future, asynchronous bucket merges further up
the level hierarchy. Pushing this work to a background thread would shorten
the apply window by exactly the time spent in `getBucket` on the apply
thread.

## Trigger

Run the soroswap apply-load benchmark; profile with Tracy; measure the
`getBucket` zone calls whose parent zone is `mergeInMemory` /
`prepareFirstLevel` / `addLiveBatch` (the apply-path instances, not the
background-merge instances).

## Target Code

- `src/bucket/BucketOutputIterator.cpp:167-220` — `getBucket`: synchronous
  `mOut.close()` + hash + `adoptFileAsBucket`.
- `src/bucket/LiveBucket.cpp:613-528` — `mergeInMemory`: line 527 returns
  via `out.getBucket(bucketManager)` synchronously on the apply thread.
- `src/bucket/BucketListBase.cpp:193-238` — `prepareFirstLevel<LiveBucket>`:
  the path that drives `mergeInMemory` from `addLiveBatch`.

## Evidence

- Meta-pattern 26 in `ai-summary/fail/transaction-ledger/summary.md`
  explicitly invites investigation of "internal merge work inside
  `prepareFirstLevel`/`mergeInMemory`" as the remaining angle after
  whole-`addLiveBatch` deferral was rejected.
- `getBucket` returns a bucket that contains both an in-memory
  representation (via the `mEntries` move into the new `LiveBucket`) and a
  filename — so the in-memory copy is genuinely independent of the disk
  finalize and could in principle be produced first.

## Anti-Evidence

- The in-memory `LiveBucket` constructor requires the filename and hash; the
  hash is only known once the output iterator has finalised the file.
  Producing the in-memory bucket "first" therefore requires either (i)
  splitting the hash into a streaming computation finished synchronously
  (already the case) plus a deferred file-rename, or (ii) carrying a
  promise-of-filename through the rest of the BucketList machinery, which is
  a significant invasive refactor.
- `addLiveBatch` registers the new bucket in `BucketList` state under a
  lock; downstream code (`snapshotLedger`, `bucketListHash` computation) must
  see a fully-formed bucket including its `Hash`. The hash IS already
  computed synchronously inside the put-loop SHA accumulator, so this isn't
  itself a blocker, but the architectural integration cost is non-trivial.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — neither `BucketOutputIterator::getBucket` deferral nor
the specific `mOut.close()` / `adoptFileAsBucket` split appears in
`summary.md` (verified via grep for `getBucket`, `adoptFile`, `out.close`).
The closest prior record (011-defer-add-live-batch-to-post-apply-future)
rejected the *whole-batch* deferral and Meta-26 explicitly redirected to
internal-merge investigation.

### Why It Failed

Tracy CSV (`/tmp/soroswap_self.csv`) shows the apply-path
`getBucket@bucket/BucketOutputIterator.cpp:174` zone is 1.33ms total / 75
calls = **17.8µs per call ≈ 18.5µs/ledger**. Companion zone
`adoptFileAsBucketInternal@bucket/BucketManager.cpp:484` on the apply path is
2.86ms / 74 calls = **39µs/ledger**. Even fully eliminating both yields
~58µs/ledger out of a 211ms soroswap baseline = **0.027%** — three orders of
magnitude below the Medium (3%) hypothesis threshold and far below the 1%
benchmark-noise floor.

Estimation error: the prior session checkpoint inferred ~1.6ms/ledger by
subtracting `mergeInMemory put loop` from `mergeInMemory` total. That
inference was wrong — the actual `mergeInMemory` envelope is 3.04ms over 73
calls = 41.7µs/ledger; the entire bucket-merge apply-path stack
(`addLiveBatch` ≈ 4.5ms/ledger) is bounded above by ~2.1% even if the entire
thing vanished.

### Lesson Learned

Inferring zone durations from arithmetic on parent/child totals is unreliable
when the child zone counts differ (other call sites contribute to the same
zone label). Always confirm with the direct Tracy self-time and divide by
call-count to get per-ledger cost. The `BucketOutputIterator::getBucket` /
`adoptFileAsBucketInternal` apply-path cost has now been measured directly
and shown to be sub-noise — future bucket-disk-finalize deferral hypotheses
are not viable on the current baseline.
