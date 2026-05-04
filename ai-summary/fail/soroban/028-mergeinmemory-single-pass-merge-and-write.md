# H028: Single-pass merge-and-write in `LiveBucket::mergeInMemory`

**Date**: 2026-05-03
**Subsystem**: soroban (bucket / apply path)
**Severity**: Low
**Impact**: apply-time reduction in `addLiveBatch` / `prepareFirstLevel`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::mergeInMemory` is the synchronous, on-apply-path level-0 merge
that combines the previous level-0 curr's in-memory entries with this
ledger's new in-memory entries, producing both an in-memory cache and a
freshly written bucket file on disk. Ideally the function should walk the
merged stream exactly once, visiting each merged entry one time to (a)
serialize and write it to the on-disk `LiveBucketOutputIterator` and
(b) record it in the new in-memory entries vector that becomes the new
bucket's `getInMemoryEntries()` cache. Doing this in a single pass would
minimise allocator traffic and keep the merged-entry data hot in L1/L2.

## Mechanism

Today `mergeInMemory` does the work in two physically separate passes:

1. `mergeInternal(...)` walks the merge stream and the `putFunc` closure
   (`|e| mergedEntries.emplace_back(e)`) appends each merged entry to a
   freshly-allocated `Vec<BucketEntry>` (`mergedEntries`).
2. After `mergeInternal` returns, a second loop iterates the now-fully-built
   `mergedEntries` vector and calls `out.put(e)` on each — this is the
   `mergeInMemory put loop` Tracy zone, which serialises the entry to XDR,
   feeds it to SHA256, and writes it to the bucket file.

Between the two passes the `mergedEntries` vector has typically grown to
tens-of-MB and is no longer hot in cache, so the second pass re-touches every
entry from L3/RAM. A unified single-pass implementation could fuse the two
loops by having `putFunc` both append to `mergedEntries` and call
`out.put(...)` inline, eliminating the cache-cold reread.

## Trigger

Any apply ledger that produces a non-empty level-0 merge — i.e. essentially
every soroswap-benchmark ledger.

## Target Code

- `src/bucket/LiveBucket.cpp:614-697` — `LiveBucket::mergeInMemory`. Note the
  `putFunc` at lines 649-652 only populates `mergedEntries`; the disk write
  happens in a separate loop at lines 678-683 after `mergeInternal` returns.
- `src/bucket/LiveBucket.cpp:649-652` — `putFunc` closure that would need to
  be widened to also call `out.put(...)` inline.
- `src/bucket/BucketListBase.cpp:196-238` — `BucketLevel<LiveBucket>::prepareFirstLevel`
  (caller).

## Evidence

Tracy zones from accepted soroswap baseline trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`,
71 ledgers, 8 worker clusters):

| Zone | Total time | Calls |
|---|---|---|
| `mergeInMemory` | 138.4 ms | 72 |
| `mergeInMemory merge` (`mergeInternal` body) | 17.7 ms | 72 |
| `mergeInMemory put loop` | 73.4 ms | 72 |
| `getBucket` (BucketOutputIterator close, on-apply-path slice) | ~22.9 ms | 74 |

`mergeInMemory put loop` is the single largest sub-zone of `mergeInMemory`
and runs synchronously on the apply thread; it currently re-reads
`mergedEntries` after `mergeInternal` has finished populating it.

## Anti-Evidence

The `out.put(...)` work is dominated by XDR-encode + SHA256, **not** by the
vector-read load that single-passing would save:

- The actual `writeOne` template has 584 280 calls totalling 204.5 ms
  aggregate — but the vast majority of those are bucket-merge background
  threads, not the on-apply-path `mergeInMemory put loop`.
- Of the 73.4 ms in `mergeInMemory put loop`, the `out.put(...)` body
  is dominated by `xdr_size`/`writeOne`/SHA256 — the cache-cold reread of
  `mergedEntries` is at most a small fraction (~10–20 % of those 73 ms).
- Even **eliminating the second pass entirely** — i.e. assuming we save the
  full 73 ms — translates to 73 ms / 5230 ms = **1.4 % of `applyLedger`
  wall time**, which is below the objective's Medium severity floor (3 %)
  and within Low (1–3 %) territory; the realistic saving (cache-cold
  reread only, ~10–20 ms) is well below the 1 % benchmark-noise floor.
- `addLiveBatch`-class optimisations have been investigated repeatedly
  (fail records 011, 002, 003, 021, 006); the meta-pattern is that
  on-apply-path bucket work is below Medium for the soroswap baseline.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior bucket fails (011 async-add-live-batch,
002/003 async-level0-file-write, 006 parallelize-fresh-encode-hash, 021
third-async-future); none of those proposed fusing the two passes.

### Why It Failed

The realistic saving (re-reading the cache-cold `mergedEntries` vector
during the put loop) is a small fraction of the 73 ms put-loop total — the
put-loop time is dominated by per-entry XDR encoding + SHA256 + `writeOne`
work that cannot be skipped. Even an upper-bound saving of the entire
73 ms second pass is 1.4 % of `applyLedger`, below the objective's Medium
floor; the actually-achievable saving (~10–20 ms) is below the 1 %
benchmark noise floor. Per fail meta-pattern, on-apply-path bucket work
at this baseline does not clear Medium without a structural change.

### Lesson Learned

When two passes share a hot vector, only the *cache-cold reread* portion
of the second pass is reclaimable by fusion — not the inner work. Quantify
the fraction of the second pass that is data-touch vs. inner-compute
before proposing fusion. For apply-path bucket work, the per-entry
encode/hash dominates and fusion savings are sub-noise.
