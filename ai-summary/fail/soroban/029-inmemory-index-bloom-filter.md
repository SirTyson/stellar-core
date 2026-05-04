# H029: Per-bucket bloom filter for `InMemoryIndex` to skip empty-level scans

**Date**: 2026-05-03
**Subsystem**: soroban (bucket / apply path)
**Severity**: Low
**Impact**: apply-time reduction in classic-key BucketList lookups
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SearchableBucketListSnapshot::getBucketEntry` walks every BucketList level
(up to 22 levels × 2 buckets = 44 buckets) calling `bucket->getIndex().lookup(k)`
on each. For a `LiveBucketIndex` backed by a `DiskIndex`, a per-bucket Bloom
filter cheaply rejects keys that are not in the bucket *without* paying for
a full hash-table probe. For a `LiveBucketIndex` backed by an
`InMemoryIndex` (small buckets, < 20 MB), no Bloom filter exists — every
level walk does a full `std::unordered_set::find` even when the key is not
present. Ideally, the in-memory index would also skip negative lookups via
a tiny per-bucket Bloom filter, so an apply-path `getBucketEntry` walk
costs ~22 cheap rejections + 1 successful probe instead of ~22 full
unordered-set probes + 1 successful one.

## Mechanism

`InMemoryBucketState::scan` (`src/bucket/InMemoryIndex.cpp:251-262`) calls
`mEntries.find(searchKey)` unconditionally. `mEntries` is a
`std::unordered_set<InternalInMemoryBucketEntry, …>` (`InMemoryIndex.h:79-86`).
`find` hashes the key (~50 ns for ACCOUNT/TRUSTLINE — already noted in
fail #4), walks the chain, and compares cached entry hashes plus
`keyEquals`. A typical full negative probe is ~0.3–0.5 µs (cache misses on
the chain head dominate). A small Bloom filter probe (1 hash, ~3 bit
tests) is ~50–100 ns and almost always cache-hot. Replacing the negative
probes with Bloom filter rejections would shave ~0.3 µs × ~22 negative
levels per get = ~6.6 µs per `getBucketEntry`.

The deviation: the in-memory path currently spends *the same* per-call
cost on negative levels as on the one positive level, even though Bloom
filters already protect the disk path against exactly this asymmetry.

## Trigger

Any classic-entry lookup on a steady-state BucketList where the key
resides in a deep level — the soroswap benchmark exercises this on every
tx for source/op-source ACCOUNT and TRUSTLINE keys.

## Target Code

- `src/bucket/InMemoryIndex.cpp:241-262` — `InMemoryBucketState::insert` /
  `scan`. Bloom filter would be populated in `insert` and queried in
  `scan` before the `mEntries.find` call.
- `src/bucket/InMemoryIndex.h:79-115` — `InMemoryBucketState` class (would
  gain a `BloomFilter mBloomFilter` field).
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry`, the
  `bucket->getIndex().lookup(k)` call site that benefits.
- `src/bucket/DiskIndex.h:112-195` — existing `mBloomLookupMeter` /
  `markBloomMiss` pattern to mirror.

## Evidence

Tracy zones from accepted soroswap baseline trace (71 ledgers,
8 worker clusters):

| Zone | Total time | Calls | Per-call avg |
|---|---|---|---|
| `load` (`BucketListSnapshot.cpp:317`) | 2 324 ms | 521 715 | 4.5 µs |
| `getBucketEntry` (`BucketListSnapshot.cpp:174`) | 2 048 ms | 776 931 | 2.6 µs |
| `scan` (`InMemoryIndex.cpp:253`) | 1 952 ms | 926 932 | 2.1 µs |

So the worker-CPU aggregate spent in `InMemoryBucketState::scan` is
~1.95 s across the 70-ledger trace — the largest single classic-path
zone after `getBucketEntry` itself. The 926 932 / 776 931 = 1.19×
ratio of scans-to-gets confirms multi-level walks per get.

## Anti-Evidence

After amortising over `NUM_CLUSTERS = 8` workers, the classic-path
`scan` work is far below the Medium floor:

- Aggregate worker CPU saved (upper bound, *all* negative scans replaced
  by Bloom probes): ~22/23 of `scan` total time = ~1.86 s aggregate.
  Divided by 8-worker cluster parallelism: ~233 ms per-cluster wall over
  the whole 70-ledger trace = **~3.3 ms per ledger**.
- `applyLedger` per-ledger wall = 5230 ms / 71 = ~73.6 ms per ledger.
  Saving = 3.3 / 73.6 = **~4.5 % of `applyLedger`** — *would* be Medium
  if all the negative-scan time were truly reclaimable.
- BUT: the 2.1 µs avg `scan` cost is **dominated by Tracy `ZoneScoped`
  instrumentation overhead** (`InMemoryIndex.cpp:253`), not by the
  underlying `unordered_set::find`. With Tracy disabled, the actual
  `find` cost is closer to 0.3-0.5 µs per call. Bloom-filter savings
  scale with the *real* probe cost, not the instrumented cost — so the
  production-build saving is more like 0.5 µs × 22 negative levels ×
  10 942 gets/ledger / 8 workers = **~15 ms aggregate / 1.9 ms wall per
  ledger = 2.6 % of applyLedger** in the worst case, dropping further
  if the prod-build `find` dominates over the Bloom probe.
- Realistic estimate (negative-probe savings net of Bloom overhead and
  prod-vs-tracy correction): **~1–2 % of `applyLedger`** — Low tier,
  below the Medium floor required at the hypothesis stage.
- Adjacent fail records: #4 `cache-ledgerkey-hash-bucket-walk.md`
  rejected for similar reasons (ACCOUNT/TRUSTLINE key hash is ~50 ns,
  full-walk savings sub-1 %). Bloom filter generalises the same idea
  with marginally better numbers but still below the Medium threshold.
- Implementation also adds memory overhead per in-memory bucket
  (~bucket_size / 16 bytes for a 1 % FPR Bloom) — small but non-zero
  cost against a small wall-time saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — fail #4 (cache-ledgerkey-hash-bucket-walk) covered the
*hash-recompute* angle for the same level-walk; this Bloom-filter angle is
distinct (replacing negative probes wholesale, not caching the hash).
Success #001 `inmemory-bucket-scan-polymorphic-wrapper` removed virtual
dispatch on the scan but did not add a Bloom path.

### Why It Failed

The Tracy-measured `scan` cost is heavily inflated by `ZoneScoped`
instrumentation overhead in a 2.1 µs hot loop. After correcting for
production-build cost and amortising over 8-worker cluster parallelism,
the realistic apply-time saving is ~1–2 % — Low tier, below the
objective's Medium (3 %) hypothesis-stage floor. The same diminishing
return defeated fail #4 on the closely related hash-cache angle.

### Lesson Learned

For very-hot tight-loop zones (sub-µs body, hundreds-of-thousands of
calls), Tracy `ZoneScoped` overhead can be a large fraction of the
measured time — discount it heavily before estimating the production
saving from removing the *underlying* work. For BucketList classic-key
walks at the soroswap baseline, per-level micro-optimisations are
consistently below the Medium threshold; a structural change (e.g.,
merged top-N-level index, prefix routing) is the only path that could
clear it.
