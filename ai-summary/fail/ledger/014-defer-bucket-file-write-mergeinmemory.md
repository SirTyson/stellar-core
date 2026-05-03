# H014: Defer On-Disk File Write of Level-0 In-Memory Bucket Merge

**Date**: 2026-05-02
**Subsystem**: ledger / bucket
**Severity**: Low
**Impact**: apply-time (synchronous-bucket-finalize)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The synchronous portion of `LiveBucket::mergeInMemory` should do only the
work that the apply path actually depends on before `addLiveBatch` returns:
producing a `LiveBucket` whose in-memory entries and index are populated, and
whose hash is finalized (because `snapshotLedger` reads the new BucketList
hash immediately afterward in `sealLedgerTxnAndStoreInBucketsAndDB`). On-disk
persistence of the bucket file is needed only for restart correctness and
could in principle run on a background thread without the apply path waiting
on it.

## Mechanism

Currently `LiveBucket::mergeInMemory` (`src/bucket/LiveBucket.cpp:614-698`)
runs a `LiveBucketOutputIterator out(...)` open on `apply` thread, then a
`put(e)` loop that, per entry, XDR-encodes the entry into a stream buffer,
updates a SHA-256 hash, and writes the bytes to the bucket file. The
finalize step (`out.getBucket(...)`) closes/syncs the file and seals the
hash. By splitting the loop so the apply thread only XDR-encodes + hashes
into an in-memory byte buffer, and a background worker performs the actual
file write + fsync, we would remove file I/O latency from the critical
path. The hash and the in-memory bucket would still be ready synchronously
for `snapshotLedger`.

## Trigger

Soroswap apply-load benchmark: every closed ledger calls `addLiveBatch` once,
which always exercises `mergeInMemory` for the level-0 in-memory bucket.

## Target Code

- `src/bucket/LiveBucket.cpp:614-698` — `LiveBucket::mergeInMemory` put loop
  and `out.getBucket(...)` finalize.
- `src/bucket/BucketOutputIterator.cpp` — `LiveBucketOutputIterator::put`
  interleaves XDR encode, hash update, and `mOut.writeOne` into a single
  per-entry call.
- `src/ledger/LedgerManagerImpl.cpp:3354-3365` — `addLiveBatch` is awaited
  synchronously immediately before `snapshotLedger`.

## Evidence

Tracy (soroswap, T=8): `applyLedger` total ≈ 5,230 M ns. `addLiveBatch` is
296 M ns (5.66%); inside it, `prepareFirstLevel` is 178 M ns and
`mergeInMemory` is 138 M ns. The `mergeInMemory put loop` zone is 73 M ns
(1.4% applyLedger) and the implicit finalize / fclose work in `getBucket`
adds roughly another 30–40 M ns. Of the put-loop time, file-I/O bytes go
through buffered streams; on Linux with default page cache, the
write+memcpy portion of each `put` call is a measurable but small slice of
each entry's cost.

## Anti-Evidence

The branch already runs `addHotArchiveBatch` and `updateInMemorySorobanState`
asynchronously alongside `addLiveBatch` (`LedgerManagerImpl.cpp:3286-3365`),
so the "easy" overlap wins on this critical section are already taken.
`LiveBucketOutputIterator::put` was deliberately written to interleave
serialize+hash+write so a single XDR pass produces both the file bytes and
the hash; splitting them requires either two passes (paying the encode cost
twice) or buffering the encoded bytes (extra allocation per merged entry,
~15–40 M ns of allocator pressure). `out.getBucket()` also closes the
output stream synchronously to obtain the hash; deferring fclose/fsync to a
background thread is feasible but requires `LiveBucket` to hold a
`std::future<void>` and gate destruction / restart-time validation on its
completion. Earlier fail entries (notably fail/008 on the addLiveBatch put
loop) already concluded the put loop is sub-Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (fail/008 targeted
parallelizing the put loop itself; this targets deferring file I/O).

### Why It Failed

Quantified upper bound is below the Medium threshold. Even fully eliminating
synchronous file I/O from `LiveBucketOutputIterator::put` and
`out.getBucket()` recovers at most the file-I/O fraction of the put loop
plus the fclose/fsync portion of `getBucket()`: roughly 50–60 M ns / ledger
on the soroswap trace, ≈ 1.0–1.2% of `applyLedger`. That is firmly Low (and
arguably within benchmark noise). The implementation cost is non-trivial:
splitting `LiveBucketOutputIterator::put` into "encode+hash" vs "write"
phases changes a hot, well-tested code path used by every node, requires
buffering all encoded entry bytes in memory (extra allocations partially
offset the savings), and introduces a new background-write future that
restart and bucket-GC paths must coordinate with. The risk/reward is poor
relative to the SEVERITY_SCALE bar.

### Lesson Learned

`mergeInMemory`'s synchronous cost is dominated by XDR encoding and hash
update, not by buffered file I/O. Future "move bucket work off apply
thread" attempts should target the encode/hash work itself (e.g.,
parallel-encode across `NUM_CLUSTERS` workers, then sequential
hash+write), or look further upstream at why `freshInMemoryOnly` +
`mergeInternal` together cost ~58 M ns before the put loop even starts —
not at the file-write tail.
