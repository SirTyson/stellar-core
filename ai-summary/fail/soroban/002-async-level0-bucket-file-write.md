# H002: Move level-0 in-memory bucket file write/hash off the apply thread

**Date**: 2026-04-28
**Subsystem**: bucket / ledger apply path
**Severity**: Medium
**Impact**: Hot-path serial bucket write inside `addLiveBatch`; projected ~5 ms/ledger ≈ 7% reduction in soroswap apply time.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::mergeInMemory` produces a `mergedEntries` vector that is the authoritative in-memory representation of the new level-0 `curr` bucket; the on-disk file written by `LiveBucketOutputIterator` is only required when (a) some downstream consumer needs to read the bucket from disk (catchup, history publish) or (b) the bucket hash is needed (consumed in `BucketManager::snapshotLedger`/BucketList hash computation in `sealLedgerTxnAndStoreInBucketsAndDB`). The expected design is to overlap the file-write + incremental-hash work with subsequent independent apply-thread work (e.g. `inMemoryStateUpdateFuture.get()`, `hotArchiveBatchFuture.get()`, the SQL `unsealHeader` callback, `storePersistentStateAndLedgerHeaderInDB`) and to join only at the first point that actually needs the new bucket hash, rather than blocking on the entire write loop synchronously inside `addLiveBatch`.

## Mechanism

In `LiveBucket::mergeInMemory` (`src/bucket/LiveBucket.cpp:614-698`), the merge step (synchronous, fast) is followed by a serial `out.put(e)` loop (`src/bucket/LiveBucket.cpp:677-683`) which performs XDR serialization, incremental SHA256 hashing, and `write()`/`fwrite()` syscalls inside `BucketOutputIterator::put` and ultimately `BucketOutputIterator::flushFileChanges`. Tracy shows this serial work — `mergeInMemory put loop` (~92 ms) plus the `flushFileChanges` it eventually triggers (~96 ms) — runs inside `addLiveBatch`, which is itself a serial step inside `finalizeLedgerTxnChanges` (`src/ledger/LedgerManagerImpl.cpp:3356`) that the apply thread waits on before returning. Meanwhile `inMemoryStateUpdateFuture` and `hotArchiveBatchFuture` are *already* async (lines 3285-3292, 3345-3352), so the apply thread is otherwise free between addLiveBatch start and the join points at lines 3361/3365. Backgrounding the put-loop+flush work onto its own `std::async`, joined just before the bucket hash is consumed (`mApp.getBucketManager().snapshotLedger(lh)` in `sealLedgerTxnAndStoreInBucketsAndDB` callback at `src/ledger/LedgerManagerImpl.cpp:3414`), eliminates that serial wait and overlaps it with the existing parallel work.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`, soroswap scenario, 4000 tx/ledger, 8 threads). Observe Tracy zones inside `applyLedger`:
- `addLiveBatch` — ~7.6 ms/ledger
- `mergeInMemory put loop` — 92 ms total / 65 ledgers ≈ 1.4 ms/ledger
- `flushFileChanges` — 96 ms total / 65 ledgers ≈ 1.5 ms/ledger
- Plus serialization/hash inside `writeOne` accounting for further per-entry cost.

After the change, expect `addLiveBatch` to drop to ~2 ms/ledger and `mergeInMemory` to spawn a background task that the next stage (`snapshotLedger`) joins.

## Target Code

- `src/bucket/LiveBucket.cpp:614-698` — `mergeInMemory`: split into a synchronous merge phase that returns immediately with a `std::future<std::shared_ptr<LiveBucket>>` for the file-backed bucket, plus an in-memory bucket descriptor usable by readers that don't need the file yet.
- `src/bucket/BucketOutputIterator.cpp:78-200` — `put` / `flushFileChanges` / `getBucket`: the serial XDR-write + incremental-hash work to background.
- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal` / `prepareFirstLevel` / `commit`: must accept the future or hold the in-memory representation until the future resolves.
- `src/ledger/LedgerManagerImpl.cpp:3356` — `addLiveBatch` call site; new join point should be around `src/ledger/LedgerManagerImpl.cpp:3414` (`snapshotLedger`).
- `src/bucket/BucketManager.cpp` — `snapshotLedger` / `addLiveBatch`: needs to join the future before returning bucket hash.

## Evidence

- Tracy (soroswap, `02-soroswap-tx-4000-t-8.tracy`):
  - `addLiveBatch` self-time: 502 ms / 65 = 7.7 ms/ledger; ~12% of `applyLedger` mean (66.6 ms/ledger).
  - `mergeInMemory put loop` (92 ms) + `flushFileChanges` (96 ms) inside it ≈ 3 ms/ledger directly attributable to the file-write portion.
  - The existing async pattern in `finalizeLedgerTxnChanges` (`hotArchiveBatchFuture` at lines 3285-3292; `inMemoryStateUpdateFuture` at lines 3345-3352) demonstrates that parallel buckets/in-memory-state work is already an accepted pattern — extending the same pattern to the level-0 file write is a small architectural delta.
  - The level-0 in-memory merge already constructs the index on a worker thread (`indexFuture` at `src/bucket/LiveBucket.cpp:667-670`); the same async machinery can host the file write/hash.
- Determinism: every node performs the same merge, produces the same `mergedEntries`, writes the same XDR bytes in the same order, and computes the same SHA256 — backgrounding the I/O does not change the bytes hashed or the order.

## Anti-Evidence

- The bucket hash is consumed inside `snapshotLedger` (lh.bucketListHash) and the LedgerHeader-stored hash IS persisted, so the join must occur before LedgerHeader hash computation. There is genuine work between addLiveBatch and that join — `inMemoryStateUpdateFuture.get()`, `hotArchiveBatchFuture.get()`, `getAllEntries` sealing of ltx, `addAnyContractsToModuleCache` — which gives the background write some headroom but the headroom is finite. Net savings depend on actual overlap.
- Failure-mode handling: a background `std::async` that throws (disk-full, fsync error) needs to surface the exception at the join point in `snapshotLedger`. Not architecturally hard but requires careful exception propagation and rollback semantics.
- Prior fail H011 backgrounded *all* of `addLiveBatch` including `prepareFirstLevel` work. This hypothesis is narrower: it backgrounds only the post-merge file-write/hash portion (the 3 ms+ tail), keeping `prepareFirstLevel`'s critical-section bookkeeping on the apply thread. Prior fail H012 backgrounded `forgetUnreferencedBuckets`, an unrelated path.
- The bucket file may also be needed for `BucketManager::scanForEvictionLegacy` or hot-archive operations; if any sibling apply-thread work reads the new level-0 bucket from disk before `snapshotLedger`, the join point must move earlier or those reads must use the in-memory `mergedEntries` directly. Worth verifying during PoC.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — narrower than the prior `fail/soroban/003-async-addLiveBatch.md`, which offloaded the whole live-bucket batch and joined at the end of finalization.
**Failed At**: reviewer

### Trace Summary

The claimed synchronous work exists: `finalizeLedgerTxnChanges()` calls `BucketManager::addLiveBatch()` on the apply thread, level 0 uses `prepareFirstLevel()`, and the in-memory merge writes the merged bucket file before the level can commit a hashed `LiveBucket` as `curr`. `BucketOutputIterator::put()` serializes and hashes each buffered entry through `XDROutputFileStream::writeOne()`, and `getBucket()` closes the stream, which flushes and optionally fsyncs before `adoptFileAsBucket()` installs the canonical bucket. However, the proposal only targets a subset of `addLiveBatch`, and the entire previously measured `addLiveBatch` zone was already below the objective's Medium threshold when measured against the apply-load top-line time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3322-3367` — finalization seals the ledger transaction, starts the in-memory Soroban-state update asynchronously, updates the module cache, calls `addLiveBatch()` synchronously, then waits for hot-archive and in-memory futures.
- `src/ledger/LedgerManagerImpl.cpp:3408-3418` — `snapshotLedger()` is called immediately after finalization returns, before the ledger header and HAS are stored in the database.
- `src/bucket/BucketManager.cpp:1026-1045` — `addLiveBatch()` delegates to `LiveBucketList::addBatch()` and records bucket metrics.
- `src/bucket/BucketListBase.cpp:196-238` — live level-0 `prepareFirstLevel()` builds a fresh in-memory snap bucket, calls `LiveBucket::mergeInMemory()`, and stores the returned bucket in `mNextCurr`.
- `src/bucket/BucketListBase.cpp:169-190` and `src/bucket/BucketListBase.cpp:781-783` — `commit()` immediately promotes the returned level-0 bucket to `mCurr`, so the current API requires a usable `LiveBucket` before `addBatchInternal()` returns.
- `src/bucket/LiveBucket.cpp:613-698` — `mergeInMemory()` merges entries in memory, starts index construction asynchronously, then synchronously constructs `LiveBucketOutputIterator`, runs the `out.put(e)` loop, waits for the index future, and calls `out.getBucket()`.
- `src/bucket/BucketOutputIterator.cpp:78-180` — `put()` performs protocol checks, deduplicates adjacent keys, and writes buffered entries via `mOut.writeOne()`; `getBucket()` writes the final buffered entry and closes the output stream.
- `src/util/XDRStream.h:307-320` and `src/util/XDRStream.h:483-515` — closing the stream flushes and optionally fsyncs; `writeOne()` computes the XDR size, serializes into a buffer, writes bytes, and adds the same bytes to SHA256.
- `src/bucket/BucketManager.cpp:1103-1134` and `src/bucket/BucketListBase.cpp:507-518` — `snapshotLedger()` consumes the bucket-list hash, which is the first hard point where a deferred level-0 bucket hash must be available.
- `src/simulation/ApplyLoad.cpp:2301-2308` — the model-tx benchmark drains pending bucket-list futures before reading the close/apply timer, reinforcing that benchmark severity must be judged against the reported top-line close time rather than unrelated setup or background work.
- `ai-summary/fail/soroban/003-async-addLiveBatch.md:58-69` — prior review data bounds the whole `addLiveBatch` zone at about 7.6 ms per ledger, 1.3% of the 596 ms top-line baseline, and notes that joining with existing async siblings captures less than the full zone.

### Why It Failed

The inefficiency is real but below the objective severity threshold. This proposal can only hide the level-0 file-write/hash tail, while the prior broader `addLiveBatch` investigation established that the entire live-bucket batch zone was about 7.6 ms per ledger, or roughly 1.3% of the apply-load top-line baseline. A subset of that work cannot plausibly produce the required 3-10% Medium reduction, and the claimed 7% projection uses the much smaller Tracy `applyLedger` zone denominator rather than the objective's `scripts/run_apply_load_matrix.py` apply-time metric.

The available overlap window is also limited. After `addLiveBatch()` returns, finalization only waits for the already-started hot-archive and in-memory Soroban-state futures before `snapshotLedger()` needs the bucket-list hash; moving the join from the bottom of finalization to `snapshotLedger()` adds essentially no additional work to hide behind. The change would require invasive new level-0 placeholder/future plumbing across `BucketLevel`, bucket hash computation, and bucket adoption, but its best-case savings remain below the Medium floor.

### Lesson Learned

For optimize-soroswap, bucket sub-zones must be normalized against the benchmark's reported apply-load time, not only against an inner Tracy zone. If a proposed optimization is a subset of a previously rejected whole-zone async upper bound, it needs new timing evidence showing that subset independently clears the 3% floor; otherwise it remains below threshold even when the underlying synchronous work is real.
