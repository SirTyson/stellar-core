# H001: Parallelize addLiveBatch With Other Finalize Async Tasks

**Date**: 2026-05-26
**Subsystem**: soroban (ledger/bucket — finalizeLedgerTxnChanges critical path)
**Severity**: Medium
**Impact**: Apply-time reduction by tightening critical path of `finalizeLedgerTxnChanges` (~7.7% of apply window in soroswap)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges` should overlap *all three* mutually-independent
batch operations — `addHotArchiveBatch` (hot-archive bucketlist),
`updateInMemorySorobanState` (in-memory map), and `addLiveBatch`
(live bucketlist) — so that the apply thread waits on a single barrier
equal to **max(t_hotArchive, t_inMemory, t_liveBatch)** rather than
**t_liveBatch + max(t_hotArchive, t_inMemory)**. The data they consume —
the `initEntries`, `liveEntries`, `deadEntries` vectors produced by
`ltx.getAllEntries(...)` — is **const** and immutable after the
`getAllEntries` call seals the ltx, so the three operations have no
data dependency on each other. The next ledger's apply waits on a barrier
joining all three futures before returning.

## Mechanism

In `LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3217–3367`), only `addHotArchiveBatch`
(line 3285) and `updateInMemorySorobanState` (line 3345) are launched
via `std::async`; `addLiveBatch` (line 3356) runs **serially on the apply
thread before** the two `.get()` waits. The author comment at lines
3334–3339 explicitly notes that **"All three can run in parallel"** because
the three modify disjoint state (`mLiveBucketList`, `mHotArchiveBucketList`,
`mInMemorySorobanState`), and lines 3228–3229 already document
`addHotArchiveBatch` independence from `addLiveBatch`. Despite this stated
intent, the code leaves `addLiveBatch` serial. For soroswap (high
per-ledger write volume, ~14k Soroban tx applies across 71 ledgers),
`addLiveBatch` is the dominant component of the finalize zone, so making it
the third concurrent branch should reduce the finalize critical path to
roughly the single longest of the three tasks instead of a serial sum.

## Trigger

Soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, 2000 tx, 8-thread config) with the
trace at `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`.
The `finalizeLedgerTxnChanges` Tracy zone consumes **3.29% of total trace
time = ~7.7% of the `applyLedger` envelope**. The serial portion of
`addLiveBatch` on the apply thread is the targeted savings.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:finalizeLedgerTxnChanges:3217–3367` —
  the function where the serial-vs-async ordering decision is made.
  Specifically line 3356 (`addLiveBatch`) runs serially before the
  `.get()` joins at 3361/3365; move it into a third `std::async` launched
  immediately after `getAllEntries` returns (line 3332).
- `src/ledger/LedgerManagerImpl.cpp:3334–3339` — comment explicitly
  documenting that all three operations are independent and can run in
  parallel; the implementation does not match.
- `src/bucket/BucketManager.cpp:addLiveBatch` — confirm thread-safety
  precondition holds (already guaranteed by `ledgerApplied` mutex
  protecting `finalizeLedgerTxnChanges` per comment on line 3223).
- `src/bucket/LiveBucketList.cpp:addBatch` and
  `src/bucket/BucketSnapshotManager.cpp` — confirm that snapshot
  publication semantics still work when `addLiveBatch` runs on a worker
  thread joined at the same barrier as the other two.

## Evidence

1. **Author's stated intent**: lines 3334–3339 explicitly say "All three
   can run in parallel" yet `addLiveBatch` is left on the apply thread.
   This reads as an incomplete refactor — the in-memory state path was
   parallelized in a prior change but `addLiveBatch` was not converted
   in the same sweep.
2. **Tracy sizing**: `finalizeLedgerTxnChanges` self-time = **3.29% of
   trace ≈ 7.7% of apply window**. The serial-only component of
   `addLiveBatch` is the largest single contributor (bucket-level writes
   for all Soroban entries + per-tx fee/account changes). Even partial
   overlap with `inMemoryStateUpdate` (which also walks the same vectors)
   should hide a meaningful fraction of `addLiveBatch`'s wall time.
3. **Data independence already proven**: the comment at lines 3228–3229
   states `addHotArchiveBatch` is independent from `addLiveBatch`; both
   read the same const vectors but write to different containers. The
   same argument trivially extends to `inMemoryStateUpdate` (writes to
   `mInMemorySorobanState`).
4. **No new synchronization needed**: the vectors are by-reference
   captured `&` and never mutated after `getAllEntries`. `ledgerApplied`
   already holds the per-ledger mutex (line 3223) ensuring no concurrent
   `finalizeLedgerTxnChanges` invocation. `addLiveBatch` only takes its
   own internal bucket-level locks.
5. **Determinism preserved**: each of the three branches is a pure
   function of the same const inputs; their results are joined at a
   single barrier before the apply thread returns, so observable
   ledger state ordering is unchanged across nodes.

## Anti-Evidence

1. **Apply thread is not idle during current serial `addLiveBatch`** —
   it's possible the comment at lines 3334–3339 was added *aspirationally*
   and an earlier engineer determined `addLiveBatch` couldn't safely run
   off the apply thread due to a snapshot-publication ordering issue with
   `BucketSnapshotManager`. Need to verify that `LiveBucketList::addBatch`
   does not implicitly assume execution on a specific thread.
2. **`addAnyContractsToModuleCache` (lines 3354–3355)** is currently
   between `getAllEntries` and `addLiveBatch`. It walks the same vectors
   on the apply thread. After the proposed change, this would run
   concurrently with all three async tasks. It mutates the **module
   cache** (`mApplyState`) which is read by the next ledger's apply path;
   this must be sequenced before the next apply, but the barrier already
   exists at function exit. **No new race expected**, but worth verifying
   `addAnyContractsToModuleCache` doesn't share mutable state with
   `addLiveBatch` (it shouldn't — module cache lives in `mApplyState`,
   buckets live in `mBucketManager`).
3. If `addLiveBatch` is already dominated by `inMemoryStateUpdate` (i.e.
   `t_inMemory >= t_liveBatch`), parallelizing it yields zero gain because
   the inMemory branch was already the critical path. Need to measure
   relative branch durations.
4. **Worker thread availability**: `std::async(std::launch::async, ...)`
   spawns a new thread or pulls from the implementation pool. For each
   ledger we'd briefly hold three worker threads simultaneously. This is
   within budget (no `NUM_CLUSTERS` constraint at this layer — clusters
   are about parallel-apply workers), but allocation overhead should be
   measured.
5. **Meta-pattern fingerprint**: This hypothesis does not match any of the
   16 Meta-Patterns in `ai-summary/fail/soroban/summary.md` — it is not a
   sub-ms serial path, not a SHA256/budget micro-op, not a bucket-merge
   background task, not a parallelism-vs-determinism risk. The closest
   prior work is success/002 (parallelizing in-memory state update), and
   this hypothesis is the natural next step in the same series.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` row `021-addlivebatch-as-third-async-future.md`
**Failed At**: reviewer

### Trace Summary

The checked-out code still has the shape described by the hypothesis: `finalizeLedgerTxnChanges` seals the `LedgerTxn` with `getAllEntries`, starts `updateInMemorySorobanState` asynchronously, performs module-cache updates on the apply thread, then runs `BucketManager::addLiveBatch` synchronously before joining the existing hot-archive and in-memory futures. `addLiveBatch` delegates to `LiveBucketList::addBatch`, which performs the live bucket-list mutation and level-0 work synchronously while only deeper bucket merges become `FutureBucket` background work. After `finalizeLedgerTxnChanges` returns, `sealLedgerTxnAndStoreInBucketsAndDB` snapshots the live/hot bucket-list hashes and constructs the new immutable `CompleteConstLedgerState`, so all three branch effects must still be joined before that point. This exact "make addLiveBatch a third async future" mechanism has already been retained in the soroban fail summary and rejected for insufficient impact.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges` launches `addHotArchiveBatch` and `updateInMemorySorobanState` via `std::async`, leaves `addLiveBatch` synchronous, then joins both futures before returning.
- `src/ledger/LedgerManagerImpl.cpp:3408-3418` — `sealLedgerTxnAndStoreInBucketsAndDB` calls `finalizeLedgerTxnChanges`, then unseals the header, snapshots bucket-list hashes, stores HAS/header state, and builds the next apply snapshot.
- `src/bucket/BucketManager.cpp:1025-1046` — `addLiveBatch` updates metrics, delegates to `mLiveBucketList->addBatch`, and reports live bucket/index metrics.
- `src/bucket/LiveBucketList.cpp:14-27` — `LiveBucketList::addBatch` calls `addBatchInternal` and initializes caches for newly-added buckets.
- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal` performs spill/commit/prepare sequencing, does level-0 `prepareFirstLevel` and `commit` synchronously, and only resolves already-ready futures non-blockingly.
- `src/ledger/LedgerStateSnapshot.cpp:347-377` — `CompleteConstLedgerState` materializes immutable live and hot-archive bucket-list snapshot data after bucket-list mutation has completed.
- `ai-summary/fail/soroban/summary.md:54` — prior retained fail `021-addlivebatch-as-third-async-future.md` covers the same change and rejects it because the maximum recoverable overlap is bounded by already-async `addHotArchiveBatch` at 38 ms across 70 ledgers, about 0.74% of `applyLedger`.

### Why It Failed

This is a duplicate of an already-investigated soroban performance hypothesis. The prior retained fail directly matches the proposed mechanism ("Run `addLiveBatch` as a third async future alongside `addHotArchiveBatch` and `updateInMemorySorobanState`") and concluded that, even if mechanically correct, the only additional wall-time recoverable is the duration of the second-largest already-independent branch. That bound is about 0.74% of `applyLedger`, which is below the objective's 1% noise floor and far below the required 3% Medium threshold.

### Lesson Learned

For async fan-out in `finalizeLedgerTxnChanges`, the relevant upper bound is not the total `addLiveBatch` duration but the work it can newly overlap with. Because the current independent branches are already small, making the largest branch asynchronous cannot produce a Medium soroswap apply-time win unless another substantial independent apply-thread task is also deferred behind the same barrier.
