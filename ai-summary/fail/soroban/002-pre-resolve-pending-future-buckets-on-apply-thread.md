# H002: Pre-resolve pending FutureBuckets at applyLedger entry to overlap bucket merge waits with apply work

**Date**: 2026-04-28
**Subsystem**: bucket / ledger (apply-thread BL commit)
**Severity**: Medium
**Impact**: 3–6% reduction in soroswap apply time by moving the synchronous FutureBucket::resolve wait off the apply critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketLevel::commit()` (`src/bucket/BucketListBase.cpp:169-191`) is
called from `BucketListBase::addBatchInternal`
(`src/bucket/BucketListBase.cpp:728-772`, line 768) for each level
that should spill in the current ledger. The call walks the
`std::variant` for `mNextCurr`; when the variant holds a
`FutureBucket<BucketT>` (the asynchronous-merge case), `commit()`
calls `arg.resolve()` (`BucketListBase.cpp:185`) which in turn calls
`mOutputBucketFuture.get()` (`src/bucket/FutureBucket.cpp:292`).
If the background merge has not completed, this call **blocks the
apply thread** until the merge finishes.

The expected behavior is that this block should not appear on the
apply critical path: bucket merges run on the BucketManager's worker
pool and have one full ledger of wall time to complete before the
next ledger's `addBatchInternal` needs them, but in the soroswap
benchmark the apply window per ledger (~66 ms) is shorter than the
slow-tail merges, so `commit()` waits.

After this optimization, `applyLedger` (or, more precisely, the
earliest possible point in `closeLedger` after the next ledger's
`LedgerTxnRoot` snapshot is taken) calls a new
`BucketList::resolveAllPendingMerges()` helper that synchronously
joins on **every pending FutureBucket on every level** *before any
apply work begins*. Because the resolve call happens before parallel
apply, the wait runs in parallel with prefetch / fee processing /
nothing-else (it is moved out of the post-apply finalization window),
and the subsequent `addBatchInternal` `commit()` calls hit the
already-resolved fast path at `FutureBucket.cpp:282-285`
(`if (mState == FB_LIVE_OUTPUT) return mOutputBucket;`).

## Mechanism

Tracy zone `resolve,bucket/FutureBucket.cpp,278` reports
**277 ms self-time across 69 calls (mean 4.02 ms/call)** in the
current accepted trace. With 65 ledgers measured, the per-ledger
mean is ~4.3 ms/ledger waiting on background bucket merges from
inside `addLiveBatch -> addBatchInternal -> BucketLevel::commit ->
FutureBucket::resolve`. The parent zone `addLiveBatch` consumes
**502 ms / 4.33 s applyLedger = 11.6%** of the apply critical
path; subtracting the unavoidable in-memory merge work
(`mergeInMemory` 171 ms) and the `convertToBucketEntry` /
`addLiveBatch` accounting overhead, the **resolve wait is the
single largest deferrable component**. The mean of 4.0 ms/call ×
~1.06 calls/ledger gives ~4.3 ms/ledger / 66 ms applyLedger ≈
**6.5% of applyLedger**. Even if we capture only the median (mean
4.02 ms includes one tail event of 87.8 ms), the per-ledger steady-
state savings clear the 3% Medium threshold.

The code path:

- `LedgerManagerImpl::finalizeLedgerTxnChanges`
  (`src/ledger/LedgerManagerImpl.cpp:3217-3368`, line 3356) calls
  `BucketManager::addLiveBatch` synchronously on the apply thread.
- `addLiveBatch` calls
  `LiveBucketList::addBatch -> addBatchInternal`
  (`src/bucket/BucketListBase.cpp:684`).
- `addBatchInternal` first calls `resolveAnyReadyFutures()`
  (line not shown but documented at `BucketListBase.cpp:616`)
  which is **non-blocking** — it sweeps only futures that are
  already done and returns immediately for futures that aren't.
- The spill loop at lines 728-772 then calls `mLevels[i].commit()`
  for every spilling level. **Each `commit()` blocks** on
  `arg.resolve()` for any future that wasn't ready when
  `resolveAnyReadyFutures()` ran.
- The fix: insert a new pre-apply step (called near the start of
  `LedgerManagerImpl::applyLedger`, immediately after acquiring
  the apply LTX) that walks every level's `mNextCurr`, and for any
  `FutureBucket` in the `FB_LIVE_INPUTS` state, calls
  `resolve()` synchronously **before parallel apply starts**. This
  shifts the wait into a window that is currently nearly idle on
  the apply thread (it overlaps with the apply thread's own
  prefetch and fee-processing work that doesn't depend on the
  bucket list contents being committed).

Determinism is preserved trivially: the merged bucket content is a
pure function of the input buckets and the merge protocol. Calling
`resolve()` earlier in the same ledger does not change the
resulting bucket — only when the apply thread waits for it. The
`FutureBucket` state-machine (`FutureBucket::checkState`) accepts
`resolve()` from any single thread; the implementation is
idempotent only in the `FB_LIVE_OUTPUT` state, so the pre-apply
resolve must run on the same apply thread as the later `commit()`
to avoid a data race on `mState`. This is satisfied because both
the new pre-apply call and the existing `addBatchInternal::commit()`
run on the apply thread.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py --mode soroswap`, TX=4000, T=8).
Tracy zone `resolve,bucket/FutureBucket.cpp,278` should drop to
near zero in the apply path (the resolve work is shifted earlier in
the ledger but recorded under a new zone, e.g.,
`preApplyResolveFutures`). The `addLiveBatch` zone should drop by
~270 ms cumulative (~4 ms/ledger), and the `applyLedger` zone
should fall by 3–6%. Run benchmarks ≥3 times to confirm the win
exceeds the Medium threshold and survives noise.

## Target Code

- `src/bucket/BucketListBase.cpp:169-191` — `BucketLevel::commit`,
  the apply-thread blocking point. Today the synchronous
  `arg.resolve()` is inside `commit()`; the optimization keeps
  this call but ensures that by the time `commit()` is reached,
  the future is in `FB_LIVE_OUTPUT` so the resolve is a fast
  return.
- `src/bucket/BucketListBase.cpp:728-772` — `addBatchInternal`
  spill loop that calls `commit()` per level. The pre-apply
  resolve walks the same set of levels so no future is missed.
- `src/bucket/BucketListBase.cpp:603-633` — existing
  `resolveAllFutures` / `resolveAnyReadyFutures` /
  `futuresAllResolved` helpers. The new
  `resolveAllPendingMerges()` is a thin wrapper over
  `resolveAllFutures` (not the non-blocking variant), called at a
  different point in the ledger lifecycle.
- `src/ledger/LedgerManagerImpl.cpp` — `applyLedger` (entry point
  near line 1648), insert one call to
  `mApp.getBucketManager().getLiveBucketList().resolveAllPendingMerges()`
  after the apply LTX is set up but before
  `applyTransactions`. (Same call could be made for the hot
  archive bucket list if its `commit()` also blocks; Tracy shows
  hot-archive resolve traffic is negligible, so this hypothesis
  scopes the fix to live buckets.)
- `src/bucket/FutureBucket.cpp:274-304` — `resolve()`
  implementation; idempotent in `FB_LIVE_OUTPUT`, single-shot in
  `FB_LIVE_INPUTS`. The new pre-apply call drives the
  state-machine transition once on the apply thread; the later
  `commit()`-driven `resolve()` becomes a fast return.

## Evidence

- Tracy zone `resolve,bucket/FutureBucket.cpp,278` self = 277 ms
  across 69 calls (mean 4.02 ms, max 87.8 ms) in the current
  accepted trace. The trace is the `final_review`-published
  baseline at
  `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`.
- `addLiveBatch` self+children total = **502 ms / 4.33 s
  applyLedger = 11.6%** of the apply critical path
  (zone `addLiveBatch,bucket/BucketManager.cpp,1031`). Subtracting
  `mergeInMemory` (171 ms) and `convertToBucketEntry` /
  related accounting (~50 ms), `resolve` is the single largest
  remaining synchronous cost.
- `resolveAnyReadyFutures` (`BucketListBase.cpp:618`) self =
  13 µs across 65 calls — proves the existing periodic sweep
  catches only already-done futures and does not contribute to the
  blocking wait. The blocking wait is exclusively in the
  `commit() -> resolve()` path.
- `resolveAllFutures` (`BucketListBase.cpp:603`) already exists
  and is a tested helper that performs a synchronous wait on all
  pending futures. The optimization reuses an existing function;
  no new threading machinery is introduced.
- The `FutureBucket` resolve fast-return path
  (`FutureBucket.cpp:282-285`) handles the idempotent case where
  the future is already in `FB_LIVE_OUTPUT`, so calling `resolve()`
  twice on the apply thread is correct and cheap on the second
  call.

## Anti-Evidence

- The pre-apply resolve runs synchronously on the apply thread,
  so if a merge is *still* not done when applyLedger starts, the
  pre-apply wait is no faster than the deferred wait; it is only
  *moved earlier*. This is a real risk for ledgers where the
  merge is genuinely slower than the entire previous ledger's
  apply window. Mitigation: only ledgers whose previous-ledger
  spill is still in flight pay the cost; for those ledgers, the
  net wait is unchanged (we still wait, just earlier). For the
  common case where merges finish in well under one ledger
  (`mean 4.0 ms` is consistent with most futures completing
  quickly), the savings materialize.
- The objective explicitly notes that **bucket merge work that
  runs lazily on background threads is OUT_OF_SCOPE unless apply
  blocks on it**. This hypothesis targets *exactly* the blocking
  case (`BucketLevel::commit -> FutureBucket::resolve` is the
  apply thread waiting on a background merge); it is in scope by
  construction.
- The 87.8 ms tail event in `resolve` (max in the histogram)
  contributes ~31% of the cumulative `resolve` time; if that tail
  event happens to fall on an out-of-window ledger, the per-ledger
  steady-state win is closer to ~3% than ~6%. PoC must measure
  end-to-end median across ≥3 runs to confirm the Medium
  threshold.
- This hypothesis is **distinct** from
  `ai-summary/fail/soroban/003-async-addLiveBatch.md`. That fail
  proposed moving the entire `addLiveBatch` to a worker thread
  with a join inside `finalizeLedgerTxnChanges`; the join point
  was still on the apply critical path, so the gain was small.
  This hypothesis instead leaves `addLiveBatch` synchronous but
  removes its single largest internal blocking component
  (`resolve`) by moving the resolve call earlier in the ledger,
  not later — overlapping it with the apply thread's pre-apply
  setup work rather than trying to hide it on a worker.
- If the level whose merge is in flight changes within a single
  apply (e.g., new spills produced during apply by Soroban
  bucket-related side effects), the pre-apply resolve might miss
  a future that becomes pending later. Inspection of
  `addBatchInternal` shows that **only** `addBatchInternal`
  itself starts new merges (via `prepare`), so there are no
  in-apply transitions to `FB_LIVE_INPUTS` that the pre-apply
  resolve could miss.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; related `fail/soroban/003-async-addLiveBatch.md` targeted async offload of the whole live-bucket batch, not pre-resolving pending `FutureBucket`s.
**Failed At**: reviewer

### Trace Summary

The production bucket-list path can block exactly where the hypothesis says: `BucketLevel::commit()` resolves a live `FutureBucket`, and `FutureBucket::resolve()` waits on `mOutputBucketFuture.get()` when the background merge is not complete. However, the soroswap apply-load benchmark already drains both live and hot-archive bucket-list futures immediately before the measured `closeLedger()` call. Because the timer baseline is read after `resolveAllFutures()` and before `closeLedger()`, a new `applyLedger`-entry pre-resolve would normally see already-resolved futures in this objective's benchmark and would not remove 3-6% from measured apply time.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2265-2311` — the model-tx benchmark selects the close/apply timer, generates soroswap transactions, calls `getLiveBucketList().resolveAllFutures()` and `getHotArchiveBucketList().resolveAllFutures()`, then reads `timeBefore` and calls `closeLedger()`.
- `src/bucket/BucketListBase.cpp:601-610` — `resolveAllFutures()` synchronously resolves every currently merging future in all levels; this is the helper the apply-load benchmark already invokes outside the measured close.
- `src/bucket/BucketListBase.cpp:169-190` — `BucketLevel::commit()` sets curr from the variant; for a live `FutureBucket`, it calls `arg.resolve()` and can block if the future is still in `FB_LIVE_INPUTS`.
- `src/bucket/FutureBucket.cpp:274-303` — `FutureBucket::resolve()` fast-returns in `FB_LIVE_OUTPUT`, otherwise clears inputs and blocks on `mOutputBucketFuture.get()`.
- `src/bucket/BucketListBase.cpp:684-797` — `addBatchInternal()` spills levels by calling `snap()`, `commit()`, then `prepare()`; the final `resolveAnyReadyFutures()` sweep is non-blocking.
- `src/ledger/LedgerManagerImpl.cpp:1779-1785` and `src/ledger/LedgerManagerImpl.cpp:3217-3368` — the measured seal/bucket phase calls `finalizeLedgerTxnChanges()`, which invokes `BucketManager::addLiveBatch()` synchronously.
- `src/bucket/BucketManager.cpp:1026-1045` — `addLiveBatch()` delegates to `LiveBucketList::addBatch()` and then updates bucket metrics.

### Why It Failed

The proposed inefficiency is not present in the objective's measured hot path: apply-load model transactions pre-resolve all pending live and hot-archive bucket futures before starting the timer interval that includes `closeLedger()`. Any Tracy aggregate showing `FutureBucket::resolve` self-time can therefore include benchmark setup work outside the measured apply interval, and cannot be assumed to be an `addLiveBatch` child without checking zone nesting. Adding a production `resolveAllPendingMerges()` call at `applyLedger` entry would be a fast no-op for the soroswap benchmark after the existing pre-measure drain, so it cannot meet the Medium 3% apply-time threshold.

There is also no overlap created by the suggested placement in production: a synchronous resolve at the start of `applyLedger` runs on the same apply thread before prefetch, fee processing, and transaction apply. If a merge is unfinished, the same thread still waits; the wait is only relocated earlier inside `applyLedger`, not overlapped with independent apply-thread work.

### Lesson Learned

For bucket-performance hypotheses based on Tracy aggregates, verify both zone nesting and benchmark timer boundaries. `FutureBucket::resolve` is a real blocking operation in production, but the apply-load harness deliberately drains pending bucket futures before measuring each model ledger, so setup-time resolve samples are not automatically apply-time savings opportunities.
