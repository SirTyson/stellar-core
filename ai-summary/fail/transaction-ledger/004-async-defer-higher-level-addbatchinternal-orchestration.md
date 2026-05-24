# H004: Async-Offload Per-Level `snap()`/`commit()`/`prepare()` Orchestration in `addBatchInternal` Higher Levels

**Date**: 2026-05-24
**Subsystem**: transaction-ledger (bucket)
**Severity**: Medium (initial projection) — re-sized to Low (sub-1.9 ms/ledger ceiling) on review
**Impact**: shorten-mandatory-bucket-write-chain
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`BucketListBase<LiveBucket>::addBatchInternal`
(`src/bucket/BucketListBase.cpp:684-797`) runs synchronously on the
apply thread inside `finalizeLedgerTxnChanges`. For levels 1..N (the
"higher-level" promotion loop at line 728), the work consists of
calling `snap()`, `commit()`, and `prepare()` on each level that
fires a spill event for the current ledger (`levelShouldSpill`).
`prepare()` launches a `FutureBucket` merge on a background worker
(`BucketLevel::prepare` schedules `BucketBase::merge` via
`bucketManager.getWorkerIOContext()`) and immediately returns —
only the small bookkeeping (snap/commit pointer rotation, future
construction, shadow-list maintenance, level-i promotion) should
remain on the apply thread. Per the
`addLiveBatch → snapshotLedger → bucketListHash` chain (Meta-Pattern
26), only level-0 work that produces the new top-of-bucket-list hash
is mandatory-sync; higher-level FutureBucket bookkeeping should be
small relative to the level-0 in-memory merge.

## Mechanism

Tracy decomposition for the current soroswap baseline shows:

- `addBatchInternal` total = 329 ms / 72 ledgers ≈ **4.57 ms/ledger**
- `prepareFirstLevel` (level-0) total = 189 ms / 72 ≈ **2.63 ms/ledger**
- Residual higher-level work (`addBatchInternal` minus
  `prepareFirstLevel`) = 329 − 189 = **140 ms / 72 ≈ 1.95 ms/ledger**

That ~1.95 ms/ledger covers the level-1..N `snap()`/`commit()`/
`prepare()` loop, the shadow-vector construction at lines 691-696,
and the `resolveAnyReadyFutures` call at line 795. These all run on
the apply thread between the (apply-thread-mandatory) input vector
production and the (apply-thread-mandatory) `snapshotLedger` call.

The deviation from the expected "small bookkeeping" picture is that
`prepare()` performs file I/O setup (output-iterator construction
preconditions, shadow vector copy/sort) and `snap()`/`commit()`
manipulate `shared_ptr<Bucket>` chains under `BucketSnapshotManager`
locks. Some of this could in principle be deferred to a worker
thread that runs in parallel with the (separately-async)
`addHotArchiveBatch` and `updateInMemorySorobanState` futures
already launched in `finalizeLedgerTxnChanges` (LedgerManagerImpl.cpp:3217).

## Trigger

Profile the bucket-write chain inside `finalizeLedgerTxnChanges`
on soroswap-2000-t-8 with NUM_CLUSTERS=8; observe that the
higher-level addBatchInternal loop accounts for ~1.95 ms/ledger
of apply-thread synchronous work between `prepareFirstLevel` and
`snapshotLedger`.

## Target Code

- `src/bucket/BucketListBase.cpp:684-797`
  `addBatchInternal` — the loop at line 728 + shadow setup + resolve
- `src/bucket/BucketLevel.cpp` (snap/commit/prepare)
  Per-level bookkeeping that runs on apply thread
- `src/ledger/LedgerManagerImpl.cpp:3217` (`finalizeLedgerTxnChanges`)
  The call site whose synchronous critical path includes addLiveBatch
  (and hence addBatchInternal)

## Evidence

- 140 ms of `addBatchInternal` self-time outside `prepareFirstLevel`
  is real apply-thread work on soroswap-2000-t-8.
- The shadow-vector setup (lines 691-696, 724-726, 730-732)
  involves N levels × 2 `shared_ptr` copies + pop_back operations
  on a `std::vector<shared_ptr>`.
- `prepare()` at higher levels takes some setup time before
  dispatching the FutureBucket merge to the background thread pool.

## Anti-Evidence

- **The synchronous chain to `snapshotLedger` is structural.**
  `snapshotLedger` reads the level-0 head to compute
  `bucketListHash`; the level-0 work (`prepareFirstLevel`,
  ~2.63 ms/ledger) is mandatorily sync per Meta-Pattern 26
  (`addLiveBatch → snapshotLedger → bucketListHash`).
- Higher-level snap/commit/prepare bookkeeping is interleaved with
  level-0 setup *within* the same `addBatchInternal` call. The
  level loop runs FIRST (line 728 counts down from N-1 to 1),
  then `prepareFirstLevel` runs (line 781). The order is
  load-bearing because `prepareFirstLevel` depends on the
  post-rotation `mLevels[0].mCurr` pointer left by the previous
  ledger's level-1 promotion. So the 1.95 ms/ledger is **not**
  trivially overlap-able with level-0 work; it must execute first.
- Maximum recoverable savings from async-offloading the
  level-1..N orchestration is bounded by the overlap window
  with `addHotArchiveBatch` and the other two finalize-time
  futures — but those already run concurrently and addBatchInternal
  starts only after the level-0 merge inputs are ready.
- Ceiling: **~1.95 ms/ledger ≈ 0.92% of 211 ms soroswap
  baseline ≈ 2.9% of 67 ms Tracy envelope**. Below the 1% Low
  floor on the consensus-driven baseline metric and just under
  the 3% Medium floor even on Tracy-envelope sizing.
- Async-offloading shared-pointer rotations on a
  `BucketSnapshotManager`-locked structure requires careful
  re-validation of the rotation-then-prepare invariant and
  introduces a cross-thread dependency that did not previously
  exist; complexity is high relative to the projected payoff.
- Meta-Pattern 26 ("Future bucket-write hypotheses should target
  internal merge work inside `prepareFirstLevel`/`mergeInMemory`,
  not the `addLiveBatch` call as an atomic unit") directly applies:
  the higher-level orchestration is even further from the merge
  hot work than `addLiveBatch` itself, and its measured size is
  smaller than the 4-5 ms ceiling already exhausted by
  pipeline-seal-with-next-ledger-setup (fail H004,
  `004-pipeline-seal-with-next-ledger-setup.md`).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail H001/H002 (level-0 deferral) and
fail H011 (defer-addLiveBatch-as-atomic-unit); targets the
higher-level orchestration loop in addBatchInternal specifically

### Why It Failed

The higher-level (`mLevels[i]` for i ≥ 1) snap/commit/prepare
orchestration accounts for only ~1.95 ms/ledger of apply-thread
work. Even if fully async-offloadable (which it is not — the
loop must run before `prepareFirstLevel` because level-0's
`mCurr` rotation state depends on the higher-level snap
promotion), the savings ceiling is sub-1% of the consensus
soroswap baseline and sits at most on the Low boundary of the
Tracy envelope, below the objective's 3% Medium floor.

The deeper structural blocker is the level-rotation invariant:
the level-N..1 promotion loop must complete before
`prepareFirstLevel` runs because each level's `prepare()` uses
the snapshot pointer rotated out by the level above it. Decoupling
this ordering requires changing the rotation protocol — a
correctness-sensitive redesign of the BucketList state machine.

### Lesson Learned

When decomposing `addBatchInternal` for optimization, separate
(a) the level-0 in-memory merge work (~2.63 ms/ledger, mandatorily
sync per Meta-Pattern 26) from (b) the higher-level promotion
loop (~1.95 ms/ledger, also effectively sync due to the rotation
invariant). Neither sub-zone clears Medium alone, and combining
them does not change the ceiling because the addLiveBatch →
snapshotLedger → bucketListHash chain forces synchronous
completion before ledger publishing.

Future bucket-list optimizations targeting `addBatchInternal`
should focus on reducing the *internal* work of `prepareFirstLevel`
/`mergeInMemory` (Meta-Pattern 26) rather than attempting to
async-offload the level-rotation orchestration as a whole.
