# H003: Cross-Ledger Async Deferral of `addLiveBatch` Across the `closeLedger` Boundary

**Date**: 2026-05-21
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: Apply critical path — moves synchronous BucketList write off the apply window
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Within `LedgerManagerImpl::finalizeLedgerTxnChanges` (LedgerManagerImpl.cpp:3217+), the apply
thread synchronously calls `BucketManager::addLiveBatch` (BucketManager.cpp:1025-1046) to
write the per-ledger init/live/dead deltas into the live `BucketList`. `addBatch` performs
top-level bucket construction (`mLevels[0].prepare`, `mLevels[0].snap`,
`countNewEntriesHashingIfNecessary` over the produced bucket on the apply thread, and the
synchronous portion of any required `FutureBucket::resolve` calls along the spilling path).
Because the next ledger's apply does not actually read the new bucket until its own
`prefetch`/parallel-apply stage many milliseconds later, the synchronous `addLiveBatch`
work is dead time on the apply critical path; its result is only required by *next*
ledger's apply, not the current one.

The expected behavior, in an ideally pipelined design, is that `addLiveBatch` runs on a
background thread that finishes by the time the next `closeLedger` actually needs the new
`BucketList` snapshot to be queryable, while the current ledger's `closeLedger` returns
immediately after the in-memory state update is published.

## Mechanism

`addLiveBatch` is invoked synchronously on the apply thread (LedgerManagerImpl.cpp around
the `addLiveBatch(...)` call site inside `finalizeLedgerTxnChanges`); the `addHotArchiveBatch`
and `inMemoryStateUpdateFuture` siblings are already async, but `addLiveBatch` is held on
the apply thread because subsequent post-apply steps (notably `sealLedgerTxnAndStoreInBucketsAndDB`
and the LCL-state publication) need a consistent BucketList view *for hash purposes only* —
not for read purposes. If the BucketList hash can be computed from the produced level-0
bucket without the full `addBatch` having committed level rotations, the rotation/spill
portion of `addLiveBatch` could be moved to a background task that the *next* ledger's
`applyLedger` joins on (rather than the current ledger's). This converts ~5–8 ms of
synchronous critical-path work per ledger into pipelined off-thread work.

The actual behavior diverges from the expected behavior because `addLiveBatch` couples
two responsibilities — producing the new top-level snap (cheap, needed for hashing) and
performing higher-level merge prepare/spill (expensive, only needed before next ledger
reads BucketList) — and the current implementation does both on the apply thread.

## Trigger

A normal soroswap apply with ~600 LedgerEntry writes per ledger, where `addLiveBatch`'s
top-level work plus any synchronous `FutureBucket::resolve` time accounts for several
milliseconds of apply-thread time (visible as the `BucketManager::addLiveBatch` zone or
its `BucketLevel::commit` descendants under `applyLedger`).

## Target Code

- `src/bucket/BucketManager.cpp:1025-1046` (`addLiveBatch`) — synchronous on apply thread.
- `src/ledger/LedgerManagerImpl.cpp:3217-3368` (`finalizeLedgerTxnChanges`) — caller; already
  fans out `addHotArchiveBatch` and `inMemoryStateUpdateFuture` async. `addLiveBatch` is the
  remaining sync sibling.
- `src/ledger/LedgerManagerImpl.cpp:3371-3429` (`sealLedgerTxnAndStoreInBucketsAndDB`) —
  reads `BucketList` hash; needs the new top-level bucket but not the rotation work.

## Evidence

- `addHotArchiveBatch` is already async (BucketManager.cpp:1048+ launched via
  `std::async` in finalizeLedgerTxnChanges), proving the pattern is acceptable for at
  least one bucket-list write path.
- The fail summary's `001-async-addlivebatch.md` rejection was scoped to *within-ledger*
  async (joined inside `finalizeLedgerTxnChanges`), not across the `closeLedger` boundary.
  Cross-ledger deferral has a strictly larger overlap window and is structurally distinct.
- Tracy on the soroswap trace shows apply-thread time inside the `BucketManager::addLiveBatch`
  zone (level-0 snap + countNewEntries hashing) is non-trivial per ledger.

## Anti-Evidence

- `sealLedgerTxnAndStoreInBucketsAndDB` (LedgerManagerImpl.cpp:3371-3429) reads
  `mLiveBucketList->getHash()` which depends on the new level-0 snap being produced —
  this part can NOT be deferred because the published `LedgerHeader.bucketListHash`
  must be deterministic at close time.
- `BucketLevel::commit` rotations are not idempotent: if a future ledger's `addBatch`
  begins before the prior one's rotations complete, the BucketList state diverges across
  nodes — determinism would break.
- The fail summary's meta-pattern #16 ("Cross-ledger pipelining ceiling ~4ms/ledger
  (~1.5%); requires changing apply-correctness guarantees since next ledger reads
  fully-committed prior state") sets a specific structural ceiling that this hypothesis
  cannot exceed.
- fail entry `003-defer-hot-archive-future-across-finalize.md` rejected an analogous
  cross-ledger defer for hot-archive at "~1.4 ms/ledger (~1.7%)" — addLiveBatch's
  synchronous portion is unlikely to be more than ~2× that amount once the level-0 snap
  remains synchronous (because it gates the hash).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — cross-ledger boundary distinct from prior in-finalize-async attempts;
not a duplicate of fail 001-async-addlivebatch (within-ledger) or fail
003-defer-hot-archive-future (different bucket list).

### Why It Failed

The synchronous portion of `addLiveBatch` that gates `closeLedger` is dominated by
producing the top-level snap whose hash feeds `LedgerHeader.bucketListHash` — and that
must complete before close. Only the post-snap rotation/spill portion of `addBatch` is
deferrable, and on a soroswap ledger that rotation portion (when no level boundaries
are crossed) is sub-millisecond. Even when level rotations *do* occur, the synchronous
`FutureBucket::resolve` waits during `BucketLevel::commit` are already covered by fail
meta-pattern #15 (only blocking bucket work counts; resolves on the apply thread happen
rarely on the soroswap workload). Quantitative ceiling: per fail meta-pattern #16,
cross-ledger pipelining tops out at ~4 ms/ledger (~1.5%), which is below this objective's
3% Medium floor. Filing this hypothesis under hypothesis/ would force a reviewer to
re-derive the same ceiling.

### Lesson Learned

When the optimization is "move sync X off the apply thread", the relevant accounting is
not "total time of X" but "the fraction of X whose result is required by close-time hash
publication". For `addLiveBatch` and any other BucketList write, the level-0 snap +
hash-feeding work is structurally bound to the apply window and cannot be moved without
breaking determinism on `LedgerHeader.bucketListHash`. Future cross-ledger pipelining
hypotheses must carry a specific "what fraction of X feeds the close-time hash" budget
to avoid duplicating this analysis.
