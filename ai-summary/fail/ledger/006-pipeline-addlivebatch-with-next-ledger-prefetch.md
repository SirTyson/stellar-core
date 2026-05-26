# H006: Pipeline ledger N's `addLiveBatch` with ledger N+1's pre-apply prefetch / fee processing

**Date**: 2026-05-26
**Subsystem**: ledger / apply path pipelining
**Severity**: Medium
**Impact**: Hide the synchronous `addLiveBatch` cost (~4.3 ms/ledger ≈ 7% of soroswap apply) behind start of next ledger's pre-apply work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyLedger` is the only entry point that mutates ledger
state on the apply thread. Each invocation must finish all of:

1. `processFeesSeqNums` (per-ledger fee debit and seqnum increment)
2. `applyTransactions` (classic + parallel Soroban)
3. `applyUpgrades`
4. `sealLedgerTxnAndStoreInBucketsAndDB` → `finalizeLedgerTxnChanges` →
   `addLiveBatch` → SOCI commit → persist header

before `applyLedger` returns and `advanceLedgerStateAndPublish` updates the
LCL. The benchmark's measured top-line zone (`applyLedger`) currently
includes the synchronous `addLiveBatch` segment, which Tracy shows at
**307,884,177 ns total / 72 calls ≈ 4.28 ms/ledger** on the latest accepted
soroswap baseline — ~6.9% of the 62.1 ms `applyLedger` mean.

The expected pipelining behavior would be: as soon as the LTX has been
sealed and the new-batch entry vectors handed to `addLiveBatch`, the
apply-thread could begin pre-apply work for ledger N+1 (prefetch of
classic source/footprint keys against the *current* BucketList snapshot,
not against the post-seal one). When ledger N+1's `applyLedger` is later
invoked, its `prefetchTxSourceIds` and `prefetchTransactionData` are
already warm, so the per-ledger pre-apply latency drops by ~1.6–2.0
ms/ledger and the post-apply `addLiveBatch` latency (~4.3 ms/ledger) is
absorbed by overlap with N+1's setup.

## Mechanism

`applyLedger` currently runs `addLiveBatch` *synchronously* at
`src/ledger/LedgerManagerImpl.cpp:3356` inside `finalizeLedgerTxnChanges`
(itself inside `sealLedgerTxnAndStoreInBucketsAndDB`). The pre-apply work
of the next ledger (`prefetchTxSourceIds` at line 1659, then
`processFeesSeqNums` at line 1678) only starts on the *next*
`applyLedger` call — and that call is gated on the apply-thread returning
from the current `applyLedger`. So the two phases run strictly serially
across ledger boundaries.

A pipelined variant would:

- Spawn `addLiveBatch` as a `std::future<void>` (similar to the existing
  `hotArchiveBatchFuture` and `inMemoryStateUpdateFuture` patterns already
  established in `finalizeLedgerTxnChanges` at lines 3285 and 3345).
- Defer the join on `addLiveBatch`'s future until *just before* the next
  `applyLedger`'s seal step requires the BL to be consistent (specifically,
  before `mLiveBucketList->snapshotLedger` would be called for the next
  ledger).
- Allow the next ledger's `prefetchTxSourceIds` /
  `prefetchTransactionData` to run on the apply thread concurrently with
  the previous ledger's `addLiveBatch` background work, since prefetch
  only reads the BucketList snapshot that existed *before* the new live
  batch was added — the snapshot it reads is `mLastClosedLedgerState`'s
  bucket snapshot, which is stable until `advanceLastClosedLedgerState`
  publishes the new one.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`)
with the proposed pipelining. The benchmark closes 71+ ledgers in
sequence; pipelining would overlap the synchronous `addLiveBatch` segment
of ledger N with the prefetch + fee processing segment of ledger N+1.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1462-1800` — `applyLedger` orchestrates
  the per-ledger pipeline; lines 1659, 1678, 1780 are the per-phase entry
  points that would need re-ordering.
- `src/ledger/LedgerManagerImpl.cpp:3356` — synchronous `addLiveBatch`
  call inside `finalizeLedgerTxnChanges`.
- `src/ledger/LedgerManagerImpl.cpp:3371-3470` —
  `sealLedgerTxnAndStoreInBucketsAndDB` orchestrates SOCI commit and
  ledger header persistence; the join point for a deferred `addLiveBatch`
  future must precede `advanceBucketListSnapshotAndMakeLedgerState` so
  that the new BL snapshot includes the just-written batch.
- `src/ledger/LedgerManagerImpl.cpp:2444-2480` — `prefetchTxSourceIds` and
  `prefetchTransactionData` read from `LedgerTxnRoot`, which delegates to
  `mSearchableBucketListSnapshot`.

## Evidence

The latest soroswap trace
(`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`)
shows `addLiveBatch` at 307,884,177 ns / 72 ledgers ≈ 4.28 ms/ledger,
which is ~6.9% of the 62.1 ms mean `applyLedger` envelope. Pre-apply
prefetch totals (`prefetchTransactionData` 117,385,188 ns + `prefetch`
145,919,777 ns + `prefetchTxSourceIds` 8,853,369 ns) ≈ 3.78 ms/ledger of
work that could be moved into the previous ledger's tail.

`finalizeLedgerTxnChanges` already uses two background futures
(`hotArchiveBatchFuture`, `inMemoryStateUpdateFuture`) that are joined
before `addLiveBatch`, demonstrating the structural pattern this
hypothesis would extend.

## Anti-Evidence

The Stellar consensus protocol requires the LCL hash to include the
post-`addLiveBatch` BucketList hash before any subsequent state mutation
is visible. The `ApplicableTxSetFrame` for ledger N+1 is only validated
against the externalized SCP value, which itself only arrives after
ledger N's close is published.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (closest prior failures
target `addLiveBatch` internal structure, not cross-ledger pipelining)

### Why It Failed

Two distinct structural blockers make this scheme infeasible:

1. **LedgerTxn root mutation barrier.** Ledger N+1's
   `prefetchTxSourceIds` and `processFeesSeqNums` operate on a
   `LedgerTxn` opened on `LedgerTxnRoot`. `LedgerTxnRoot::Impl::prefetch`
   at `src/ledger/LedgerTxn.cpp:3101` writes into the shared
   `mEntryCache` via `putInEntryCache`. But ledger N's `addLiveBatch` is
   itself mutating `mLiveBucketList` and, via the post-batch snapshot
   advance, will invalidate the entry-cache view that ledger N+1's
   prefetch just populated. Coordinating these two writers safely
   requires either (a) holding `mEntryCache` updates until N's
   `addLiveBatch` completes (negating the pipelining benefit), or (b)
   deferring N's snapshot advance until after N+1's prefetch (which
   leaves the BucketList in an inconsistent state for any other reader).
2. **Consensus dependency on externalization.** Even in the benchmark
   harness, the apply-thread cannot speculate the txset for ledger N+1
   ahead of ledger N's `advanceLedgerStateAndPublish` because the next
   `LedgerCloseData` is delivered by the simulator's externalization
   callback, which runs *after* the current `applyLedger` returns. There
   is no API surface to deliver N+1's txset before N's apply completes,
   and adding one would require restructuring the apply-thread driver
   (out of scope for a ledger-subsystem optimization).

The combined effect: even if the apply thread could safely begin N+1
prefetch during N's `addLiveBatch`, it has no `ApplicableTxSetFrame` for
N+1 available at that point.

### Lesson Learned

Cross-ledger pipelining of the apply path is structurally blocked by the
single-writer ownership of `LedgerTxnRoot`'s entry cache and by the
externalization-callback timing that delivers the next ledger's txset
only after the current ledger publishes. Any future cross-ledger
pipelining proposal must first redesign both (a) `LedgerTxnRoot` cache
invalidation to support concurrent reader/writer at the snapshot
boundary, and (b) the simulation harness driver to surface N+1's txset
during N's tail. Both are outside the ledger subsystem's scope and far
larger changes than the ~4 ms/ledger they would unlock.
