# H004: Pipeline previous ledger's `finalizeLedgerTxnChanges` + `sealLedgerTxnAndStoreInBucketsAndDB` with next ledger's apply-thread setup

**Date**: 2026-05-05
**Subsystem**: ledger / apply-thread pipelining
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by overlapping previous-ledger seal/finalize with next-ledger prefetch + fees + preParallelApply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The apply thread should not serialize `finalizeLedgerTxnChanges` and
`sealLedgerTxnAndStoreInBucketsAndDB` of ledger N before beginning the
synchronous setup work of ledger N+1 (prefetch + fee/seqnum processing +
preParallelApply construction), as long as the next ledger's apply does not
read state mutated by the previous ledger's seal until the seal future is
joined. The pipelined design should overlap the ~5 ms of previous-ledger
post-apply work (sync `addLiveBatch` + serial finalize bookkeeping + SOCI
commit) with the ~2.5 ms of next-ledger prefetch + ~2.2 ms of fee/seqnum
processing for a critical-path saving close to the smaller of the two
(~3-4 ms / ledger).

## Mechanism

`LedgerManagerImpl::applyLedger` currently runs synchronously to completion:
the apply thread performs `applyTransactions`, then `finalizeLedgerTxnChanges`
(4.5 ms / ledger; the last barrier waits on the sync `addLiveBatch` 4.1 ms
plus async hot-archive and in-memory state futures), then
`sealLedgerTxnAndStoreInBucketsAndDB` (which adds ~0.2 ms of bookkeeping
plus SOCI commit ~0.18 ms). Only after this completes does the next
`applyLedger` call run `prefetchTxSourceIds` (0.7 ms) +
`prefetchTransactionData` (1.65 ms) + `processFeesSeqNums` (2.15 ms) before
parallel apply begins. The next ledger's prefetch reads from the BucketList
snapshot, which is updated by `addLiveBatch`; fees/seqnums read account
state via the LedgerTxn opened on `LedgerTxnRoot`. If the seal/finalize work
were dispatched as a future at `applyLedger` exit and joined inside the next
`applyLedger` only at the points that truly depend on its results, the
overlap window is the entire prefetch + fee phase (~4.5 ms), bounded by the
smaller of [seal/finalize work ≈ 5 ms] and [overlapable next-ledger setup
≈ 4.5 ms]. The achievable saving is therefore ~4 ms / ledger ≈ 1.5% on the
soroswap median.

## Trigger

Run the soroswap apply-load benchmark on a PoC that wraps
`finalizeLedgerTxnChanges + sealLedgerTxnAndStoreInBucketsAndDB` in a
`std::future` launched from the apply thread, with a join point inserted at
the start of the next `applyLedger` immediately before any access to
`mInMemorySorobanState`, the BucketList snapshot, or `LedgerTxnRoot`-backed
loads.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3217-3368` —
  `finalizeLedgerTxnChanges`; the sync wait on `addLiveBatch` is the
  serial floor of the post-apply phase.
- `src/ledger/LedgerManagerImpl.cpp:3370-3430` —
  `sealLedgerTxnAndStoreInBucketsAndDB`; the SOCI commit and metadata
  emission paths.
- `src/ledger/LedgerManagerImpl.cpp:1484-1900` — `applyLedger`; entry
  point to insert the future-join barrier on next ledger's setup.
- `src/ledger/LedgerManagerImpl.cpp:2308-2470` — `processFeesSeqNums` and
  `prefetchTransactionData` setup paths that would run concurrently with
  the previous ledger's seal/finalize.

## Evidence

- Tracy self-times (per ledger averages over 71 ledgers in the diagnostic
  trace at `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/`):
  `finalizeLedgerTxnChanges` 4.52 ms, `sealLedgerTxnAndStoreInBucketsAndDB`
  4.74 ms (parent of finalize, so seal-itself ≈ 0.22 ms),
  `prefetchTxSourceIds` 0.70 ms, `prefetchTransactionData` 1.65 ms,
  `processFeesSeqNums` 2.15 ms. Total overlap candidate ≈ 4.5 ms.
- `addLiveBatch` (sync, 4.09 ms) is the dominant component of finalize and
  is structurally serial with the next ledger's prefetch only because of
  the BucketList snapshot publication ordering, not because of any
  data-flow dependency that prevents pipelining.

## Anti-Evidence (and reason for self-rejection)

- The BucketList snapshot used by `prefetch` *is* the output of
  `addLiveBatch`; the next ledger's prefetch logically requires the
  previous ledger's writes to be visible to be correct. Pipelining
  requires either (a) the prefetch reads to fall back to the LCL snapshot
  while the new snapshot is being installed (changes prefetch semantics
  for any classic key updated on the previous ledger), or (b) join the
  future before any prefetch call (which collapses the overlap window to
  zero). Neither is acceptable: option (a) silently changes
  apply-correctness guarantees and option (b) yields no saving.
- Fee/seqnum processing reads account state from `LedgerTxnRoot`, which is
  also written by `commitChild` during the previous ledger's seal. Source
  account balance lookups during `processFeesSeqNums` would race with
  SOCI commits of offer changes from the previous ledger.
- Even the maximally pipelined version, with all races resolved by
  copy-on-write snapshots, caps at ~4 ms / ledger ≈ 1.5% — below the
  3% Medium floor by itself.
- Meta-pattern #18 already established the entire prefetch subsystem at
  ~3 ms / ledger as the saving ceiling for any prefetch-overlap design;
  this hypothesis adds the seal-overlap angle but inherits the same
  ceiling because the overlap is bounded by the smaller of the two phase
  totals.
- H003-async-prefetch-overlap-fee-processing already established that
  pipelining setup phases is sub-Low; the additional 4 ms ceiling here
  does not change the conclusion.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a single combined
seal+finalize / next-ledger-setup overlap; previous fail entries cover
only sub-pieces (hot-archive future deferral H003 in fail/ledger,
async-addLiveBatch H001, async-prefetch-overlap-fee-processing H003).

### Why It Failed

The overlap window is bounded by the smaller of [previous seal/finalize
~5 ms] and [next ledger setup ~4.5 ms], giving a ceiling of ~4 ms / ledger
≈ 1.5%. Below the 3% Medium floor. Additionally, pipelining requires
either changing apply-correctness guarantees (prefetch reads from stale
snapshot) or copy-on-write snapshot machinery for `LedgerTxnRoot` and the
BucketList, both of which add complexity disproportionate to the saving.

### Lesson Learned

Cross-ledger pipelining of post-apply work and pre-apply work in the soroswap
shape cannot exceed the ~4-5 ms / ledger floor imposed by the smaller of
the two phase totals, and is structurally bounded by the snapshot
publication ordering (`addLiveBatch` -> BucketList snapshot ->
prefetch reads). Future cross-ledger pipelining hypotheses must either
(a) restructure the snapshot installation so reads can be served from a
copy-on-write overlay during seal, or (b) target a phase pair whose smaller
side exceeds 8 ms / ledger.
