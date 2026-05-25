# H071: Hoist serial post-tx-set refund processing into the parallel worker phase

**Date**: 2026-05-25
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: serial post-apply phase critical-path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`processPostTxSetApply` runs after all parallel Soroban stages complete and,
for each `TxBundle`, calls `processPostTxSetApply → processRefund →
refundSorobanFee`. Because the refund logic touches only the fee-source
account and only `processPostTxSetApply` writes are then funneled into
ledger meta via `setPostTxApplyFeeProcessing`, the per-tx work could in
principle be parallelized across clusters (each cluster's txs touch disjoint
fee-source accounts in soroswap, where source accounts are bin-unique by
design).

## Mechanism

`LedgerManagerImpl::processPostTxSetApply`
(`src/ledger/LedgerManagerImpl.cpp:3094-3148`) iterates every tx in every
stage serially, opens a child `LedgerTxn` per tx, calls
`processPostTxSetApply → refundSorobanFee` which loads the fee-source
account, adjusts balance, commits the inner LTX, then calls
`processResultAndMeta` which is also serial. Per-tx serial work in this
phase, even with refund early-outs, multiplies by 2000 txs/ledger on
soroswap.

## Trigger

Any Soroban ledger that produces a non-zero refundable-fee delta on most txs
(typical soroswap shape) and runs at v23+ so the parallel apply path is
exercised. The hypothesis would batch refunds per cluster on worker threads
and merge results in canonical cluster-index order in the post-apply phase.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3094-3148` —
  `processPostTxSetApply` serial double loop.
- `src/transactions/TransactionFrame.cpp:2782-2816` — `processPostTxSetApply`
  → `processRefund` per-tx body.
- `src/transactions/TransactionFrame.cpp:1044-1083` — `refundSorobanFee`
  per-tx LedgerTxn / loadAccount / addBalance / commit.
- `src/ledger/LedgerManagerImpl.cpp:2727-2782` — `processResultAndMeta`
  serial counter/meta finalize.

## Evidence

- Cluster-disjoint fee-source accounts on soroswap (binning is by source
  account) — the refund step naturally parallelizes across clusters.
- Serial post-apply loop processes every tx in the ledger.

## Anti-Evidence

- Tracy measurements on the diagnostic soroswap trace show this phase is
  trivially small in the current build: `processPostTxSetApply` self-time is
  3.45 ms across 71 ledgers (~49 µs/ledger), `refundSorobanFee` self-time is
  ~8.95 ms / 14036 calls (~637 ns/call), and `processResultAndMeta` self-time
  is 7.16 ms / 32945 calls (~217 ns/call). The dominant cost was already
  driven out by the existing fast paths (refund=0 early-out, meta-disabled
  guards, sparse no-meta ledger-change pipeline).
- Total per-ledger serial cost of the entire phase is ~280 µs/ledger
  (~0.14% of the 207 ms soroswap baseline). Even idealized
  `NUM_CLUSTERS=8` parallelization saves at most ~245 µs/ledger
  (~0.12%), under both Low (1%) and Medium (3%) floors.
- Determinism: meta and counter sums depend on canonical tx order, so
  any parallel refund pass would still need a serial merge step, eroding the
  upper bound further.
- The existing fail entries `H024 / H062 / H063` already establish the
  meta-disabled benchmark configuration drives these post-apply zones below
  the noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — prior post-apply hypotheses targeted destruction
(H062), arena allocation (H063), `commitChangesFromThreads` parallelization
(H003/H004), and per-tx counter coalescing (005-coalesce-per-tx-result-
counter-inc); parallelizing the refund/result loop itself has not been
specifically investigated.

### Why It Failed

The total serial envelope of `processPostTxSetApply` plus
`processResultAndMeta` is bounded at ~280 µs/ledger on the current
sparse-no-meta + cached-old-entry-XDR baseline (Tracy measurements above).
That is roughly 0.14% of the 207 ms soroswap baseline. Even with a perfect
8-way cluster shard and zero merge overhead, the recoverable saving is
~0.12%, well below the 1% Low floor and orders of magnitude below the
3% Medium floor accepted by this objective. The work to plumb parallelism
into the post-apply phase (worker-pool scheduling, deterministic merge
into `ledgerCloseMeta` and `txResultSet`, scope reasoning for
`LedgerTxn`) is disproportionate to the projected win.

### Lesson Learned

After `001-sparse-no-meta-ledger-changes` and the meta-disabled benchmark
config, the post-apply serial loop is essentially a no-op envelope.
Hypotheses targeting `processPostTxSetApply` / `processResultAndMeta` /
post-apply refund parallelism must first measure the absolute apply-window
self-time of those zones on the current accepted baseline; the
`refundSorobanFee` zone in particular has been driven into the sub-µs/call
regime by the existing refund=0 early-out path. Add this to the existing
"sub-threshold post-cluster serial loops" meta-pattern.
