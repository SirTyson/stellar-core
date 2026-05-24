# H003: Eliminate per-tx child LedgerTxn in `preParallelApplyWrite`

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Low
**Impact**: per-tx scaffolding overhead in serial post-cluster commit
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the apply path commits the pre-parallel write-side classic state for each
Soroban tx (sequence-number bump and optional one-time-signer removal), it
should do so without paying the cost of constructing and committing a fresh
child `LedgerTxn` per transaction. With meta disabled
(`DISABLE_TX_META_FOR_TESTING = true`) and no per-tx meta payload to capture,
the seqnum bump and signer removal could be applied directly against the
parent `LedgerTxn` (or against a single batched child) without per-tx
allocation overhead.

## Mechanism

`commitBufferedPreParallelApplyWrites` (ParallelApplyUtils.cpp:585) iterates
all txs in a stage and calls `TransactionFrame::preParallelApplyWrite`
(TransactionFrame.cpp:2320) per tx. Each call constructs a child `LedgerTxn`,
invokes `processSeqNum`/`removeOneTimeSignerFromAllSourceAccounts` against it,
calls `meta.pushTxChangesBefore` (a no-op when meta is disabled), then
commits the child to the parent. The child `LedgerTxn` exists primarily to
provide a meta-capture boundary; with meta disabled, the boundary is
unnecessary scaffolding.

## Trigger

Soroswap benchmark workload: 16,036 Soroban txs across 71 closed ledgers
(≈226 txs/ledger). For each tx, `preParallelApplyWrite` is called serially
on the apply thread.

## Target Code

- `src/transactions/TransactionFrame.cpp:2320` — `preParallelApplyWrite`
  constructs `LedgerTxn ltxTx(ltx)`, calls `processSeqNum(ltxTx)` and
  optional signer removal, then `ltxTx.commit()`.
- `src/transactions/ParallelApplyUtils.cpp:585` —
  `commitBufferedPreParallelApplyWrites` loops over all txs invoking the
  above.

## Evidence

Tracy zone `preParallelApplyWrite` (TransactionFrame.cpp:2320) reports
**11.1 ms self-time across 16,036 calls** in the soroswap trace
(`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`),
mean 691 ns/call. The body is a child `LedgerTxn` ctor + 1-3 inner
operations + commit. Replacing the child with direct parent operations
could save approximately the ctor + commit overhead (~300-500 ns/call out
of the 691 ns).

## Anti-Evidence

The benchmark template explicitly disables tx meta
(`DISABLE_TX_META_FOR_TESTING = true`), but production paths require the
child boundary for meta capture, so any optimization would need to be
gated on the no-meta path or restructure meta capture to not require a
per-tx child.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (prior fail-021 and
fail-003 targeted the `processFeesSeqNums` outer wrapper LedgerTxn, not
the `preParallelApplyWrite` per-tx child).

### Why It Failed

Even with full elimination of the per-tx child `LedgerTxn`, the maximum
recoverable wall-time is bounded by the zone's self-time:
**11.1 ms / 71 ledgers = 156 µs/ledger = 0.07% of `applyLedger`**
(2.18 ms baseline). This is below the 1% Low floor and far below the
3% Medium objective threshold. Additionally, the optimization would
require a meta-mode bifurcation (or larger meta-capture redesign) to
preserve production correctness, adding implementation risk for a
sub-noise gain.

### Lesson Learned

Per-tx scaffolding overhead in serial post-cluster commit paths
(`preParallelApplyWrite`, `commitBufferedPreParallelApplyWrites`) is
fundamentally bounded by per-call cost × tx count / parallelism. With
~226 serial Soroban txs/ledger and sub-µs per-tx scaffolding, even
literally zero-cost replacement cannot reach Medium. Same pattern as
fail-024 (applyThread scaffolding) and fail-021 (fee-processing
wrapper LedgerTxn): hundreds of µs/ledger is always sub-threshold
on a 220+ ms baseline.
