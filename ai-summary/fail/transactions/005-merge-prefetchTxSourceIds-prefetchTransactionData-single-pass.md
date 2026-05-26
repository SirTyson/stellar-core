# H005: Merge `prefetchTxSourceIds` and `prefetchTransactionData` into a single tx-set pass

**Date**: 2026-05-26
**Subsystem**: transactions
**Severity**: Low
**Impact**: combined per-ledger prefetch surface (sub-medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For the soroswap apply path on a V26+ ledger, `prefetchTxSourceIds` and
`prefetchTransactionData` together should iterate the tx-set only as many
times as semantically required and issue prefetches as compactly as possible,
without performing redundant per-tx outer-loop work.

## Mechanism

Both `LedgerManagerImpl::prefetchTxSourceIds` (LedgerManagerImpl.cpp:2444)
and `LedgerManagerImpl::prefetchTransactionData` (LedgerManagerImpl.cpp:2464)
iterate the same nested `for (phase : txSet.getPhases()) for (tx : phase)`
structure and accumulate a `UnorderedSet<LedgerKey>` of keys, differing only
in which `insertKeysFor*` virtual is called. They are invoked at separate
points in the apply pipeline (one before `processFeesSeqNums`, one inside
`applyTransactions`), but the two key sets could in principle be merged
into a single `UnorderedSet` populated by one combined walk over the tx-set
and submitted as one `ltx.prefetch(combinedKeys)` call. The walk itself
plus two virtual `insertKeysFor*` dispatches per tx is duplicated work
across the two phases.

## Trigger

Run apply-load soroswap benchmark. Both prefetch zones appear in the
applyLedger window once per ledger, walking the same ~200 txs each time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2444-2461` — `prefetchTxSourceIds`
  (calls `insertKeysForFeeProcessing` per tx, prefetches via parent LTX)
- `src/ledger/LedgerManagerImpl.cpp:2463-2481` — `prefetchTransactionData`
  (calls `insertKeysForTxApply` per tx, prefetches via parent LTX)
- `src/ledger/LedgerManagerImpl.cpp:1678` — `processFeesSeqNums` call
  (consumer of source-id prefetch)
- `src/ledger/LedgerManagerImpl.cpp:2823` — `prefetchTransactionData` call
  site inside `applyTransactions`

## Evidence

Apply-path Tracy zones (soroswap, 71 ledgers):
- `prefetchTxSourceIds` 51,852,314 ns (0.504% of applyLedger)
- `prefetchTransactionData` 117,385,188 ns (1.142% of applyLedger)
- Combined surface = 169,237,502 ns = 1.65% of applyLedger
  (4,412,547,914 ns)
- Inner `prefetch` (LedgerTxn.cpp:3103) self-time = 89,083,699 ns (0.87%)

Both walks iterate the identical txSet structure (~200 txs × 71 ledgers =
~14,200 outer iterations per phase, doubled across the two calls).

## Anti-Evidence

1. **Two phases cannot collapse into one** — `prefetchTxSourceIds` must
   complete *before* `processFeesSeqNums` (so fee-source accounts are warm
   for the per-tx fee-deduction loads), while `prefetchTransactionData` runs
   only inside `applyTransactions` after fees are processed. Merging the two
   key sets and issuing a single prefetch would force the apply-key fetch to
   complete before fees can be processed, removing the existing
   fee-then-apply overlap.

2. **Total surface is sub-Medium even with 100% elimination.** The combined
   1.65% applyLedger share cannot reach the 3% Medium floor, and the
   removable portion is strictly smaller (mandatory `ltx.prefetch` and
   `insertKeysFor*` dispatch remain).

3. **Pre-existing fail records cover adjacent angles.** Fail
   `001-merge-and-shortcircuit-prefetch-passes.md` rejected merging
   prefetch passes on a mechanism basis; fail
   `003-skip-prefetchTransactionData-for-soroban-only.md` rejected the
   skip path at 2.23% sub-Medium. Both confirm the prefetch surface is
   structurally below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — proposes a single-pass walk that prior fails did not
explicitly propose, but the conclusion matches Meta-Patterns 9 and 15.

### Why It Failed

The combined apply-window surface of the two prefetch passes is 1.65% of
`applyLedger`, below the 3% Medium floor. Even if the two walks were fused
into one combined walk, the removable portion (outer loop overhead +
duplicated `insertKeysFor*` dispatch) is a small fraction of the already
sub-Medium surface, and the two prefetch calls cannot semantically share
issuance because they must complete at different pipeline stages
(`prefetchTxSourceIds` before `processFeesSeqNums`, `prefetchTransactionData`
before `applyTransactions`).

### Lesson Learned

Prefetch-pass merges in the transactions subsystem must clear the Medium
floor *as combined surface*, not the merge-overhead delta. When two
similar walks happen at different pipeline stages, the structural ordering
constraint prevents collapsing them into one issuance; the only achievable
saving is the outer-loop iteration cost, which is sub-noise. Extends
Meta-Pattern 9 (Pre-Parallel-Apply Phase Is Thin) to per-tx prefetch loops.
