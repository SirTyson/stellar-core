# H026: Eliminate Per-Tx Child LedgerTxn in processPostTxSetApply via Stage-Batched LTX

**Date**: 2026-05-24
**Subsystem**: transactions (post-tx-set Soroban refund / meta capture serial phase)
**Severity**: Low
**Impact**: soroswap apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::processPostTxSetApply` runs serially after Soroban stages
complete. For each `TxBundle` it constructs a per-tx child `LedgerTxn
ltxInner(ltx)` (line 3112), invokes `processPostTxSetApply` (which refunds
unused Soroban fee to the source account), captures `ltxInner.getChanges()`
into `LedgerCloseMeta` via `setPostTxApplyFeeProcessing`, then commits the
child back to the parent. A correct implementation could instead amortize the
per-tx child-LTX cost by either (a) opening one `ltxInner` per `ApplyStage` and
demarcating per-tx changes via `getDelta()` snapshots between refunds, or
(b) applying refunds directly to the outer `ltx` and reconstructing per-tx
`LedgerEntryChanges` from a single batched delta diff.

## Mechanism

Every soroswap tx pays Soroban fees and receives a refund in this phase, so
`processPostTxSetApply` is invoked for every successful Soroban tx. With
TX=2000 and ~70 ledgers the loop runs ~138,000 times, each iteration
constructing and committing a `LedgerTxn` child that holds only the fee-source
account's `AccountEntry` mutation. The per-tx child LTX brings: entry-cache
inheritance setup, parent-pointer registration, header materialization on
first load, change-buffer allocation, and commit-time entry merge back into
the parent. Hoisting to a per-stage LTX would amortize these fixed setup
costs across all txs in a cluster.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load workload. Every successful
tx enters `processPostTxSetApply` and creates one child `LedgerTxn` for fee
refund.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — `processPostTxSetApply`
  per-bundle child LTX construction + commit loop.
- `src/transactions/TransactionFrame.cpp:2782-2816` — `processPostTxSetApply`
  → `processRefund` performs one `loadHeader().current().ledgerVersion` read
  and one source-account credit via `refundSorobanFee`.
- `src/ledger/LedgerTxn.cpp` — child LTX construction overhead
  (parent-link, change-buffer, header-snapshot inheritance).

## Evidence

`processPostTxSetApply` is a Soroban-mandatory serial phase that runs after
all parallel apply stages complete. The phase consists of N independent
per-tx fee refunds plus per-tx meta finalization. Each refund mutates a
single account entry. Per-tx child-LTX construction is structurally
amortizable across the cluster/stage with a careful delta-snapshot scheme.

## Anti-Evidence

The transactions fail summary record
`001-parallelize-post-tx-set-apply-fee-refunds.md` already bounded the entire
post-tx-set phase at 1.06-1.12% of soroswap close time using non-Tracy
benchmark data. The per-tx child-LTX overhead is a strict sub-component of
that already-thin budget: even 100% elimination of the child-LTX cost
(impossible without changing meta semantics) is bounded by ~1% of apply
time. The mandatory work — loading the fee-source account, computing refund
amount, mutating balance, emitting the fee event, and capturing per-tx
`LedgerEntryChanges` into LedgerCloseMeta — cannot be removed by hoisting
the LTX. Per-tx meta requires per-tx change separation, which a batched LTX
must reconstruct from snapshots, adding cost that likely cancels the savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — prior post-tx-set fail (`001-parallelize-post-tx-set-apply-fee-refunds.md`)
targeted parallelizing the loop across threads; this distinct angle targets
serial child-LTX amortization within the existing serial loop. Prior
transactions-summary record `022-eliminate-per-tx-child-ltx-in-processFeesSeqNums.md`
targeted the analogous pattern in the *pre*-apply `processFeesSeqNums` phase
(not the post-tx-set phase).

### Why It Failed

Below the objective severity threshold. The full post-tx-set Soroban refund
phase is structurally capped at ~1.06-1.12% of soroswap close time (per
prior fail `001-parallelize-post-tx-set-apply-fee-refunds.md`). The child-LTX
construction/commit cost is a strict sub-component, bounded well below the 3%
Medium floor and even below the 1% Low noise floor. Per-tx meta capture
requires per-tx change separation; a stage-batched LTX would have to
reconstruct equivalent per-tx delta windows, adding overhead that erodes the
savings further. Extends Meta-Pattern 9 (pre-parallel-apply phase is thin) to
its post-apply mirror: the post-tx-set Soroban refund phase is equally thin.

### Lesson Learned

Both the pre-apply `processFeesSeqNums` and post-tx-set Soroban refund phases
have analogous per-tx child-LTX patterns; both are bounded by sub-Medium
total phase budgets (transactions fail `022` covered the pre-side at ~3.55%
phase with sub-1% removable; this hypothesis covers the post-side at
~1.06-1.12% phase). Future per-tx LTX-elimination hypotheses in either of
these mirror phases should be rejected without new trace evidence showing the
parent phase substantially above 3% Medium.
