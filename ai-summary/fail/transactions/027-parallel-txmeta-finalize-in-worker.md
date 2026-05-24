# H027: Move TransactionMetaBuilder::finalize Into Parallel Workers

**Date**: 2026-05-24
**Subsystem**: transactions (TransactionMeta XDR finalization serial phase)
**Severity**: Low
**Impact**: soroswap apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::processResultAndMeta` currently calls
`txMetaBuilder.finalize(result.isSuccess())` serially per-tx at
`LedgerManagerImpl.cpp:2761`. `finalize` produces the final
`TransactionMeta` XDR by assembling stored `OperationMeta` entries, tx-level
`LedgerEntryChanges` (`pushTxChangesBefore`/`pushTxChangesAfter`), event
buffers, refundable-fee meta, and Soroban return values into a single XDR
union. For ~138,000 successful Soroban txs per benchmark run, this is a
serial XDR-construction pass on the apply thread. A correct implementation
could move `finalize` (and the subsequent `xdr_to_msg` encoding for
LedgerCloseMeta capture) into the parallel cluster workers, where each
worker already owns its `TransactionMetaBuilder` via `TxEffects`. The
serial apply thread would then only need to splice pre-built XDR buffers
into the LedgerCloseMeta vector.

## Mechanism

`TransactionMetaBuilder::finalize` builds a `TransactionMeta` XDR variant
holding nested `LedgerEntryChanges`, `OperationMeta[]`, `ContractEvent[]`,
`DiagnosticEvent[]`, and Soroban `SCVal` return value. For soroswap this is
dominated by the OperationMeta v3 entries containing ledger entry changes
extracted from the worker's `setLedgerChangesFromSuccessfulOp` plus the
contract events and Soroban return value. All inputs are already owned by
the per-worker `TxEffects` before the serial `processResultAndMeta` runs.
Moving the XDR-union assembly into the worker would shift serial CPU into
parallel CPU; the post-tx-set apply phase only adds the small
`setPostTxApplyFeeProcessing` per-tx changes, which could be appended to a
pre-built skeleton in the serial phase.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load workload. Every
successful Soroban tx hits `processResultAndMeta` →
`TransactionMetaBuilder::finalize` on the serial apply thread inside
`processPostTxSetApply`'s per-bundle loop.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2727-2780` — `processResultAndMeta`
  calls `txMetaBuilder.finalize(...)` serially per tx.
- `src/ledger/LedgerManagerImpl.cpp:3107-3140` — serial `processPostTxSetApply`
  loop drives the finalize calls.
- `src/transactions/TransactionMeta.cpp` — `TransactionMetaBuilder::finalize`
  assembles the union from buffered components.
- `src/transactions/ParallelApplyStage.h` — `TxEffects` owns the
  `TransactionMetaBuilder` for each parallel-applied tx.

## Evidence

`TransactionMetaBuilder::finalize` is a per-tx serial pass that runs after
all parallel apply work completes. All input data (ledger changes, events,
return value, operation meta) is captured in per-worker `TxEffects` during
parallel apply, so the inputs are available before the serial phase begins.
The only post-parallel addition is `setPostTxApplyFeeProcessing`, which sets
a small per-tx fee-change vector.

## Anti-Evidence

The transactions fail record
`001-parallelize-post-tx-set-apply-fee-refunds.md` bounded the full
post-tx-set serial phase at 1.06-1.12% of soroswap close time using
non-Tracy benchmark data. `finalize` is a strict sub-component of that
phase, alongside the fee-refund work and `setPostTxApplyFeeProcessing`.
Even after moving finalize fully into workers (which is itself constrained
because `setPostTxApplyFeeProcessing` must run after the fee refund and
must be appended to the meta), the recoverable critical-path cost is well
below 1% of apply time. Additionally, moving finalize into workers shifts
work from the serial thread into the parallel phase where workers are
already saturated; the Amdahl's-law benefit accrues only if the serial
phase is the bottleneck, which prior evidence shows it is not (≤1.12%).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — prior post-tx-set fail
(`001-parallelize-post-tx-set-apply-fee-refunds.md`) targeted parallelizing
fee-refund execution across threads; prior allocation-pooling fail
(`016-pool-allocate-per-tx-state-objects.md`) targeted construction-time
allocation. Neither targeted moving the per-tx XDR finalization work itself
from the serial thread into the parallel workers.

### Why It Failed

Below the objective severity threshold. The full post-tx-set serial phase
including `finalize` is bounded at ~1.06-1.12% of soroswap close time per
prior non-Tracy benchmark data. `finalize` is a strict sub-component of that
phase, so its complete elimination from the serial path cannot reach the 1%
Low noise floor — let alone the 3% Medium floor required for hypothesis
promotion. Worker-side relocation also competes with already-saturated
parallel CPU (clusters fill all `NUM_CLUSTERS=8` lanes), so any "moved"
work that doesn't fit in the worker's existing slack adds critical-path
cost rather than removing it. Extends Meta-Pattern 9 (pre-parallel-apply
phase is thin) to its mirror serial post-apply phase and confirms the
post-tx-set sub-component analysis: serial XDR finalization is a real
per-tx cost but its absolute apply-time share is structurally sub-noise.

### Lesson Learned

Both pre-apply and post-apply serial-phase per-tx CPU costs are exhaustively
sub-noise for soroswap. Future hypotheses targeting per-tx serial CPU
relocation into workers (whether for finalize, meta-XDR assembly, result
extraction, or fee-event splicing) should be rejected without new trace
evidence showing the parent serial phase substantially above 3% Medium.
Worker slack must also be verified before "moving work to parallel" —
soroswap's T=8 lanes are already CPU-saturated by Soroban invocation, so
adding serial-phase work to workers does not always reduce critical path.
