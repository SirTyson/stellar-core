# H001: Parallelize per-tx Soroban fee refunds in processPostTxSetApply

**Date**: 2026-04-30
**Subsystem**: transactions, ledger
**Severity**: Medium
**Impact**: Apply-time reduction (parallelize a serial post-apply phase)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all parallel-apply stages complete, each Soroban transaction needs its
refundable fee returned to the fee source account, the per-tx meta change
record produced, and `feePool` decremented. Because fee sources for distinct
transactions are (in steady state) distinct accounts, and the only true
shared mutable value is the scalar `feePool` field on the ledger header, the
work can be sharded across the existing `LEDGER_CLOSE_WORKER_THREADS` (= 8 in
the benchmark) and reconciled deterministically: refunds applied in parallel
to disjoint account entries, results buffered, then `feePool` reduced by a
single summed delta and meta emitted in canonical tx order. End-state
ledger and meta should be byte-identical to the current serial loop.

## Mechanism

Today `LedgerManagerImpl::processPostTxSetApply`
(`src/ledger/LedgerManagerImpl.cpp:3094-3148`) walks every applied tx
serially: it constructs a per-tx `LedgerTxn ltxInner(ltx)`, calls
`TransactionFrame::processPostTxSetApply` (which runs `refundSorobanFee` →
`loadAccount` + `addBalance` + `feePool -=` + `ltx.commit()`), captures
`ltxInner.getChanges()` for meta, and finally calls `processResultAndMeta`.
For ~28,945 Soroban tx invocations in the soroswap trace this consumes
≈ 290 ms wall (4.85% of the 5.77 s `applyLedger` budget) with the
`processPostTxSetApply` zone itself showing ~290 ms total / 2.5 ms self.
This phase runs strictly between the parallel-apply stage barrier and the
remainder of the close-ledger pipeline, so the entire 290 ms is on the
critical path. Parallelizing per-tx refund + meta-capture across the
existing close-worker pool and reconciling `feePool` and meta ordering at
the end should reduce the serial portion to a fixed merge cost, yielding a
projected 3-4% reduction in apply time without changing observable output.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py` with `tx=2000 t=8`); examine Tracy zone
`processPostTxSetApply` under `applyLedger` — the zone is currently a
single-threaded loop over all parallel-stage txs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3094-3148` — `processPostTxSetApply` serial loop over `applyStages`.
- `src/transactions/TransactionFrame.cpp:2782-2820` — `TransactionFrame::processPostTxSetApply` (calls `refundSorobanFee`).
- `src/transactions/TransactionFrame.cpp:1045-1083` — `refundSorobanFee` (only true cross-tx shared state is `header.current().feePool`).
- `src/transactions/FeeBumpTransactionFrame.cpp:255` — fee-bump variant (must be handled identically).
- `src/transactions/ParallelApplyUtils.h/.cpp` — existing `ThreadParallelApplyLedgerState` infrastructure that already applies disjoint per-tx writes deterministically; the same merge pattern can be reused for the post-apply refund phase.

## Evidence

- Tracy export (csvexport-release): `processPostTxSetApply` 293 ms total /
  2.5 ms self, 69 invocations (one per ledger), running serially on the
  apply thread.
- The per-tx work (`LedgerTxn ltxInner` ctor + load fee-source account +
  `addBalance` + commit + getChanges + processResultAndMeta) is small but
  multiplied by ~28,945 calls; aggregate is the 4.85% slice above.
- Fee sources for distinct transactions in the soroswap workload are
  distinct accounts, so concurrent `loadAccount`/`addBalance` operations
  don't conflict on entry-level state.
- The only ledger-header mutation is `header.current().feePool -=
  feeRefund` — a scalar that trivially commutes across txs and can be
  collapsed into a single subtraction of the summed refund.
- The existing `ParallelApplyUtils` infrastructure already proves
  deterministic per-tx-disjoint writes can be merged back into a parent
  `LedgerTxn` in canonical order (see `commitChangesToLedgerTxn`); reusing
  this pattern for the refund phase is a structural extension, not a new
  concurrency design.
- Meta order must remain canonical (tx index order); buffering per-tx
  `LedgerTxn::getChanges()` and `processResultAndMeta` outputs and
  flushing them in order at the end preserves byte-identical meta.

## Anti-Evidence

- `feePool` is a shared mutable scalar on the ledger header — naive
  per-thread `loadHeader()` mutation would race. Mitigation: each worker
  computes its local refund sum without touching `feePool`; the apply
  thread applies the single aggregate decrement after the join. Since
  `feePool` is not read by any tx during this phase, ordering is
  irrelevant.
- Account-merge handling (`loadAccount` returns null if the fee-source
  account was merged) currently early-returns 0; this remains correct
  per-thread without coordination.
- Per-tx work is small (~10 µs avg), so per-task scheduling overhead
  matters: the implementation must batch many txs per worker (e.g.,
  contiguous tx-index ranges) rather than spawning one task per tx.
- Determinism: `setPostTxApplyFeeProcessing` and `processResultAndMeta`
  must be invoked in canonical (txNum) order to keep `LedgerCloseMeta`
  byte-identical. This requires a deterministic merge step after the
  parallel phase, identical to the existing parallel-apply meta merge.
- A previous fail (`fail/transactions/00x-parallel-fee-processing`)
  rejected parallelizing `processFeesSeqNums` because of `feePool`
  contention. That fail concerned the *pre-apply* phase, where every tx's
  fee debit must be applied before any tx runs (reads/writes interleaved
  with execution). The post-apply refund phase is structurally different:
  it runs *after* all apply work completes, has no interleaving with tx
  execution, and the `feePool` decrement is the only cross-tx dependency
  — exactly the situation where a sum-and-apply-once pattern works.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/transactions`, `ai-summary/success/transactions`, or the cross-subsystem fail/success records
**Failed At**: reviewer

### Trace Summary

The serial post-tx-set refund path exists: `applyTransactions` runs parallel Soroban stages, then `processPostTxSetApply` iterates the flattened `ApplyStage` objects in deterministic order and calls each transaction's post-tx-set hook before appending its final result. In the apply-load benchmark configuration, metadata output and test meta collection are disabled, so the currently measured path skips the outer per-transaction `LedgerTxn ltxInner` and `setPostTxApplyFeeProcessing` work; the remaining serial work is `TransactionFrame::processRefund` -> `refundSorobanFee`, which creates its own child `LedgerTxn`, loads the fee-source account, adds the refund, decrements `feePool`, finalizes `feeCharged`, and commits. The inefficiency is real, but the authoritative non-Tracy phase timings show `post_tx_set_apply` at only about 3.33-3.35 ms median while soroswap close time is about 297-313 ms median. Even eliminating the entire phase would save only about 1.1% of close time, below this objective's Medium severity threshold.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:34-42,120-124,417-424` — the active soroswap scenario is `TX=2000, T=8`; it inherits the default testing flags and renders benchmark overrides for the measured run.
- `docs/apply-load-benchmark-sac.cfg:18-22` — the benchmark template disables Soroban metrics and transaction meta collection and sets `METADATA_OUTPUT_STREAM = ""`, so `ledgerCloseMeta` is null and test-only tx meta storage is disabled in apply-load.
- `src/ledger/LedgerManagerImpl.cpp:2790-2963` — `applyTransactions` records phase timings, applies parallel phases, then calls `processPostTxSetApply` before tail metrics and stage destruction.
- `src/ledger/LedgerManagerImpl.cpp:3094-3148` — `processPostTxSetApply` is serial; with metadata enabled it uses an outer child `LedgerTxn` and records post-apply fee-processing changes, but with `ledgerCloseMeta == nullptr` it operates directly on the parent `LedgerTxn`.
- `src/transactions/TransactionFrame.cpp:1045-1083,2782-2816` — `processPostTxSetApply` calls `processRefund`, which calls `refundSorobanFee`; refunding creates an inner child `LedgerTxn`, loads the forwarded fee source account, applies `addBalance`, calls `finalizeFeeRefund`, decrements `header.current().feePool`, commits, and emits an after-all-txs fee event.
- `src/transactions/FeeBumpTransactionFrame.cpp:255-262` — the fee-bump variant forwards the outer fee-source account to the inner transaction's refund logic.
- `src/transactions/MutableTransactionResult.cpp:300-305,421-442` — `finalizeFeeRefund` mutates the transaction result's charged fee, including protocol-gated fee-bump result behavior.
- `src/transactions/ParallelApplyStage.h:74-158` and `src/transactions/ParallelApplyStage.cpp:15-74` — `TxBundle` retains the canonical transaction number and `ApplyStage` iteration flattens clusters deterministically, which explains the current result/meta order.
- `src/ledger/LedgerTxn.cpp:429-453,481-487,531-539,570-608` — `LedgerTxn` is thread-affine and supports only one active child, so the current `LedgerTxn` operations cannot simply be run concurrently against the same parent; any parallel version would need separate buffered state plus a deterministic merge.
- `/mnt/nvme2/apply-load/1695facd04c8-20260429-010922/logs/1695facd04c8-20260429-010922-02-soroswap-tx-2000-t-8.log:2366,2372,2394` — non-Tracy p50 close time was 313.255 ms and `post_tx_set_apply` median was 3.35 ms.
- `/mnt/nvme2/apply-load/1695facd04c8-20260429-011626/logs/1695facd04c8-20260429-011626-02-soroswap-tx-2000-t-8.log:2366,2372,2394` — non-Tracy p50 close time was 297.380 ms and `post_tx_set_apply` median was 3.33 ms.
- `/mnt/nvme2/apply-load/1695facd04c8-20260429-012311/logs/1695facd04c8-20260429-012311-02-soroswap-tx-2000-t-8.log:2366,2372,2394` — non-Tracy p50 close time was 304.891 ms and `post_tx_set_apply` median was 3.35 ms.

### Why It Failed

This is below the objective severity threshold. The post-tx-set refund loop is a real serial apply-path phase, but the accepted non-Tracy benchmark data bounds the entire phase at roughly 1.06-1.12% of soroswap close time. A correct parallel implementation could not recover more than the whole phase, and would recover less after worker scheduling, buffered state construction, conflict handling for repeated fee-source accounts, deterministic result/meta emission, and the final `LedgerTxn` merge. Therefore it cannot plausibly reach the required 3-10% Medium improvement.

### Lesson Learned

Aggregate Tracy totals must be converted to per-ledger phase cost and compared with the authoritative non-Tracy close-time baseline before promotion. For the current apply-load configuration, post-tx-set Soroban refunds remain serial but are only a Low-tier slice; additionally, metadata-specific costs in `processPostTxSetApply` are not part of the measured soroswap path because metadata output and test meta collection are disabled.
