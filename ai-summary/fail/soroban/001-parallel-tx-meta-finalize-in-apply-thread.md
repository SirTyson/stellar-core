# H001: Parallel Per-Tx Meta Finalization Inside `applyThread`

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 2-4% soroswap apply-time reduction by moving sequential per-tx
meta XDR finalization off the serial commit-tail and into the parallel
cluster workers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After the parallel Soroban stage executes, the apply path should perform
only work that genuinely depends on a globally consistent ledger state
sequentially. Per-transaction meta finalization — flattening
`TransactionMetaBuilder::finalize(bool success)` into a `TransactionMeta`
XDR by reading per-tx event managers, return values, and per-op meta
builders — is per-tx pure: it reads only the txBundle's own
`MutableTransactionResult` and `Effects` (its own `TxEventManager`,
`DiagnosticEventManager`, per-op event managers). Therefore it should
execute on the cluster worker thread as soon as the tx's `parallelApply`
returns, in parallel with all other clusters' workers, rather than being
serialized in the post-parallel `processResultAndMeta` /
`processPostTxSetApply` pass on the apply thread.

## Mechanism

`TransactionMetaBuilder::finalize` (`src/transactions/TransactionMeta.cpp:1036`)
is currently called from `processResultAndMeta`
(`src/ledger/LedgerManagerImpl.cpp:2761`) and from `processPostTxSetApply`
(`src/ledger/LedgerManagerImpl.cpp:3137`) — both run sequentially on the
apply thread after the parallel cluster `future.get()` join in
`applySorobanStageClustersInParallel`. For a soroswap-shaped ledger
(~95 Soroban txs/ledger), each `finalize` walks per-tx event managers,
calls `EventManager::finalize()` (XDR move/encode), constructs a
`TransactionMeta` variant, calls `setOperationMetas`, etc. With
DISABLE_TX_META_FOR_TESTING=false (the default for the apply-load
benchmark, which in BUILD_TESTS forces `enableTxMeta = true` regardless
of `ledgerCloseMeta` nullness — see
`LedgerManagerImpl::applyTransactions:2843`), every tx pays this cost
sequentially. The actual result deviates from the expected behavior:
work that has zero cross-tx dependency runs on the single apply thread
during the commit-tail instead of overlapping with the still-busiest
cluster worker. Moving `finalize` into `applyThread` (or into a new
post-tx hook invoked by `applyThread` after `parallelApply` returns)
removes ~`per_tx_finalize × tx_count` from the serial tail and replaces
it with a constant per-cluster cost paid in parallel, normalized by
NUM_CLUSTERS=8.

## Trigger

Reproduce the soroswap apply-load run as in `CURRENT_STATE.md`. Soroswap
generates ~95 Soroban txs per ledger across 71 measured ledgers; every
tx's `TransactionMetaBuilder::finalize` is invoked sequentially on the
apply thread, immediately after the parallel apply join and before
`applyStages.clear()`.

## Target Code

- `src/transactions/TransactionMeta.cpp:1036-1109` —
  `TransactionMetaBuilder::finalize` body: walks per-tx event managers,
  diagnostic event managers, op meta builders; pure per-tx work with no
  shared-state writes.
- `src/ledger/LedgerManagerImpl.cpp:2727-2782` — `processResultAndMeta`
  calls `txMetaBuilder.finalize` sequentially after the parallel join,
  one tx at a time.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — `processPostTxSetApply`
  also calls `processResultAndMeta` per tx; both call sites are
  serialized on the apply thread.
- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread` is the
  natural attachment point: after `parallelApply` returns and
  `commitChangesFromSuccessfulTx` runs, the txBundle's `Effects` /
  `MutableTransactionResult` are fully populated and ready to feed into
  `finalize`. The only added cross-thread state is the resulting
  `TransactionMeta` xdr value, which is plain data and trivially
  std::move-able to the main thread on join.
- `src/transactions/EventManager.h` and
  `src/transactions/TransactionFrame.h:377` — confirm per-tx event
  manager containment (no cross-tx dependency).

## Evidence

- The serial commit-tail visible in the diagnostic Tracy trace
  (`processResultAndMeta`-region work plus `processPostTxSetApply`)
  totals an estimated 3-5 ms/ledger on the soroswap workload (95 txs ×
  ~30-50 µs per `finalize` of typical Soroban-tx event/return-value/op
  meta payload). Even at the conservative end this is ~1.1-1.8% of the
  272 ms median; at the upper end with ~50 µs/finalize and including
  the XDR-encode cost of ~3 transfer events per swap with topic
  serialization, it crosses the 3% Medium floor (≥8.2 ms/ledger).
- `TransactionMetaBuilder::finalize` is gated by `mFinalized` and
  `mEnabled` only and contains no inter-tx coordination — no global
  mutex, no shared map, no LedgerTxn touch. It reads only members of
  the same `TransactionMetaBuilder` instance and event managers stored
  on the per-tx `Effects` object that `applyThread` already holds.
- `applyThread` already holds the txBundle through
  `commitChangesFromSuccessfulTx` (line 2510), so adding a finalize
  call immediately after that line is structurally trivial. The result
  is a plain XDR value that can be stored on the txBundle's
  `Effects::Meta` (already a thread-local accumulator) and consumed by
  the main thread during `processResultAndMeta` without re-running the
  expensive build step.
- This optimization is explicitly distinct from
  `fail/soroban/003-meta-disabled-success-hash-output.md`: that
  hypothesis tried to skip metering-relevant XDR work when meta output
  is disabled and was rejected because `metered_write_xdr` charges run
  regardless of buffering. This hypothesis preserves all C++-side meta
  work and all host-side metering; it only relocates *where* on the
  thread topology the C++ `TransactionMetaBuilder::finalize` runs. No
  protocol-visible behavior changes.
- This optimization is also distinct from
  `fail/soroban/021-addlivebatch-as-third-async-future.md` and
  `fail/soroban/006-parallelize-livebucket-fresh-encode-hash.md`,
  which target post-finalize bucket work. Here the move is *upstream*
  of finalize, into the existing parallel worker pool, which has no
  added thread-launch cost (workers are already running).

## Anti-Evidence

- `processResultAndMeta` also pushes `TransactionResultPair` into the
  shared `txResultSet` and updates `mApplyState.getMetrics()` counters.
  These remaining tail steps must stay on the main thread, but they
  are constant-time per tx and not the dominant cost — the dominant
  cost is the `txMetaBuilder.finalize` body.
- `mLastLedgerTxMeta.emplace_back(metaXDR)` is BUILD_TESTS-only test
  scaffolding (`LedgerManagerImpl.cpp:2765`) but is not the bottleneck;
  it can stay on the main thread.
- `processPostTxSetApply` in the parallel-phase path (line 3107) calls
  `tx->processPostTxSetApply` *after* the parallel apply, modifying
  the shared `ltx`. This must remain sequential due to fee-source
  ordering (per `fail/soroban/001-detached-copy-parallel-process-fees`).
  However, the meta-finalize step inside `processResultAndMeta` does
  not depend on `processPostTxSetApply`'s ltx writes — only on the
  refundable-fee-tracker meta which is already attached to the
  per-tx `Effects` before the apply-thread tail runs. The exact
  ordering between fee-refund meta updates and finalize must be
  verified; if `setPostTxApplyFeeProcessing` mutates meta after the
  parallel join, finalize must come after that step rather than
  inside `applyThread` — but it can still be parallelized at the
  finalize call site by a per-tx `std::async` or a worker-pool
  dispatch.
- The cost of moving across thread boundaries (the xdr
  `TransactionMeta` move) must be smaller than the saved sequential
  finalize work; for soroswap-typical metas (~few KB) this should be
  far below the saved 30-50 µs/tx.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The current parallel Soroban path does call `TransactionMetaBuilder::finalize` sequentially from `processResultAndMeta`, but the builder is not complete when `applyThread` finishes a transaction. After all worker futures join, the apply thread still calls `processPostTxSetApply`, which runs `processRefund` and appends the after-all-transactions refund fee event to the same per-tx `TxEventManager` that `finalize` later moves into `TransactionMeta`. The claimed placement in `applyThread` would therefore either omit refund events or trip the event-manager `mFinalized` assertions when post-apply fee processing tries to append events.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread` runs each cluster sequentially on a worker and commits successful tx entry changes, but does not run post-tx-set refund processing.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` waits for all worker futures before any post-tx-set processing occurs.
- `src/ledger/LedgerManagerImpl.cpp:2577-2620` — after stage execution, `checkAllTxBundleInvariants` calls `maybeSetRefundableFeeMeta`, another metadata mutation that happens outside the worker loop.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — parallel-phase `processPostTxSetApply` calls each tx's `processPostTxSetApply`, records `postTxApplyFeeProcessing`, then calls `processResultAndMeta`.
- `src/transactions/TransactionFrame.cpp:2782-2816` — `processPostTxSetApply` delegates to `processRefund`, which calls `TxEventManager::newFeeEvent(..., TRANSACTION_EVENT_STAGE_AFTER_ALL_TXS)` after the parallel workers have already returned.
- `src/transactions/EventManager.cpp:603-640` — `TxEventManager::newFeeEvent` requires `!mFinalized`, and `TxEventManager::finalize` marks the manager finalized and moves out its buffered events.
- `src/transactions/TransactionMeta.cpp:1035-1109` — `TransactionMetaBuilder::finalize` marks the builder finalized, moves operation, transaction, and diagnostic event vectors into the XDR, and returns the completed `TransactionMeta`.

### Why It Failed

The proposed worker-thread attachment point is not correctness-preserving. For v23+ parallel Soroban transactions, the refund fee event is a required part of transaction metadata and is appended only during the sequential `processPostTxSetApply` loop after the worker futures have joined. Finalizing inside `applyThread` would freeze `TxEventManager` before `processRefund` emits that event.

The performance claim is also overstated for the only correctness-preserving variant. `EventManager::finalize` implementations simply mark finalized and `std::move` their existing XDR vectors; `TransactionMetaBuilder::finalize` mostly moves already-built data and sets variant fields. There is no event XDR encode in this function body. If finalization were parallelized after `processPostTxSetApply`, it could no longer reuse the existing cluster workers and would need extra dispatch/join machinery around a small move-heavy operation, making a reproducible 3%+ apply-time reduction implausible under the optimize-soroswap Medium threshold.

### Lesson Learned

In the parallel Soroban path, per-tx metadata remains mutable until after post-tx-set fee refund processing. Any future metadata optimization must preserve the ordering `parallelApply` -> invariant/refundable-fee metadata -> `processPostTxSetApply` refund event -> `finalize`, and should first measure the entire post-tx-set/finalize parent phase because the standalone `finalize` body is mostly container moves rather than serialization.
