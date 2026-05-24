# H002: Post-Fee Classic Overlay for Parallel Soroban Pre-Apply

**Date**: 2026-05-24
**Subsystem**: soroban / ledger pre-parallel apply
**Severity**: Medium
**Impact**: 3-8% soroswap apply-time reduction by keeping fee-mutated classic accounts out of the `LedgerTxn` snapshot used to classify Soroban read-only pre-apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban fee charging and sequence/signature pre-apply should preserve ledger-order effects for each transaction while still allowing read-only validation and resource/account checks to run through the bounded `readOnlyPreParallelApply` worker path whenever there are no true classic dependencies. A transaction whose only classic difference from LCL is its own already-charged source or fee-source account should not force the whole pre-apply body to execute serially on the apply thread.

## Mechanism

Today `processFeesSeqNums` mutates source/fee accounts in the parent `LedgerTxn` before `GlobalParallelApplyLedgerState` is constructed. The V26 setup then compares current classic keys against the LCL snapshot in `requiresSequentialPreParallelApply`; ordinary fee debits therefore look like external classic modifications and route most Soroban transactions through serial `preParallelApply`. A post-fee overlay would capture fee-processing account deltas in a deterministic side map, expose that overlay to pre-apply reads, and delay materializing the account writes into `LedgerTxn` until after the read-only pre-apply worker phase has produced `ParallelPreApplyInfo`.

The key distinction from a narrow "ignore fee-source differences" classifier is that the overlay becomes the authoritative post-fee classic state for pre-apply reads. Source/fee account sequence numbers, balances, one-time signer removal state, and fee-charged values are read from the overlay in deterministic transaction order, while unrelated classic modifications still trigger the conservative sequential path. `preParallelApplyWrite` remains ordered, so observable account writes and result/meta effects match the current close path.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. The diagnostic phase table reports `process_fees_seqnums` median **5.23 ms/ledger** and `soroban_setup_glbl` median **24.24 ms/ledger**, while Tracy shows `readOnlyPreParallelApply` is effectively unused in the same run. A PoC should count transactions whose only classic dirtiness is represented by the post-fee overlay, send them through `readOnlyPreParallelApply`, and show `soroban_setup_glbl` falling by enough to move top-line soroswap median apply time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums`, where fee/source account mutations are currently written directly to `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — transition from fee processing into `applyParallelPhase` / `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:170-207` — `requiresSequentialPreParallelApply`, which should consult the overlay-aware classic state instead of treating every fee-dirtied account as an unrelated modification.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup partitioning between serial `preParallelApply` and worker `readOnlyPreParallelApply`.
- `src/transactions/ParallelApplyUtils.cpp:526-597` — existing bounded read-only worker path and deterministic write replay.
- `src/transactions/TransactionFrame.cpp:2145-2349` — split read-only/write pre-apply pieces that consume account state and replay sequence/signer side effects.

## Evidence

- Current soroswap diagnostic log (`62ee1ffb5d05-20260523-010230`) measures a large serial setup window: `soroban_setup_glbl` **24.24 ms median** per ledger, plus `process_fees_seqnums` **5.23 ms median** immediately before it.
- The same source path contains an existing worker implementation (`readOnlyPreParallelApply`) bounded by `LEDGER_CLOSE_WORKER_THREADS`; the issue is classification/visibility of fee-mutated classic state, not absence of a parallel executor.
- The mechanism is inside `applyLedger`: `processFeesSeqNums` completes before `applyTransactions`, and `applySorobanStages` constructs `GlobalParallelApplyLedgerState` inside the measured `apply_transactions -> parallel_total` window.
- Determinism is preserved by retaining original transaction order for overlay writes and ordered `preParallelApplyWrite` replay. Parallel read-only workers compute validation/pre-apply observations from an immutable overlay snapshot; they do not commit classic writes concurrently.

## Anti-Evidence

- This must not become a broad "ignore classic differences" shortcut. Operation-source accounts, classic footprint keys, fee-bump edge cases, one-time signer removals, and any account delta not produced by this ledger's fee pass must stay on the sequential path.
- The design touches fee processing and pre-apply state ownership, so it is more invasive than a classifier-only patch. It needs explicit handling for failed fee processing, insufficient balance fee caps, result-code propagation, and fee-bump inner/outer source interactions.
- A previous fee-dirtiness line of investigation established the shape of the bottleneck but did not get a clean final confirmation. This hypothesis should be treated as a refined overlay design: it must produce fresh three-run non-Tracy benchmark evidence, not rely solely on the phase table.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-fused-soroban-fee-preapply-state` and retained individual reviews `ai-summary/fail/soroban/001-fee-aware-preparallel-classic-diff.md` / `ai-summary/fail/soroban/002-source-grouped-fee-seqnum-preapply.md`
**Failed At**: reviewer

### Trace Summary

The source trace confirms the described ordering: `LedgerManagerImpl::applyLedger` calls `processFeesSeqNums` before `applyTransactions`, so Soroban fee-source/source accounts are already fee-mutated when `applySorobanStages` constructs `GlobalParallelApplyLedgerState`. In protocol V26+, `preParallelApplyAndCollectModifiedClassicEntries` compares the current `LedgerTxn` view against the LCL snapshot via `requiresSequentialPreParallelApply`; if the tx source, fee source, op sources, or classic footprint keys differ, the transaction is routed through serial `preParallelApply`, otherwise read-only pre-apply runs on bounded workers and write effects replay in vector order. This is the same fee-source dirtiness bypass of the V26 read-only pre-apply dispatcher retained in the previous fused fee/preapply-state failure; the overlay wording refines the implementation shape but not the investigated performance mechanism.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:129` — retained failure `001-fused-soroban-fee-preapply-state` records the same "fee-source dirtiness bypasses v26 read-only pre-apply dispatcher" mechanism and rejects it below the Medium review floor.
- `ai-summary/fail/soroban/001-fee-aware-preparallel-classic-diff.md:51-67` — prior individual review traces the same `processFeesSeqNums` to V26 pre-apply fallback path and marks the fee-aware classification idea as duplicate/sub-threshold.
- `ai-summary/fail/soroban/002-source-grouped-fee-seqnum-preapply.md:50-70` — prior individual review rejects a broader fee/pre-apply fusion formulation as duplicate of the same retained mechanism.
- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — `processFeesSeqNums` completes before `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — fee processing iterates transactions in apply order and commits fee-source/source account changes into the parent ledger transaction.
- `src/transactions/TransactionFrame.cpp:1777-1817` — regular transaction fee processing loads the source account, caps the fee by balance, debits balance, and credits the fee pool.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState` inside the measured `sorobanSetupGlobalMs` window.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` transitions from fee processing into parallel Soroban stages and invokes `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:150-207` — `isModifiedClassicKey` and `requiresSequentialPreParallelApply` compare current state with LCL for source, fee-source, op-source, and classic footprint keys.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup sends modified-classic-key transactions to serial `preParallelApply`; only clean transactions use `readOnlyPreParallelApply` followed by ordered buffered write replay.
- `src/transactions/ParallelApplyUtils.cpp:526-597` — the existing read-only worker path is bounded by `LEDGER_CLOSE_WORKER_THREADS`, and write replay preserves `txBundles` order.
- `src/transactions/TransactionFrame.cpp:2145-2349` and `src/transactions/TransactionFrame.cpp:2351-2371` — read-only pre-apply records `ParallelPreApplyInfo`; serial pre-apply performs the same read-only step and immediately applies sequence/signer/metric writes.
- `src/transactions/FeeBumpTransactionFrame.cpp:85-155` — fee-bump pre-apply also splits read-only and write phases, but outer fee-source one-time signer handling remains part of the same conservative ordering problem.

### Why It Failed

This is not novel. The post-fee overlay proposal is a refined implementation sketch for the already-investigated fee-source dirtiness / fused fee-preapply-state mechanism, whose retained review found the issue real but below the optimize-soroswap Medium severity floor after normalizing against the benchmark baseline.

### Lesson Learned

Future submissions in this area need either a materially different mechanism beyond fee-source dirtiness bypassing the V26 read-only dispatcher, or fresh benchmark-normalized evidence showing a Medium-tier top-line apply-time reduction that overcomes the retained severity finding.
