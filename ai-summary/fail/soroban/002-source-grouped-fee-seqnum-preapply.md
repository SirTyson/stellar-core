# H002: Source-grouped Soroban fee and pre-apply fusion

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: soroswap apply-time reduction by collapsing two serial source-account passes before parallel execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For Soroban-only parallel phases, source-account fee charging and pre-parallel validation should preserve the same deterministic per-source transaction order while avoiding two separate serial passes over the same source/fee accounts. Transactions with independent fee sources can be grouped and processed with bounded parallelism, while transactions sharing a fee source remain ordered exactly as today.

## Mechanism

The current close path first runs `processFeesSeqNums` serially for the whole tx set, then `GlobalParallelApplyLedgerState` performs pre-parallel setup and may run serial `preParallelApply` for transactions whose fee-source account was just dirtied. This creates two source-account-heavy passes before worker `parallelApply`: one in `LedgerManagerImpl::processFeesSeqNums` and one in Soroban global setup. A source-grouped pipeline could process fee/sequence effects and read-only pre-apply classification together per deterministic fee-source group, replaying writes in original transaction order at group boundaries and capping parallelism to `LEDGER_CLOSE_WORKER_THREADS`/`NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load scenario from the accepted baseline. The diagnostic phase table shows **5.22 ms median-scale `process_fees_seqnums`** and **24.24 ms median `soroban_setup_glbl`** before `soroban_parallel` begins. A PoC should build fee-source groups for the Soroban phase, keep same-source transactions in original order, process disjoint groups through the fused fee/pre-apply pipeline, and compare three non-Tracy apply-load runs plus phase timing changes.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` serial fee/sequence pass before transaction application.
- `src/ledger/LedgerManagerImpl.cpp:2860-3030` — transition from fee processing into `applyParallelPhase` and `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 pre-parallel setup that currently reacts to fee-dirtied accounts after the fact.
- `src/transactions/TransactionFrame.cpp:2145-2349` — split read-only/write pre-apply pieces that can be reused by a fused grouped pipeline.
- `src/transactions/FeeBumpTransactionFrame.cpp:86-153` — fee-bump pre-apply split that must remain ordered and should probably stay on the conservative sequential path initially.

## Evidence

- Current soroswap diagnostic log reports `process_fees_seqnums` at **5.22 ms mean / 5.23 ms median** and `soroban_setup_glbl` at **24.40 ms mean / 24.24 ms median** per ledger.
- Source inspection shows the second phase's sequential gate is directly affected by account mutations from the first phase, so the two phases are not independent in practice.
- The existing parallel-apply architecture already groups transaction execution by conflict stages; a fee-source grouping for pre-worker setup can preserve deterministic order within each account while allowing independent accounts to be prepared concurrently.

## Anti-Evidence

- A prior detached-copy fee-processing idea failed because `isSoroban()` alone does not imply fee-source independence. This hypothesis must explicitly group by fee source and preserve original order within each group; otherwise it is not viable.
- The standalone `process_fees_seqnums` phase is below Medium by itself. The hypothesis only clears the severity threshold if fusing it with setup also unlocks the read-only pre-apply path and materially reduces the combined ~29 ms pre-worker serial window. If it only parallelizes fee charging, it should be rejected as below threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-fused-soroban-fee-preapply-state` and the individual retained review `ai-summary/fail/soroban/001-fee-aware-preparallel-classic-diff.md`
**Failed At**: reviewer

### Trace Summary

The traced close path matches the hypothesis: `LedgerManagerImpl::applyLedger` calls `processFeesSeqNums` before `applyTransactions`, so source/fee accounts are fee-mutated before Soroban global setup. `applySorobanStages` then constructs `GlobalParallelApplyLedgerState`, whose v26 setup checks current-vs-LCL classic account and footprint keys; transactions with fee-dirtied classic keys fall back to serial `preParallelApply`, while only clean transactions use the bounded read-only pre-apply workers plus ordered write replay. This is the same fee-source-dirtiness/read-only-dispatcher mechanism already retained as `001-fused-soroban-fee-preapply-state`, and the prior retained review rejected it under the optimize-soroswap Medium threshold.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:129` — prior retained failure covers "Fuse Soroban fee processing with pre-parallel apply state" and explicitly notes fee-source dirtiness bypassing the v26 read-only pre-apply dispatcher.
- `ai-summary/fail/soroban/001-fee-aware-preparallel-classic-diff.md:51-67` — individual fail file traces the same processFeesSeqNums-to-v26-preParallelApply path and rejects it as duplicate/sub-threshold.
- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — fee/sequence processing completes before `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` iterates txs in apply order and calls `processFeeSeqNum` for each transaction.
- `src/transactions/TransactionFrame.cpp:1777-1817` — regular transaction fee processing debits the source account and updates the fee pool; sequence numbers are deferred to apply for modern protocols.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `sorobanSetupGlobalMs` measures construction of `GlobalParallelApplyLedgerState`, the setup window targeted by the hypothesis.
- `src/transactions/ParallelApplyUtils.cpp:171-207` — `requiresSequentialPreParallelApply` compares source, fee source, operation-source, and footprint classic keys between current state and the previous snapshot.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — v26 setup sends modified-classic-key transactions to serial `preParallelApply` and sends only the rest through `readOnlyPreParallelApply` plus ordered write replay.
- `src/transactions/ParallelApplyUtils.cpp:526-597` — existing read-only worker path is bounded by `LEDGER_CLOSE_WORKER_THREADS` and replays writes in deterministic transaction-vector order.
- `src/transactions/TransactionFrame.cpp:2145-2349` — read-only pre-apply records `ParallelPreApplyInfo`; `preParallelApplyWrite` later applies sequence/signer/metric side effects through the ledger transaction.
- `src/transactions/FeeBumpTransactionFrame.cpp:86-153` — fee-bump pre-apply already splits read-only and write phases, but its outer fee-source signer mutation makes it part of the same conservative ordering problem.

### Why It Failed

This is not novel. The source-grouped fusion proposal is a broader formulation of the already-retained fee-source dirtiness/pre-parallel setup finding, and the prior retained record already rejected promotion because the normalized projected savings did not clear the optimize-soroswap 3% Medium review floor.

### Lesson Learned

Future Soroban pre-apply hypotheses must either introduce a materially different mechanism from fee-source dirtiness bypassing the v26 read-only dispatcher, or provide new benchmark-normalized evidence that overcomes the retained `001-fused-soroban-fee-preapply-state` severity finding.
