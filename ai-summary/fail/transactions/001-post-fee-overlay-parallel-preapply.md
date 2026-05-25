# H001: Post-Fee Overlay Enables Parallel Soroban PreApply

**Date**: 2026-05-25
**Subsystem**: transactions
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by making the V26 read-only pre-parallel-apply split reachable for fee-only source-account updates
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban-only ledger, fee debits must still happen before transaction application, and sequence-number / one-time-signer writes must still be committed in deterministic transaction order. The read-only part of pre-parallel apply should be able to validate signatures, sequence constraints, Soroban resource fees, and operation validity against the post-fee account state without treating fee-only account deltas as a classic-phase conflict that forces every transaction through serial `preParallelApply`.

## Mechanism

`processFeesSeqNums` mutates every fee/source account before `GlobalParallelApplyLedgerState` is constructed. The V26 split path then calls `requiresSequentialPreParallelApply`, which compares the current `LedgerTxn` against the LCL snapshot for each source, fee-source, op-source, and classic footprint key; because fee processing already changed each source account, every soroswap transaction looks like it depends on modified classic state and falls into the serial `txBundle.getTx()->preParallelApply(...)` branch instead of the parallel `readOnlyPreParallelApply` / ordered `commitBufferedPreParallelApplyWrites` path.

The proposed change is to have fee processing produce a deterministic post-fee overlay (or a set/map of account keys whose only current-vs-LCL difference is the known fee debit), then evaluate `requiresSequentialPreParallelApply` and `preParallelApplyReadOnly` against that post-fee baseline. True classic-phase modifications would still force sequential preapply, but fee-only source-account changes would no longer serialize the read-only validation work; writes would still be buffered and committed in original tx order, preserving ledger output determinism and staying bounded by the configured cluster/worker count.

## Trigger

Run the accepted soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) at V26. The workload has a single parallel Soroban phase with 2000 txs and no classic phase, but every tx source account is fee-debited before global parallel state setup, so `requiresSequentialPreParallelApply` classifies the txs as requiring sequential preapply. A PoC should show non-empty `txBundles` in `GlobalParallelApplyLedgerState::readOnlyPreParallelApply`, lower `soroban_setup_glbl`, and a reproducible 3-10% reduction in soroswap median close/apply time across three non-Tracy runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` mutates fee/source accounts before Soroban global state setup; this is where a post-fee overlay or fee-only modified-key record could be produced.
- `src/transactions/ParallelApplyUtils.cpp:151-208` — `isModifiedClassicKey` and `requiresSequentialPreParallelApply` currently compare current vs LCL snapshots without distinguishing fee-only source-account deltas from classic-phase conflicts.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 global setup sends sequential-required txs through serial `preParallelApply`, otherwise through `readOnlyPreParallelApply` plus ordered buffered writes.
- `src/transactions/TransactionFrame.cpp:2146-2198` — `commonParallelPreApplyReadOnly` performs the read-only validation work that should be parallelizable once it can observe the correct post-fee baseline.
- `src/transactions/TransactionFrame.cpp:2315-2349` — `preParallelApplyWrite` applies sequence/signer side effects and can remain ordered to preserve deterministic ledger state.

## Evidence

`ai-summary/CURRENT_STATE.md` identifies the current soroswap trace and authoritative non-Tracy runs. The non-Tracy phase breakdown shows `soroban_setup_glbl` as a large serial phase in all three accepted runs: about 24.19ms, 24.14ms, and 24.34ms median per ledger, roughly 11.6% of the 206-209ms soroswap close time. That phase contains `GlobalParallelApplyLedgerState` construction and the pre-parallel-apply split.

Timestamp-filtered Tracy events fully contained in `applyLedger` show the same boundary is real apply-path work, not TX-set construction: `preParallelApply` at `transactions/TransactionFrame.cpp:2359` accounts for 299.142ms across the trace, with `preParallelApplyReadOnly` at `TransactionFrame.cpp:2277` accounting for 117.391ms and `preParallelApplyWrite` at `TransactionFrame.cpp:2320` accounting for 31.440ms. `processFeesSeqNums` at `ledger/LedgerManagerImpl.cpp:2308` is also inside `applyLedger` at 149.404ms. The source shape explains why the intended V26 read-only split can be defeated by prior fee-source mutations even when the benchmark has no classic phase.

## Anti-Evidence

Prior simpler hypotheses around fee processing and pre-parallel-apply were rejected as sub-threshold when they only moved the thin read-only phase, parallelized fee processing, or removed per-tx micro-costs. This hypothesis is only viable if the overlay makes the broader `soroban_setup_glbl` serial work fall materially, not merely if it trims cached getter or per-tx child-LTX overhead. A PoC must also prove that non-fee classic account changes still force sequential handling, and that the post-fee overlay cannot let validation observe a stale balance, sequence number, signer set, or sponsorship state.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transactions/summary.md` entry `012-fee-processing-forces-sequential-prepar-apply.md`
**Failed At**: reviewer

### Trace Summary

The code trace confirms the mechanism: `processFeesSeqNums` runs before `applyTransactions`, debits each Soroban source or fee-source account, and commits those changes to the ledger transaction before `GlobalParallelApplyLedgerState` is constructed. In V26, `preParallelApplyAndCollectModifiedClassicEntries` compares the current ledger view against the LCL snapshot, so each fee-debited source account makes `requiresSequentialPreParallelApply` return true and sends the tx through serial `preParallelApply`. This exact mechanism has already been recorded in the transactions failure summary as `012-fee-processing-forces-sequential-prepar-apply.md`, with the same key lesson that the fast-path exemption is unreachable for the soroswap workload and below the objective's Medium threshold.

### Code Paths Examined

- `ai-summary/fail/transactions/summary.md:54` — prior failed investigation records the same fee-processing-forces-sequential-preapply mechanism and rejects it as Low/below Medium.
- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches sources, calls `processFeesSeqNums`, then calls `applyTransactions`; fee debits are committed before Soroban parallel setup.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` iterates phases in apply order and commits per-tx fee processing into the parent ledger transaction.
- `src/transactions/TransactionFrame.cpp:1777-1817` — regular tx fee processing loads the source account, subtracts the fee from account balance, and adds it to the header fee pool; for v10+ sequence numbers are not updated here.
- `src/transactions/FeeBumpTransactionFrame.cpp:765-795` — fee-bump processing mutates the outer fee-source account balance and fee pool before inner preapply.
- `src/ledger/LedgerManagerImpl.cpp:2672-2690` — `applySorobanStages` constructs `GlobalParallelApplyLedgerState`; the measured `sorobanSetupGlobalMs` covers construction including pre-parallel setup.
- `src/transactions/ParallelApplyUtils.cpp:151-208` — `isModifiedClassicKey` compares current vs previous non-Soroban entries, and `requiresSequentialPreParallelApply` checks tx source, fee source, op sources, and classic footprint keys.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup sends txs requiring sequential handling to `preParallelApply`; only the remaining txs enter `readOnlyPreParallelApply` and ordered buffered writes.
- `src/transactions/ParallelApplyUtils.cpp:526-598` — the non-sequential branch parallelizes read-only preapply across `LEDGER_CLOSE_WORKER_THREADS`, then commits `preParallelApplyWrite` serially in tx order.
- `src/transactions/TransactionFrame.cpp:2146-2198` and `src/transactions/TransactionFrame.cpp:2250-2371` — read-only preapply validates signatures, resource fees, operation validity, and records buffered write flags; `preParallelApplyWrite` later applies sequence-number and one-time-signer side effects.

### Why It Failed

This is not novel: the transactions failure summary already investigated the same source-shape finding under `012-fee-processing-forces-sequential-prepar-apply.md`. The current hypothesis reframes the mitigation as a post-fee overlay and attributes more of `soroban_setup_glbl` to the bypass, but the reviewed prior result and summary meta-patterns already bound the relevant pre-parallel-apply work below the objective's 3% Medium threshold. Because the optimize-soroswap reviewer objective rejects Low-severity findings, this duplicate remains NOT_VIABLE rather than proceeding to PoC.

### Lesson Learned

Fee processing really does make the V26 read-only preapply fast path unreachable for soroswap, but this is already known and has been severity-filtered. Future hypotheses should not re-target the same `requiresSequentialPreParallelApply` fee-source classification unless they provide new evidence that the complete removable critical-path surface exceeds the Medium threshold, not just that `soroban_setup_glbl` is an inclusive setup bucket.
