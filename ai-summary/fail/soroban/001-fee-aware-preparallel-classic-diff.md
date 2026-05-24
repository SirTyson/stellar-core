# H001: Fee-aware classic-key diff to unlock parallel Soroban pre-apply

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: soroswap apply-time reduction by moving read-only Soroban pre-apply work out of the serial global setup path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After `processFeesSeqNums` has charged a Soroban transaction's own fee source, pre-parallel setup should distinguish that expected fee-processing delta from unrelated classic-ledger dependencies. A transaction whose only current-vs-LCL classic difference is its own already-charged source/fee account should still run `preParallelApplyReadOnly` in the existing worker-parallel path, then replay `preParallelApplyWrite` in deterministic transaction order.

## Mechanism

`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` calls `requiresSequentialPreParallelApply` after fee processing has already mutated source/fee accounts in the parent `LedgerTxn`. The gate compares the current source account, fee source account, operation source accounts, and classic footprint keys against the LCL snapshot; normal fee debits therefore look like classic dependencies and force `tx->preParallelApply(...)` to run serially. A stricter fee-aware classifier can accept only the exact account delta caused by this transaction's own fee charge, keep all other classic mutations on the sequential path, and let the existing read-only validation/signature/resource work run across the bounded worker set without changing write ordering.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. The diagnostic log reports `soroban_setup_glbl` at **24.40 ms mean / 24.24 ms median per ledger**, while Tracy reports `readOnlyPreParallelApply` effectively unused (**5.308 us total over 72 calls**). A PoC should count how many transactions are forced sequential only because their own fee-source entry differs from LCL, route those through the read-only batch, and show lower `soroban_setup_glbl` plus a reproducible top-line soroswap apply-time win.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:170-207` — `requiresSequentialPreParallelApply` performs current-vs-previous classic-key comparisons.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup partitions txs between sequential `preParallelApply` and `readOnlyPreParallelApply`.
- `src/transactions/ParallelApplyUtils.cpp:526-583` — existing bounded read-only worker path that should carry the eligible Soroban txs.
- `src/transactions/TransactionFrame.cpp:2145-2198` and `:2271-2349` — read-only pre-apply fills `ParallelPreApplyInfo`; write replay stays ordered through `preParallelApplyWrite`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `soroban_setup_glbl` timing window around `GlobalParallelApplyLedgerState` construction.

## Evidence

- Current soroswap diagnostic log: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.log`.
- Phase table: `soroban_setup_glbl` median **24.24 ms**, more than 10% of the current ~218 ms non-Tracy median baseline.
- Current soroswap Tracy trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
- `csvexport-release -f "preParallelApply"` shows `readOnlyPreParallelApply` only **5,308 ns** total, while `preParallelApply`/`preParallelApplyReadOnly` still run 16,036 times, consistent with the serial fallback carrying the workload.
- Source inspection confirms fee processing happens before `applySorobanStages`, and the sequential gate compares fee-mutated current accounts against the LCL snapshot.

## Anti-Evidence

- The classifier must be stricter than "ignore source-account differences": it can accept only the exact fee-processing mutation for the transaction's own fee source/source account, and must continue rejecting operation-source changes, footprint classic-key changes, one-time signer changes not replayable through `ParallelPreApplyInfo`, fee-bump edge cases, and any account delta beyond the charged fee. If only a small fraction of soroswap transactions qualify, the setup reduction may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-fused-soroban-fee-preapply-state`
**Failed At**: reviewer

### Trace Summary

The source trace confirms the described mechanics: `processFeesSeqNums` charges Soroban fee/source accounts before `applyParallelPhase`, then `GlobalParallelApplyLedgerState` compares the fee-mutated current `LedgerTxn` against the LCL snapshot and sends modified classic-account cases down serial `preParallelApply`. However, this is substantially the same finding already retained as `001-fused-soroban-fee-preapply-state`, whose summary explicitly records that "fee-source dirtiness bypasses v26 read-only pre-apply dispatcher" and rejected the optimization because normalized impact did not clear the objective's 3% Medium review floor. The current hypothesis repackages that same fee-source-dirtiness/read-only-dispatcher mechanism, so it is not novel.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:129` — prior retained failure for `001-fused-soroban-fee-preapply-state` covers the same fee-source dirtiness bypass of the v26 read-only pre-apply dispatcher.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` runs before transaction application and charges each transaction's fee source in ledger order.
- `src/ledger/LedgerManagerImpl.cpp:2784-3029` — `applyTransactions` builds parallel Soroban phases after fee processing and invokes `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `sorobanSetupGlobalMs` measures construction of `GlobalParallelApplyLedgerState`, including the pre-parallel setup under discussion.
- `src/transactions/ParallelApplyUtils.cpp:170-207` — `requiresSequentialPreParallelApply` compares source, fee source, operation sources, and classic footprint keys between current state and previous snapshot.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — v26 setup sends transactions with modified classic keys to serial `preParallelApply`; only the remainder use `readOnlyPreParallelApply` plus ordered write replay.
- `src/transactions/TransactionFrame.cpp:2145-2198` and `src/transactions/TransactionFrame.cpp:2271-2349` — read-only pre-apply records sequence/signer/metric actions in `ParallelPreApplyInfo`; ordered write replay applies them through `preParallelApplyWrite`.

### Why It Failed

This is a duplicate of the prior `001-fused-soroban-fee-preapply-state` investigation. That retained failure already recognized the same underlying fee-source dirtiness issue and rejected it under the optimize-soroswap review criteria because the normalized projected savings did not meet the Medium threshold.

### Lesson Learned

Fee-source dirtiness bypassing v26 read-only pre-apply is a known issue, but future submissions must bring genuinely new mechanics or new benchmark evidence strong enough to overcome the prior retained severity finding; renaming the classifier around the same serial fallback is not novel.
