# H001: Fee-Aware Classic-Key Diff for Soroban Pre-Parallel Setup

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by shortening `soroban_setup_glbl` before parallel execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban-only ledger whose source and fee accounts were modified only by the current transaction's normal fee/sequence processing, pre-parallel validation should still use the read-only split path: run `preParallelApplyReadOnly` in parallel where possible, then replay `preParallelApplyWrite` in deterministic transaction order. Only transactions whose classic footprint depends on another transaction's prior classic mutation should be forced through fully sequential `preParallelApply`.

## Mechanism

`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` currently calls `requiresSequentialPreParallelApply`, which compares the current `LedgerTxn` against the LCL snapshot for the tx source account, fee source account, operation source accounts, and classic footprint keys. In the apply path this comparison runs after fee/sequence processing, so the tx's own source/fee account is often already different from LCL and causes an immediate sequential fallback even when the difference is the expected per-tx fee/seq mutation that `preParallelApplyWrite` can replay deterministically. A fee-aware diff that ignores the tx's own expected fee/seq account deltas, while still treating unrelated classic-key mutations as sequential dependencies, should remove the repeated current-vs-previous point-load scan and enable the existing read-only batching path without changing observable transaction order.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) on the 2026-05-23 baseline. The phase log reports `soroban_setup_glbl` at 24.40 ms mean / 24.24 ms median per ledger, while Tracy shows `readOnlyPreParallelApply` effectively unused (5.3 us total) and all setup flowing through the sequential path after the classic-key diff.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:170-207` — `requiresSequentialPreParallelApply` compares current and previous snapshots for source, fee-source, op-source, and footprint classic keys.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup partitions txs into sequential vs read-only pre-parallel apply; this is where fee-aware classification should feed the existing split path.
- `src/transactions/TransactionFrame.cpp:2271-2349` — existing deterministic split: read-only validation populates `ParallelPreApplyInfo`, and writes are replayed by `preParallelApplyWrite`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `soroban_setup_glbl` is measured around `GlobalParallelApplyLedgerState` construction before stage execution.

## Evidence

The diagnostic soroswap log's phase breakdown shows `soroban_setup_glbl` is a material serial phase: 24.40 ms mean and 24.24 ms median per ledger, over 10% of the current 218.31 ms average non-Tracy soroswap median. The same trace shows `readOnlyPreParallelApply` totals only 5.3 us, indicating the intended read-only split path is not carrying the workload. Source reading shows the gate uses current-vs-LCL diffs after fee/sequence processing, so normal own-account fee/seq mutations can look like classic dependencies and force sequential handling.

## Anti-Evidence

The earlier "precompute modified classic keys" angle was procedural-failed at final review and should not be duplicated as a pure set-precompute micro-optimization. This hypothesis is narrower: preserve the existing scan for unrelated classic dependencies, but make the diff aware of own-account fee/seq deltas that are already replayed by `preParallelApplyWrite`. The design must prove that one-time signer removal, operation-source overrides, and fee-bump source cases remain ordered exactly as today.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`LedgerManagerImpl::applyLedger` processes all fees before `applyTransactions`, then `applyParallelPhase` constructs `GlobalParallelApplyLedgerState` inside the measured `soroban_setup_glbl` window. In V26, the global state constructor calls `preParallelApplyAndCollectModifiedClassicEntries`, which compares the fee-mutated current `LedgerTxn` to the LCL snapshot before deciding whether to use the existing read-only split. For ordinary Soroban transactions, `processFeeSeqNum` has already deducted the fee from the source/fee account, so `requiresSequentialPreParallelApply` returns true at the source/fee-account check and bypasses `readOnlyPreParallelApply`. The split path already has deterministic write replay via `preParallelApplyWrite`, so a classifier that accepts only exactly-accounted fee-only source/fee deltas and rejects all other classic mutations can unlock the existing parallel read-only work without changing application order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches, calls `processFeesSeqNums`, and only then enters `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` iterates all phases in apply order and calls `tx->processFeeSeqNum`, committing fee mutations into the parent `LedgerTxn`.
- `src/transactions/TransactionFrame.cpp:1777-1816` — regular Soroban tx fee processing deducts the charged fee from the source account and does not update sequence numbers in V26.
- `src/transactions/FeeBumpTransactionFrame.cpp:765-795` — fee-bump processing deducts the outer fee from `getFeeSourceID`, which is also tested by the current sequential gate.
- `src/ledger/LedgerManagerImpl.cpp:2785-3030` — `applyTransactions` identifies the Soroban parallel phase, builds `TxBundle`s, and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2672-2709` — `soroban_setup_glbl` measures construction of `GlobalParallelApplyLedgerState`, including pre-parallel setup.
- `src/transactions/ParallelApplyUtils.cpp:170-207` — `requiresSequentialPreParallelApply` loads source, fee source, op source, and footprint classic keys from both current and previous snapshots; any difference forces serial pre-apply.
- `src/transactions/ParallelApplyUtils.cpp:432-466` — V26 setup sends txs that pass the gate to `readOnlyPreParallelApply`, then replays buffered writes with `commitBufferedPreParallelApplyWrites`.
- `src/transactions/TransactionFrame.cpp:2145-2198` and `src/transactions/TransactionFrame.cpp:2271-2349` — read-only pre-apply records `mUpdateSeqNum`, `mRemoveOneTimeSigners`, and `mUpdateSorobanMetrics`; the write phase later applies sequence and one-time-signer changes in transaction order.
- `src/herder/TxSetFrame.cpp:2606-2625` and `src/herder/TxSetUtils.cpp:394-447` — generalized tx-set validation rejects multiple transactions per source account and verifies aggregate fee affordability, reducing the correctness burden of a per-tx fee-aware gate.

### Findings

The inefficiency exists on the hot apply path. `processFeeSeqNum` mutates exactly the account keys that `requiresSequentialPreParallelApply` checks first, so current regular Soroban transactions cannot reach the read-only path unless their source/fee account entry happens to remain byte-identical after fee processing, which is not true when a positive fee is charged. This explains why `readOnlyPreParallelApply` can be nearly unused while `soroban_setup_glbl` remains a significant serial phase.

The existing split is the right target: `readOnlyPreParallelApplyRange` can run validation over the LCL snapshot across worker threads, and `commitBufferedPreParallelApplyWrites` replays `preParallelApplyWrite` serially in the same `txBundles` order. Correctness depends on the classifier being stricter than "ignore source/fee differences": it must accept only the exact fee-processing delta for the transaction's fee source/source account, must reject any operation-source or footprint classic-key mutation not explained by that fee processing, and must preserve current sequential handling for classic-phase effects, fee-bump outer fee-source cases with extra mutations, and any account state changed beyond balance/fee-only effects.

The expected impact clears the objective's review threshold. The cited setup phase is about 24 ms per ledger, and the source trace shows ordinary Soroban transactions are forced through the sequential fallback before the existing worker-parallel read-only path can do useful work. A correct fee-aware classifier will not eliminate all setup work because deterministic writes and modified-classic-entry collection remain, but moving the read-only validation/signature/resource portion off the serial path plausibly targets a Medium 3-10% apply-time reduction on the soroswap benchmark.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyUtils.cpp`, especially `requiresSequentialPreParallelApply` and `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`; pass `TxBundle` or `MutableTransactionResultBase` context if needed so the classifier can use the already-computed charged fee.
- **Change description**: replace the unconditional current-vs-LCL source/fee-account byte comparison with a fee-aware check that accepts only expected fee-processing account deltas for the tx's own fee source/source account. All op-source accounts and all classic footprint keys should still force sequential pre-apply unless their current entry is byte-identical to LCL or the delta is explicitly proven to be the same tx's own fee-processing delta.
- **Correctness check**: preserve deterministic write replay through `commitBufferedPreParallelApplyWrites`; add focused tests for regular Soroban source=fee, fee-bump outer fee source, source account touched by a classic-phase operation, operation-source override, footprint classic key touched before Soroban apply, and one-time signer removal. Do not allow a tx with an unrelated balance/signers/seq change to enter the read-only batch.
- **Benchmark focus**: run `scripts/run_apply_load_matrix.py` on the soroswap `TX=2000, T=8` case repeatedly and track top-line apply time plus `soroban_setup_glbl`, `readOnlyPreParallelApply`, and serial pre-apply/fallback counts. The expected signal is a lower `soroban_setup_glbl` critical-path time with `readOnlyPreParallelApply` carrying most txs and total apply time improving by at least 3%.
