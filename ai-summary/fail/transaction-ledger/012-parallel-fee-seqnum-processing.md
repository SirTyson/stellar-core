# H012: Parallelize fee and sequence-number processing for unique-source Soroban ledgers

**Date**: 2026-04-28
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Serial pre-apply fee/sequence processing in `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a soroswap ledger where each transaction uses a unique source and fee account, fee charging and sequence-number pre-processing should not require a fully serial per-transaction read/modify/write loop. A plausible optimization would compute per-transaction fee and account deltas from a read-only snapshot in parallel, then commit those deltas and fee-pool additions in deterministic transaction order.

## Mechanism

`LedgerManagerImpl::processFeesSeqNums` iterates every transaction serially (`src/ledger/LedgerManagerImpl.cpp:2339-2402`) and calls `TransactionFrame::processFeeSeqNum`. That call loads the source account, computes the fee, subtracts it from the account balance, and adds it to the ledger header fee pool (`src/transactions/TransactionFrame.cpp:1776-1817`). The soroswap generator uses unique accounts per swap (`src/simulation/ApplyLoad.cpp:3395-3407`), so the benchmark shape appears mostly independent and tempting to shard.

## Trigger

Run the current soroswap trace and timestamp-filter `processFeesSeqNums`, `processFeeSeqNum`, `loadSourceAccount`, and `processSeqNum` against `applyLedger` windows. The longest `applyLedger` window has 4000 `processFeeSeqNum` calls, 4000 `processSeqNum` calls, and 8000 `loadSourceAccount` calls.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — `processFeesSeqNums` serial loop and deterministic result construction.
- `src/transactions/TransactionFrame.cpp:1776-1817` — `processFeeSeqNum` mutates source account balance and ledger header fee pool.
- `src/simulation/ApplyLoad.cpp:2261-2311` — model-tx benchmark times `closeLedger` around generated transactions.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generation uses a unique source account per tx.

## Evidence

The code path is in scope because `processFeesSeqNums` is called from `applyLedger`, before transaction application. The local independence property exists for the soroswap benchmark's generated source accounts, and `processFeeSeqNum` performs repeated account loads/mutations that are structurally parallelizable if deltas are committed later in a stable order.

## Anti-Evidence

Timestamp-filtered Tracy bounds the payoff too tightly. In the longest current soroswap `applyLedger` interval, `processFeesSeqNums` totals only **13.532 ms**, `processFeeSeqNum` totals **8.643 ms**, `loadSourceAccount` totals **7.021 ms**, and `processSeqNum` totals **3.140 ms**. Even deleting the entire phase would save about 2.3% of the 596 ms headline median, below the objective's 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a fee/sequence parallelization path

### Why It Failed

The optimization is real but below the objective severity floor. The current soroswap trace's longest apply window spends only 13.5 ms in the whole fee/sequence phase, and a correct implementation could not remove all of it because it still needs deterministic result construction, fee-pool accounting, replay-result handling, and ordered ledger mutation. The realistic saving is therefore Low or sub-Low, not Medium.

### Lesson Learned

Serial-looking pre-apply phases still need timestamp-filtered apply-window bounds before being promoted. For soroswap, fee/sequence processing is much smaller than parallel Soroban host execution and worker imbalance; optimizing it is not worth a standalone hypothesis under the 3% Medium threshold.
