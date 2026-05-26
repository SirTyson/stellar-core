# H001: Reuse TxSet Validation Results for Apply-Side Read-Only Preapply

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated transaction validation work from `soroban_setup_glbl`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a transaction set that has already passed full close-time validation against the same ledger sequence, close-time bounds, Soroban network config, and pre-fee source-account state, the apply path should not re-run all read-only validation logic solely to discover the same result. During `applyLedger`, the code should reuse a validated, ledger-header-bound preapply record for each transaction when it is still valid after fee processing, and only execute the write side that mutates fee/sequence or buffers Soroban metadata.

## Mechanism

The current in-memory apply path validates Soroban transactions once while building/checking the applicable transaction set and then runs another read-only preapply pass in `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`. In the current soroswap trace, the repeated apply-side setup work sits under `applyLedger`: the log reports `soroban_setup_glbl` at 24.11 ms median per ledger before worker invocation begins. A cache keyed by transaction hash plus the exact validation context could let the apply-side `preParallelApplyReadOnly` consume already-computed success/error, footprint/resource classification, and source-account read results from the just-accepted tx set, falling back to the existing path if any context bit differs.

## Trigger

Run the soroswap apply-load benchmark with 2000 Soroban transactions and 8 clusters. Every ledger first validates the generalized tx set, then `applyLedger` calls `GlobalParallelApplyLedgerState` for a single Soroban stage; each transaction's read-only checks are repeated before parallel host invocation even though the tx set was just accepted for the same close.

## Target Code

- `src/herder/TxSetUtils.cpp:249-285` — `TxSetUtils::getInvalidTxListWithErrors` is the cache producer during tx-set validation, not the measured optimization target.
- `src/herder/TxSetFrame.cpp:2565-2595` — `ApplicableTxSetFrame::checkValidInternalWithResult` supplies the ledger-header and close-time context that must be bound into the cache record.
- `src/transactions/ParallelApplyUtils.cpp:432-467` — `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` always invokes read-only preapply again before commit-side writes.
- `src/transactions/ParallelApplyUtils.cpp:526-594` — `GlobalParallelApplyLedgerState::readOnlyPreParallelApply` fans out `tx->preParallelApplyReadOnly` over all bundles.
- `src/transactions/TransactionFrame.cpp:2145-2198` — `TransactionFrame::commonParallelPreApplyReadOnly` repeats validation/resource checks that are candidates for a context-bound cache record.
- `src/transactions/TransactionFrame.cpp:2271-2312` — `TransactionFrame::preParallelApplyReadOnly` performs the Soroban read-only preapply path currently repeated during apply.

## Evidence

`ai-summary/CURRENT_STATE.md` identifies the current accepted soroswap median at about 207.59 ms and the diagnostic trace at `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`. In that run's phase log, `apply_transactions` is 189.79 ms median and `soroban_setup_glbl` alone is 24.11 ms median, comfortably above the 3% Medium threshold even if only a minority is removable. The relevant setup work is inside `applyLedger`, not TX-set construction: `GlobalParallelApplyLedgerState` is constructed from `applyParallelPhase`, and `readOnlyPreParallelApply` is called before `applySorobanStages`.

The code structure supports a safe cache boundary: the validation-time code already receives the next ledger sequence, close-time offsets, diagnostics, and Soroban config, while the apply-side read-only preapply is separated from `commitBufferedPreParallelApplyWrites`. A replay/fallback design can preserve determinism by accepting cached records only when the ledger hash, ledger sequence, close-time bounds, Soroban config digest, transaction hash, and fee-processing assumptions match exactly.

## Anti-Evidence

Prior failures rejected simpler "skip validation" ideas when they targeted signature validation or out-of-apply TX-set construction. This hypothesis is narrower: it only removes repeated read-only preapply work that is re-executed under `applyLedger`, and it requires exact context matching plus fallback to the current path. The main risk is that `checkValid` and `preParallelApplyReadOnly` are not semantically identical for fee-bump transactions, conditional validity, or source-account balance after fees; a viable implementation must either prove equivalence for each cached field or gate the fast path to transactions where those state transitions are already represented in the cache.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related preapply and validation-cache slices were investigated, but this exact tx-set-validation-result replay boundary was not retained as a duplicate
**Failed At**: reviewer

### Trace Summary

The tx-set validation path runs in Herder/SCP before ledger application and caches only a boolean tx-set validity result keyed by LCL hash, tx-set hash, and close-time offsets. `applyLedger` later reconstructs a fresh `ApplicableTxSetFrame`, charges fees and sequence numbers, then constructs `GlobalParallelApplyLedgerState`, whose V26 setup either runs full sequential `preParallelApply` for txs whose classic keys changed or splits `preParallelApplyReadOnly` from `preParallelApplyWrite`. The repeated read-only preapply work is real, but it is only one component of `soroban_setup_glbl`; required write-side preapply, modified-classic collection, Soroban preload, and thread-state setup remain.

### Code Paths Examined

- `src/herder/HerderSCPDriver.cpp:1393-1455` — `checkAndCacheTxSetValid` validates an `ApplicableTxSetFrame` outside `applyLedger` and stores only a boolean in `mTxSetValidCache`; no per-transaction preapply artifacts survive for apply.
- `src/herder/TxSetUtils.cpp:249-390` — validation calls `tx->checkValid(...)` against a snapshot with `ledgerSeq` set to LCL+1 and close-time offsets, collecting invalid txs and account fee totals.
- `src/herder/TxSetFrame.cpp:1227-1239, 1382-1435, 2201-2258, 2565-2645` — tx-set construction can skip transaction validation when `txsAreValidated=true`, and `prepareForApply` builds a fresh applicable frame from wire data; this existing skip is distinct from apply-side preparallel state production.
- `src/ledger/LedgerManagerImpl.cpp:1581-1688` — `applyLedger` prepares the tx set, runs `processFeesSeqNums`, then calls `applyTransactions`; it does not consume detailed Herder validation records.
- `src/ledger/LedgerManagerImpl.cpp:2672-3030` — `applyTransactions` builds `TxBundle`s and constructs `GlobalParallelApplyLedgerState` before worker execution; the whole constructor is timed as setup.
- `src/transactions/ParallelApplyUtils.cpp:386-467` — V26 setup checks whether classic entries changed, invokes sequential preapply when necessary, otherwise queues txs for read-only preapply, then commits buffered preapply writes and collects modified classic entries.
- `src/transactions/ParallelApplyUtils.cpp:135-148, 526-598` — read-only preapply is fanned out over worker threads and fills `ParallelPreApplyInfo`; write-side preapply still executes afterward on the apply thread.
- `src/transactions/TransactionFrame.cpp:1893-2022, 2145-2312, 2315-2371` — `checkValid` and `preParallelApplyReadOnly` share validation helpers, but apply-side validation runs in applying mode after fee processing and produces `ParallelPreApplyInfo` that drives sequence-number, one-time-signer, metric, and metadata-before writes.
- `src/transactions/OperationFrame.cpp:282-358` — operation validation has `forApply`-dependent account-loading behavior, so validation-time success is not a byte-for-byte replay of apply-side operation checks.
- `src/transactions/FeeBumpTransactionFrame.cpp:85-145` — fee-bump preapply splits outer fee-source signer cleanup from inner transaction read/write preapply, adding another special case a replay cache would have to encode.
- `ai-summary/fail/soroban/summary.md:129,134-136,142-143` — retained prior findings bound the broader fee/preparallel state family, apply-side footprint/commonValid caching, resource-fee coalescing, and signature-check skipping below the optimize-soroswap Medium threshold.

### Why It Failed

The hypothesis sizes the opportunity from the broad `soroban_setup_glbl` timer, but the source shows that timer includes required work that a validation-result cache cannot remove: buffered preapply writes, sequence/signature side effects, transaction metadata-before capture, modified-classic entry collection, Soroban read-only preload, and global-state preparation. The removable read-only slice is mostly repeated resource-fee computation, Soroban footprint/resource validation, signature-check bookkeeping, and trivial Soroban operation checks; prior retained failures already bound those slices and the broader fee/preparallel state family below the 3% Medium floor required by this objective.

The proposed cache boundary is also not a simple local reuse. Herder validation currently preserves only a boolean tx-set result, while apply reconstructs fresh transaction frames and must validate against post-fee state in applying mode. A correct replay design would need to carry detailed per-tx records across the Herder/apply boundary and exactly encode fee-bump handling, account-state assumptions after fee deduction, `forApply` account checks, one-time-signer cleanup decisions, frozen-key/resource context, and fallback behavior. After preserving those correctness constraints, the remaining pure-validation savings are sub-Medium, so the finding does not pass the objective's review threshold.

### Lesson Learned

Do not promote apply-side validation replay from the aggregate `soroban_setup_glbl` phase timer. First subtract the required write/preload/global-state work and compare only the replayable pure-validation fragments against the objective floor; in this codebase those fragments are already covered by retained sub-threshold preapply, resource-fee, and signature-validation findings.
