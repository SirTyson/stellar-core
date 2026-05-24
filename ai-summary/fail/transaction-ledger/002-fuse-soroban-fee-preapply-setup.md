# H002: Fuse Soroban Fee, Sequence, and Pre-Parallel Setup Passes

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / ledger parallel apply
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing a serial C++ setup boundary before parallel Soroban workers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For Soroban-only apply-load ledgers, the apply thread must charge fees, update source sequence numbers, run read-only transaction validation, remove one-time signers when required, collect modified classic entries, build transaction bundles, and then launch parallel workers. The correct result is the same ordered `TransactionResultSet`, same fee events/meta, same source-account state, and same global parallel-apply entry map. The efficient path should not walk the same Soroban transaction set through separate serial phases that each construct snapshots, load source accounts, open child `LedgerTxn`s, and re-check per-transaction setup invariants when the phases are strictly ordered and all operate on the same apply-thread state.

## Mechanism

`LedgerManagerImpl::processFeesSeqNums` first walks all transactions and charges fees / advances sequence numbers. Later `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` walks the same `TxBundle`s, builds current/previous `LedgerSnapshot`s, decides whether to run `preParallelApply` sequentially or buffer read-only work, then performs the write phase and modified-classic collection. On the soroswap shape, both phases are serial apply-thread setup that must complete before any worker starts; any duplicate source-account loads, snapshot wrappers, child `LedgerTxn` construction, metadata pushes, and footprint classification sit directly on the `closeLedger` critical path.

A Soroban-only fused setup pass would be introduced between `processFeesSeqNums` and `applySorobanStages`: while charging fees and producing `MutableTransactionResult`s, it would also compute the `ParallelPreApplyInfo` read-only validation result, perform the required sequence/signer writes in the same child transaction, and accumulate the classic keys that must seed `GlobalParallelApplyLedgerState`. This is not parallelizing or reordering transactions; it preserves canonical transaction order and only collapses two mandatory serial passes into one stateful apply-thread pass.

## Trigger

Run `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` with protocol 26+ parallel Soroban apply enabled. Instrument per-ledger counts and timings for `processFeesSeqNums`, `preParallelApply`, `preParallelApplyReadOnly`, `preParallelApplyWrite`, and `collectModifiedClassicEntries`. The trigger is a Soroban-only phase where every transaction is already processed by `processFeesSeqNums` before the parallel-apply setup pass revisits it.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2302-2360` — `processFeesSeqNums` starts the first serial pass over all transactions and opens a child `LedgerTxn` for fee/sequence processing.
- `src/ledger/LedgerManagerImpl.cpp:2966-3031` — `applyParallelPhase` builds `TxBundle`s only after fee processing has already produced mutable results.
- `src/transactions/ParallelApplyUtils.cpp:433-467` — `preParallelApplyAndCollectModifiedClassicEntries` performs a second serial pass over the same Soroban bundles before worker launch.
- `src/transactions/TransactionFrame.cpp:2260-2371` — `preParallelApplyReadOnly`, `preParallelApplyWrite`, and `preParallelApply` split validation and write-side sequence/signer effects that could be driven by a fused setup state machine.
- `src/transactions/ParallelApplyUtils.cpp:526-590` — existing read-only fanout and buffered write commit paths whose outputs define the equivalence target for any fused pass.

## Evidence

- Cached apply-window Tracy event containment shows the setup/validation regions are descendants of `applyLedger`, not TX-set construction: `checkSignature@TransactionFrame.cpp:504` and `checkSignature@OperationFrame.cpp:221` together account for **122.9ms** inside the sampled `applyLedger` windows; `commonValidPreSeqNum@TransactionFrame.cpp:1327` accounts for **53.3ms**; and selected `preParallelApply` events in `/tmp/soroswap-current-events-selected.csv` occur within the same apply windows before worker execution.
- The fail corpus establishes that individual fee-phase, pre-apply, source-account carry, and classifier fixes are sub-threshold in isolation. This hypothesis is narrower than a generic bundled C++ micro-optimization but broader than those single-site failures: it targets the serial phase boundary itself and the duplicated transaction-set walk / `LedgerTxn` / snapshot state machine around fee+preapply.
- The source already maintains deterministic order in both phases and stores per-tx mutable results by index. A fused pass can preserve that order and still cap worker parallelism at the configured cluster count because it runs before `applySorobanStageClustersInParallel`.

## Anti-Evidence

- The improvement is bounded by the serial setup envelope before worker launch. Review should measure direct wall time for `processFeesSeqNums + preParallelApplyAndCollectModifiedClassicEntries` on the current baseline; if the combined envelope is below about 6.3ms/ledger (3% of the current 211ms soroswap median), this drops below the objective threshold.
- The pass boundary is correctness-sensitive: fee charging must happen for invalid transactions exactly as today, replay-expected results must remain indexed correctly, one-time signer removal and sequence-number updates must preserve protocol-version behavior, and fee events currently emitted during bundle construction must keep the same metadata ordering.
- If `requiresSequentialPreParallelApply` continues to force all transactions down the sequential pre-apply path for legitimate cross-tx classic-key hazards, the fused pass still removes only overhead around validation/write plumbing, not the validation itself.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related fee/pre-apply setup failures exist, but this exact fusion record was not found in fail/success
**Failed At**: reviewer

### Trace Summary

`applyLedger` calls `processFeesSeqNums` before `applyTransactions`, and `applyParallelPhase` later builds `TxBundle`s and constructs `GlobalParallelApplyLedgerState`, which runs `preParallelApplyAndCollectModifiedClassicEntries` before worker launch. On protocol 26 Soroban transactions, `TransactionFrame::processFeeSeqNum` only charges fees; sequence-number updates and one-time signer removals are driven by `preParallelApplyReadOnly`/`preParallelApplyWrite`. The proposed fusion therefore targets a real serial boundary, but the current source and prior measurements bound the entire removable envelope below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — `processFeesSeqNums` runs first and `applyTransactions` runs afterward, so any fusion would have to restructure this apply-thread boundary.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — fee processing walks the tx set and creates mutable results; on the no-meta benchmark path it operates directly on the parent `LedgerTxn`, so the claimed per-tx child `LedgerTxn` cost is not present there.
- `src/transactions/TransactionFrame.cpp:1777-1817` — regular transaction fee processing deducts the fee and only updates `seqNum` before protocol 10; protocol 26 Soroban sequence updates do not happen in `processFeeSeqNum`.
- `src/ledger/LedgerManagerImpl.cpp:2966-3029` — `applyParallelPhase` constructs `TxBundle`s after mutable results exist, emits the fee event through each bundle's meta builder, then calls `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:171-208` — `requiresSequentialPreParallelApply` checks whether fee/source/op-source or footprint classic keys differ between current and previous snapshots.
- `src/transactions/ParallelApplyUtils.cpp:433-467` — protocol 26 setup either runs full `preParallelApply` sequentially for hazard-bearing transactions or buffers read-only results before a serial write commit and modified-classic collection.
- `src/transactions/TransactionFrame.cpp:2145-2198` — read-only pre-apply computes Soroban resource fees, initializes refundable fee tracking, runs `commonValid`, and records whether sequence/signer writes are needed.
- `src/transactions/TransactionFrame.cpp:2315-2371` — write-side pre-apply opens a child `LedgerTxn`, conditionally updates sequence numbers, removes one-time signers, pushes pre-apply meta changes, commits, and updates Soroban metrics.
- `ai-summary/fail/transaction-ledger/summary.md` — prior records bound combined sync setup around `prefetchTransactionData`, `processFeesSeqNums`, and `preParallelApply` under 2% of apply time; `processFeesSeqNums` alone is under 5 ms/ledger and pre-parallel apply is about 2.34 ms/ledger / 0.86%.

### Why It Failed

The optimization cannot clear this objective's Medium floor. The fail corpus already measured the relevant serial setup family: combined sync setup is under 2% of apply time, `processFeesSeqNums` is sub-1% to ~1.75% depending on the run, and the serial pre-parallel-apply zone is about 0.86%. Even full elimination of both zones would be below the 3% threshold, and a correct fusion cannot eliminate most of the work because fee deduction, `commonValid`, signature checks, sequence updates, one-time signer removal, fee/refund initialization, and meta ordering still have to occur.

The mechanism also overstates the duplicated work in the current source. For protocol 26 Soroban transactions, `processFeeSeqNum` does not advance sequence numbers, and when metadata is disabled it does not open a child `LedgerTxn` per transaction. The remaining source-account reload/snapshot/setup overhead is the same class of sub-threshold work already captured by the prior `share-fee-loaded-account-with-preparallelapply`, `share-ledgersnapshot-across-pre-parallel-apply-txs`, and fee-phase records.

### Lesson Learned

Before promoting serial setup fusion hypotheses, size the absolute enclosing zones first. In this code path the correctness-required validation/signature/write work dominates the small duplicated plumbing, and the whole fee/pre-apply setup envelope is below the optimize-soroswap review threshold.
