# H012: Fee Processing Modifications Force All Soroswap Txs Through Sequential Pre-Parallel Apply

**Date**: 2026-05-03
**Subsystem**: transactions
**Severity**: Low
**Impact**: serial setup phase before parallel Soroban apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The protocol-26 parallel pre-apply path (`readOnlyPreParallelApply` +
`commitBufferedPreParallelApplyWrites`) was added so that signature
verification, Soroban resource validation, and `op->checkValid` for each tx
can run on `LEDGER_CLOSE_WORKER_THREADS` workers in parallel against the LCL
snapshot, while only the small `preParallelApplyWrite` (seq num bump,
one-time signer removal, tx-changes-before meta) needs to run serially with
the writable `LedgerTxn`. For a tx whose source/fee/op-source accounts and
classic footprint keys are unchanged between LCL and the current `ltx`,
this fast path should fire; for soroswap (which is Soroban-only, no classic
phase), the vast majority of txs should be eligible.

## Mechanism

`processFeesSeqNums` runs before `applySorobanStages` and modifies every
fee-source account in `ltx` (deducting fees, bumping seq num for some
protocols). Then `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`
calls `requiresSequentialPreParallelApply(current, previous, tx)` which
checks whether `accountKey(tx.getFeeSourceID())` differs between `current`
(the writable ltx) and `previous` (LCL snapshot). Because fee processing
just modified that account in `current`, the check returns `true` for
every Soroban tx, and every tx is routed to the serial `preParallelApply`
path. The Tracy zone counts confirm this: `preParallelApply,TransactionFrame.cpp,2359`
and `preParallelApplyReadOnly,TransactionFrame.cpp,2277` both have count
14036 = full tx count, while the parallel pre-apply zone
(`readOnlyPreParallelApply,ParallelApplyUtils.cpp,529`) shows only 71
calls (one per ledger, with a fast empty-bundle return). The parallel
pre-apply infrastructure is effectively unused on soroswap.

## Trigger

Run `apply-load --mode soroswap-tps`. Observe in the trace that
`readOnlyPreParallelApply` self-time is 8 µs total (it returns immediately
because every tx has been routed sequential), while the per-tx
`preParallelApply` zone runs serially for all 14,036 txs.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:171-208` — `requiresSequentialPreParallelApply` treats fee-source modification as a blocker.
- `src/transactions/ParallelApplyUtils.cpp:432-467` — `preParallelApplyAndCollectModifiedClassicEntries` dispatches each tx based on the check.
- `src/transactions/ParallelApplyUtils.cpp:526-583` — `readOnlyPreParallelApply` (the parallel worker dispatcher that never fires for soroswap).
- `src/transactions/TransactionFrame.cpp:2271-2349` — `preParallelApplyReadOnly` / `preParallelApplyWrite` (the work being done serially).

## Evidence

Tracy trace `9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`:
- `preParallelApply` line 2359: count=14036, total=166ms (the wrapper that fires only on sequential path).
- `preParallelApplyReadOnly` line 2277: count=14036, total=130ms.
- `preParallelApplyWrite` line 2320: count=14036, total=35ms.
- `readOnlyPreParallelApply` line 529: count=71, total=8µs (one no-op call per ledger).
- `commitBufferedPreParallelApplyWrites` line 590: count=71, total=2µs.

This proves the parallel pre-apply codepath is dead code for soroswap, and
the entire 166ms preParallelApply phase is single-threaded.

## Anti-Evidence (and reason for self-rejection)

Total cost is **below the Medium severity floor**:
- `preParallelApply` total = 166ms / `applyLedger` Tracy total 5230ms = **3.18%**, which is right at the Medium floor.
- Even an *optimal* restructuring that ran the read-only portion (130ms)
  fully in parallel across 8 workers and kept only the write portion
  (35ms) serial would save: `130ms × (1 − 1/8) = 113.75ms` of serial work,
  which is `113.75 / 5230 = 2.18%` of `applyLedger`. Below the Medium floor
  (3%).
- This matches existing Meta-Pattern #9 ("Pre-Parallel-Apply Phase Is
  Thin"), which already concluded any restructuring of this phase is
  capped sub-Medium for the current soroswap workload.

A more radical restructuring (e.g., moving fee processing into the parallel
pre-apply path so it doesn't precondition the sequential decision) is
blocked by Meta-Pattern #3 ("Fee Pool Is a Shared Mutable Resource"): the
ledger header `feePool` is incremented per tx and must be serialized, and
the existing `processFeesSeqNums` design relies on a single serial pass
that updates both the fee source accounts and the fee pool. Splitting that
to enable parallel pre-apply would re-introduce the same shared-mutable
constraint that Meta-Pattern #3 already rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — the specific framing ("fee processing forces ALL
soroswap txs into the sequential pre-apply path, making the parallel
pre-apply infrastructure dead code for soroswap") is novel; prior
hypotheses (003-precompute-modified-classic-keys-hashset,
001-parallelize-thread-state-setup) targeted different aspects of the
same phase.

### Why It Failed

The serial `preParallelApply` phase totals 166ms (3.18% of `applyLedger`
Tracy total). Even a hypothetical perfect parallelization across 8 workers
recovers at most 2.18% — below the 3% Medium floor. The objective only
accepts Medium (3–10%) and High (>10%) hypotheses at the hypothesis stage.

### Lesson Learned

The protocol-26 `requiresSequentialPreParallelApply` parallel fast path is
effectively unreachable for any Soroban-only ledger because
`processFeesSeqNums` runs first and modifies every fee-source account.
Future hypotheses targeting parallel pre-apply must either:
1. Demonstrate a workload with a meaningfully different fee-source
   distribution (e.g., many txs sharing a single fee bump source),
2. Restructure fee processing itself (blocked by Meta-Pattern #3), or
3. Treat fee-source-only modifications as a special-case "still parallel-eligible"
   class — but the savings ceiling above shows even that is sub-Medium for
   soroswap. Document this as a known dead-code path in the parallel
   apply infrastructure.
