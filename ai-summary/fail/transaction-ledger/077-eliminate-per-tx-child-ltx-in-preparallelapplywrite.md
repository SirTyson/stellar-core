# H077: Eliminate per-tx child LedgerTxn in preParallelApplyWrite

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: apply-time reduction in the apply-thread serial write phase between readOnlyPreParallelApply and clusterizedSorobanApply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`commitBufferedPreParallelApplyWrites` is a sequential apply-thread loop that,
for each Soroban tx, drains pre-staged read-only validation results and then
applies the two write-side side-effects of pre-apply: (a) bumping the
fee-source account's sequence number via `processSeqNum`, and (b) removing any
PreAuthTx one-time signer via `removeOneTimeSignerFromAllSourceAccounts`. The
existing implementation (`TransactionFrame.cpp:2315 preParallelApplyWrite`)
wraps each tx's work in a fresh per-tx child `LedgerTxn ltxTx(ltx)`,
`pushTxChangesBefore`, and `ltxTx.commit()`. The expected cheaper behavior:
apply both mutations directly on the parent `ltx`, since (i) the writes
cannot fail at this point (validation already happened in the parallel
read-only phase) and (ii) there is no rollback semantic worth preserving for
the apply-thread serial path — exactly the same reasoning that justified
commit `0e93989a0` removing the per-tx child LTX from fee processing
(measured +19.2% TPS there because meta was disabled).

## Mechanism

Each Soroban tx pays for one child `LedgerTxn` construction + commit (parent
header refresh, modified-entry map move, etc.) plus an additional child LTX
inside `removeAccountSigner` (line 1874) even when the source has no
PreAuthTx signer (the dominant soroswap case). For 28 txs/ledger × 71 ledgers
that is 1988 child-LTX pairs per benchmark. Eliminating them would push the
mutations directly onto the parent `ltx`, dropping per-tx overhead from the
serial phase.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap workload (`-02-soroswap-tx-2000-t-8`).
Measure the `preParallelApplyWrite` Tracy zone before/after the patch.

## Target Code

- `src/transactions/TransactionFrame.cpp:2315 preParallelApplyWrite` — per-tx
  child LedgerTxn wrapping processSeqNum + removeOneTimeSignerFromAllSourceAccounts
  + pushTxChangesBefore.
- `src/transactions/TransactionFrame.cpp:1846 removeOneTimeSignerFromAllSourceAccounts`
  and `:1869 removeAccountSigner` — second nested child LTX per source account.
- `src/transactions/ParallelApplyUtils.cpp:465 commitBufferedPreParallelApplyWrites`
  — caller in the apply-thread serial phase.

## Evidence

- Tracy zone `preParallelApplyWrite` self-time over current soroswap trace
  (`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/...soroswap-tx-2000-t-8.tracy`):
  34.0ms total across 15738 invocations across 71 ledgers = ~0.48ms/ledger
  (~17µs/call).
- Commit `0e93989a0` ("eliminate per-tx child LTX in fee processing") proved
  the pattern: the same child-LTX-per-tx idiom in `processFeesSeqNums` was
  responsible for ~41ms/ledger (= 19.8% TPS) under no-meta runs. Direct
  parent-ltx mutation is functionally equivalent for the post-validation
  apply-thread serial path.
- For soroswap (no fee-bump, no PreAuthTx signers), `removeAccountSigner`
  is a guaranteed no-op past the empty-signer check, so even its child-LTX
  is pure overhead.

## Anti-Evidence

- The total Tracy budget of `preParallelApplyWrite` is only 0.48ms/ledger out
  of 207ms baseline ≈ **0.23%**. Even reducing it to zero would not be
  measurable above the ±1% benchmark noise floor (meta-pattern #4 / #5).
- The fee-processing precedent (`0e93989a0`) only delivered 19.2% TPS because
  the pre-existing child-LTX there was also bottlenecked by **meta**
  construction (`pushTxChangesBefore` triggers `EntryFrame::recordChange`
  copies of ledger entries into the meta vector). When meta is disabled in
  the apply-load benchmark, the meta cost is gone; the residual child-LTX
  overhead is a fraction of what it was for fee processing because there are
  far fewer mutations per call (one seq-num bump + zero signer changes).
- Per-call overhead measured here (~17µs) is consistent with raw child-LTX
  construction cost; eliminating it would save ~17µs × 1988 calls / 71
  ledgers ≈ 0.5ms/ledger ≈ 0.23% — below the 1% noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — `preParallelApplyWrite` child-LTX has not been targeted
in the existing fail summary (the analogous fee-path elimination is success,
not fail, and applies to a different call site).

### Why It Failed

Below the objective severity threshold. The targeted zone's full Tracy
budget (0.48ms/ledger) is itself sub-1% (under the noise floor), let alone
sub-Medium (3%). Per meta-pattern #5 ("individual C++ apply-path
micro-optimizations are sub-threshold") and the explicit severity scale in
the optimize-soroswap context, anything <1% is not even a Low-severity
candidate. There is no plausible path for this change to clear the Medium
floor in soroswap.

### Lesson Learned

The 19.2% TPS win from commit `0e93989a0` was driven by *meta-building*
inside the fee child LTX (pushTxChangesBefore → entry copy into meta
vector), not by the child LTX itself. When meta is disabled (as in the
apply-load benchmark) or when the per-tx work being wrapped is trivial,
removing a child LTX is a sub-1% win. Future hypotheses targeting child-LTX
removal must first quantify the *meta-building* contribution, not the LTX
construction cost.
