# H018: Skip Redundant Tx-Source-Account Reload in OperationFrame::checkValid for Soroban Single-Op Txs

**Date**: 2026-05-23
**Subsystem**: transactions
**Severity**: Low (initially projected Medium)
**Impact**: pre-parallel-apply per-tx ledger snapshot work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `preParallelApplyReadOnly`
(`src/transactions/TransactionFrame.cpp:2271–2312`),
`commonParallelPreApplyReadOnly` already validates the tx source account
during `commonValid` (which calls `loadSourceAccount` and verifies its
existence, signers, sequence, and fees). The subsequent
`mOperations.front()->checkValid(..., forApply=true, ...)`
(`src/transactions/OperationFrame.cpp:282–342`) executes `ls.getAccount(...,
getSourceID())` at line 322 to reload the operation's source account from
the ledger snapshot — necessary in the classic path because earlier ops in
the same tx may have modified the tx source account. For Soroban txs
(which are guaranteed single-op by `preParallelApply`'s
`releaseAssertOrThrow(isSoroban())` and `mOperations.front()`), no earlier
op can have modified the source, so the second account load is structurally
redundant. The expected efficient behavior is for Soroban single-op txs in
the parallel pre-apply path to skip the second `ls.getAccount` lookup.

## Mechanism

`OperationFrame::checkValid` is invoked once per Soroban tx in the
sequential pre-parallel-apply phase (`preParallelApplyReadOnly`). For
soroswap's typical 200 txs/ledger × 70 ledgers ≈ 14 000 invocations, each
extra `ls.getAccount` against the parallel-apply `LedgerSnapshot` is real
work: a hash map lookup, possible bucket snapshot traversal, and a
shared-ptr handoff. If `ls.getAccount` averages ~5–10 µs in this context,
the aggregate is 70–140 ms — projected initially as Low to Medium.
Skipping it via a Soroban-specific branch (no operation source override,
no need for second load) would reduce `preParallelApplyReadOnly` self-time
proportionally on the serial apply critical path.

## Trigger

Soroswap apply-load benchmark; every Soroban tx flows through
`preParallelApplyReadOnly` → `op->checkValid(forApply=true)`.

## Target Code

- `src/transactions/OperationFrame.cpp:311–328` — `ls.getAccount` reload
  in the `forApply=true` branch
- `src/transactions/TransactionFrame.cpp:2282–2298` — call site in
  `preParallelApplyReadOnly`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1381–1410` —
  `doCheckValidForSoroban` (tiny extra work also avoided if we short-circuit
  the op-level revalidation entirely)

## Evidence

Trace zone totals from the current accepted-state soroswap diagnostic Tracy
trace (`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`):

| zone | total_ns | total_perc | counts |
|------|----------|-----------|--------|
| `applyLedger` | 4 475 605 676 | 43.51% | 71 |
| `preParallelApply` (TF.cpp:2359) | 174 891 935 | 1.70% | 16 036 |
| `preParallelApplyReadOnly` (TF.cpp:2277) | 136 540 968 | 1.33% | 16 036 |

`InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` is empty
(`src/transactions/InvokeHostFunctionOpFrame.cpp:1421–1424`), so the tx
source account is not pre-fetched into the parent ledger and `ls.getAccount`
must search through the parallel `LedgerSnapshot` parent chain on every
call.

The structural redundancy is real: `commonValid` already calls
`loadSourceAccount`, and Soroban txs are guaranteed single-op.

## Anti-Evidence

Per Meta-Pattern 9 (Pre-Parallel-Apply Phase Is Thin),
`preParallelApplyReadOnly` total is 1.33% of `applyLedger` and the
entire `preParallelApply` envelope is 1.70%. The second `ls.getAccount`
is one of several actions inside `op->checkValid` (also: `isOpSupported`,
`doCheckValidForSoroban`), so its share of the 1.33% is even smaller —
likely under 0.3% of `applyLedger`. Even with 100% elimination, the
recovered time is well below the 3% Medium floor and even below the 1%
benchmark-noise floor.

Additionally, `preParallelApplyReadOnly` runs on the serial main thread
before parallel cluster dispatch. The redundancy elimination must
preserve the `LedgerSnapshot::getAccount` semantics that `op->checkValid`
relies on for the `opNO_ACCOUNT` failure path: removing the second load
requires a Soroban-specific fast-path branch that still produces the same
failure-result semantics if the source account does not exist (which is
otherwise impossible since `commonValid` already verified it). The
correctness reasoning is sound but the saving is sub-threshold.

This investigation also overlaps with existing fails:

- `003-preparallel-validation-fast-path.md` — broader "reuse earlier
  Soroban validation" angle (Tracy trap fail).
- `015-move-preparallel-readonly-into-cluster-workers.md` — moving the
  entire RO phase into workers (Medium-floor cap).
- `012-share-signature-checker-across-checkvalid-and-preparallelapply.md`
  — sharing pre-apply state across boundaries (sub-Medium per Pattern 9).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — specific to the
`OperationFrame::checkValid(forApply=true)` redundant `ls.getAccount` call
for Soroban single-op txs; not previously isolated as its own candidate.

### Why It Failed

`preParallelApplyReadOnly` budget cap (Meta-Pattern 9) makes any single
sub-optimization inside it sub-Medium. The redundant `ls.getAccount`
fraction of that 1.33% budget is much smaller still, and full elimination
cannot clear the 3% Medium floor (nor even the 1% noise floor). Per the
objective severity scale, Low (1–3%) hypotheses are not accepted at
hypothesis stage; this candidate is well below Low.

### Lesson Learned

For the apply path, `OperationFrame::checkValid(forApply=true)` contains
redundant source-account reload work for Soroban single-op txs, but the
parent `preParallelApplyReadOnly` budget is too thin (≤1.33% of close
time per Meta-Pattern 9) to host any individual sub-fix at Medium. Future
agents proposing sub-optimizations inside `preParallelApplyReadOnly` or
`op->checkValid(forApply=true)` must first widen the addressable budget
by combining multiple sub-fixes; even then, the cap on the entire serial
pre-parallel phase makes Medium severity structurally hard to reach
without a phase-elimination redesign (which already failed at
`015-move-preparallel-readonly-into-cluster-workers.md`).

This extends Meta-Pattern 15 (Apply-Phase Per-Tx Micro-Costs Are
Exhaustively Sub-Threshold) to specifically include the
`op->checkValid(forApply=true)` redundant source-account reload as
another individually-sub-noise candidate.
