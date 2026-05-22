# H056: Collapse nested `LedgerTxn` chain in `processPostTxSetApply` → `refundSorobanFee` per Soroban tx

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (below objective threshold)
**Impact**: Per-tx post-apply Soroban refund pipeline
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each successful Soroban transaction, the post-tx-set refund pipeline
should perform at most one `LedgerTxn` scope (open + commit) on the
finalized parent `LedgerTxn`. The refund is a single fee-source account
balance adjustment plus optional fee event emission — semantically a
single ledger mutation that does not require nested transactional scopes.

## Mechanism

Today, `LedgerManagerImpl::processPostTxSetApply`
(`src/ledger/LedgerManagerImpl.cpp:3094-3120`) iterates Soroban txs and
opens a child `LedgerTxn ltxInner(ltx)` per tx before calling
`tx->processPostTxSetApply(...)`. Inside
`TransactionFrame::processPostTxSetApply`
(`src/transactions/TransactionFrame.cpp:2782-...`), `refundSorobanFee`
opens *another* child `LedgerTxn ltx(ltxOuter)`
(`src/transactions/TransactionFrame.cpp:1045-1080`). That is **two nested
`LedgerTxn` objects per successful Soroban tx**, each with its own entry
buffer, dirty-tracking, and commit pass. For soroswap with ~2,000 Soroban
txs/ledger, that is ~4,000 `LedgerTxn` create/commit pairs per ledger run
serially on the apply thread.

The expected behavior — a single mutation per refund — could be implemented
by either (a) inlining refund mutation directly on `ltxOuter` and skipping
the per-tx inner scope, or (b) eliminating the outer `ltxInner(ltx)` in
`LedgerManagerImpl::processPostTxSetApply` since the inner refund already
opens its own child.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3094-3120` — `processPostTxSetApply` outer loop
- `src/transactions/TransactionFrame.cpp:2782-...` — `TransactionFrame::processPostTxSetApply`
- `src/transactions/TransactionFrame.cpp:1045-1080` — `refundSorobanFee` inner scope
- `src/transactions/MutableTransactionResult.cpp` — `RefundableFeeTracker` accounting

## Evidence

- Tracy csvexport (apply-window filter) shows `processPostTxSetApply`
  total wall time across 71 ledgers = 28ms, i.e. ~0.4ms/ledger.
- Source review confirms the double-nested `LedgerTxn` construction is
  literal and per-tx; both scopes create a fresh `EntryIterator`/dirty
  buffer and call `commit()` on close.

## Anti-Evidence

- Total `processPostTxSetApply` zone is only ~0.15% of soroswap apply
  time (0.4ms / 272ms). Even if the entire nested-LedgerTxn cost were
  eliminated, the win is below the Low threshold (1%) and far below the
  Medium objective floor (3%).
- The nesting pattern is also exercised in fee-bump-wrapped Soroban
  paths and meta builder bookkeeping; collapsing it risks regressing
  meta correctness or fee-bump refund attribution for marginal gain.
- Meta-pattern #15 (`ai-summary/fail/transaction-ledger/summary.md`):
  "Pure C++ apply-path savings are individually sub-threshold without
  host-level changes" — directly applies here.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — prior fails covered `addAnyContractsToModuleCache`
double-walk, `commitChangeFromSuccessfulTx` lookup coalescing,
`buildRoTTLSet` per-tx, but not the post-tx-set nested-`LedgerTxn`
collapse.

### Why It Failed

Total wall-clock for the entire `processPostTxSetApply` zone is ~0.15%
of soroswap apply time. Even a 100% elimination falls below the 1%
Low floor and far below the 3% Medium objective floor. Below benchmark
noise.

### Lesson Learned

Soroban refund is structurally cheap because soroban txs typically
mutate a single account-balance entry per refund and the parent
`LedgerTxn` is already open. Future investigations targeting nested-
`LedgerTxn` collapse should focus on hot paths that produce more
critical-path time (e.g., inside the parallel-apply worker commit loop,
where the nesting cost multiplies by worker count) rather than the
single-threaded post-set refund pass.
