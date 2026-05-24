# H010: Parallelize per-stage `processPostTxSetApply` refund loop

**Date**: 2026-05-24
**Subsystem**: soroban (ledger / parallel apply — post-worker-join serial refund loop)
**Severity**: Low (sub-Medium, below objective threshold)
**Impact**: per-tx serial refund processing on the post-worker-join critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After parallel Soroban workers join, each tx in a stage independently
needs its Soroban fee refund applied (`processRefund` →
`refundSorobanFee` + `newFeeEvent`) and its meta finalized
(`txMetaBuilder.finalize`). Within a single parallel stage, every tx
has a disjoint source account (parallel-stage construction enforces
RW-set disjointness; the fee source is part of the conflict set). The
refund work for tx `i` therefore writes only to source account `i`,
which no other tx in the stage touches. A correct, efficient
implementation should run the per-tx `processPostTxSetApply` work
inside a worker pool (capped at `NUM_CLUSTERS`) and then commit the
fee-source deltas back to the parent `ltx` in deterministic tx order
— eliminating the serial bottleneck while preserving observable
ordering.

## Mechanism

`processPostTxSetApply` (`src/ledger/LedgerManagerImpl.cpp:3094–3142`)
iterates `for (stage : applyStages) for (txBundle : stage)` serially,
calling `processPostTxSetApply` (refund + fee-event emission) and
`processResultAndMeta` (meta `finalize`, XDR result-pair push) on the
apply thread. For soroswap with ~197 Soroban txs/ledger across
multiple stages, this loop runs in the post-join serial window. The
deviation from expected behavior is that the loop is serial despite
intra-stage independence: each iteration's only shared write is into
the parent `ltx`, which can be batched and applied in tx-order at
the end of the stage.

## Trigger

`scripts/run_apply_load_matrix.py` on the soroswap benchmark; measure
post-worker-join serial-window time before/after parallelizing the
inner `for (txBundle : stage)` loop using a `NUM_CLUSTERS`-capped
worker pool that produces per-tx `(LedgerEntryChanges, fee event,
result pair, finalized meta)` tuples, then a serial commit pass that
folds them into `ltx`, `ledgerCloseMeta`, and `txResultSet` in
tx-index order.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3094–3142` — serial post-tx-set
  apply loop.
- `src/transactions/TransactionFrame.cpp:2782–2816` —
  `processPostTxSetApply` / `processRefund` (the per-tx unit of work).
- `src/ledger/LedgerManagerImpl.cpp:2727–2782` —
  `processResultAndMeta` (per-tx meta finalize + result-pair push).

## Evidence

- **Each tx's work is local to its source account.**
  `processPostTxSetApply` (`TransactionFrame.cpp:2782`) only calls
  `processRefund` → `refundSorobanFee` (touches source account
  balance) + `txEventManager.newFeeEvent` (writes into the per-tx
  event buffer obtained via `txBundle.getEffects().getMeta()...`,
  which is also per-tx storage).
- **Intra-stage source disjointness.** Parallel-stage construction
  guarantees disjoint RW sets within a stage, including fee sources.
  Two txs from the same source cannot coexist in one parallel stage
  by construction.
- **No cross-tx shared mutable state besides `ltx`.** The only
  shared write is into the parent `ltx` (via `LedgerTxn ltxInner(ltx);
  ... ltxInner.commit()` at `LedgerManagerImpl.cpp:3112–3122`). That
  commit can be deferred and applied serially in tx order at the
  stage end, preserving determinism.
- **Refund event ordering is per-tx, not cross-tx.** The
  `txEventManager` is per-tx (obtained from the per-tx
  `TransactionMetaBuilder`); fail
  `001-parallel-tx-meta-finalize-in-apply-thread.md` blocked
  worker-thread finalization because the refund event hadn't been
  emitted yet at worker time. By the time we reach
  `processPostTxSetApply`, the refund event IS emitted into the
  per-tx `TxEventManager`, so `finalize()` can happen here too.

## Anti-Evidence

- **Tracy structural budget is sub-Medium.** The post-worker-join
  serial window (`finalizeLedgerTxnChanges` +
  `sealLedgerTxnAndStoreInBucketsAndDB` + post-tx-set apply) totals
  ~15.7% of `applyLedger` (~34 ms/ledger), but
  `processPostTxSetApply` is only one constituent. The per-tx
  refund + finalize work is ~3–4 ms/ledger combined (~1.5% apply);
  parallelizing it across 8 workers caps the win at ~1.3 ms/ledger
  ≈ 0.6% apply — well below the Medium 3% floor.
- **Determinism risk.** Even with per-tx independence, the parent
  `ltx` commit order and `ledgerCloseMeta` insertion order must
  match the serial baseline byte-for-byte. Any non-determinism in
  worker scheduling or buffered-commit ordering breaks
  observability.
- **`processResultAndMeta` already runs inside the serial loop**
  and shares structural cost with `processPostTxSetApply`; refactoring
  one without the other yields fragmented wins.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc entry targets per-stage
parallelization of `processPostTxSetApply`; closest prior work
(`001-parallel-tx-meta-finalize-in-apply-thread.md`) targeted
*worker-thread* finalization, not post-join parallelization of the
refund loop itself.

### Why It Failed

The total Tracy budget for `processPostTxSetApply` + `processResultAndMeta`
in the soroswap trace is roughly 3–4 ms per ledger (~1.5% of the 218 ms
baseline). Even an idealized 8-way parallelization — bounded by
`NUM_CLUSTERS=8` per the objective's parallelism cap — caps the apply-time
win at well under 1% per ledger after accounting for join overhead and the
unavoidable serial commit/insertion pass that must preserve byte-identical
`LedgerCloseMeta` ordering. That is below the objective's Medium 3% floor
and below the Low 1% floor as well, i.e. effectively at benchmark noise.
The implementation complexity (per-stage worker pool, deterministic
post-join commit, careful event/meta ordering) is high relative to the
projected sub-noise win, so this is rejected at the hypothesis stage as
**below objective severity threshold (Low not accepted at hypothesis
stage)**.

### Lesson Learned

Post-join serial loops in `applyLedger` (`processPostTxSetApply`,
`processResultAndMeta`, and the post-tx-set-apply phase generally) are
structurally parallelizable but bounded by their absolute Tracy budget.
Future hypotheses targeting this window must first quantify the absolute
ms/ledger spend and gate against the Medium 3% floor *before* designing
the parallel scheme; per-stage parallelism is only worthwhile when the
serial work exceeds ~7 ms/ledger (≈3% of the 218 ms baseline).
