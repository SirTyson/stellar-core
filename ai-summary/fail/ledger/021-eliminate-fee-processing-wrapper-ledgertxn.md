# H021: Eliminate the outer wrapper child LedgerTxn in `processFeesSeqNums`

**Date**: 2026-05-21
**Subsystem**: ledger
**Severity**: Low
**Impact**: per-ledger child LedgerTxn allocation/commit overhead in fee processing
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`processFeesSeqNums` should charge fees and bump sequence numbers for each
transaction in the tx set with the minimum bookkeeping necessary. When
`LedgerCloseMeta` is disabled (as in the apply-load benchmark, which sets
`DISABLE_TX_META_FOR_TESTING = true`), there is no need to capture per-tx
changes for meta tracking. In that case the function should be able to apply
fee/seq updates directly to the apply-time outer `LedgerTxn` (`ltxOuter`) and
skip the cost of creating a wrapper child LedgerTxn whose only role is to
provide rollback isolation for the fee-processing loop.

## Mechanism

`LedgerManagerImpl::processFeesSeqNums` opens a child
`LedgerTxn ltx(ltxOuter)` at the top of the function (LedgerManagerImpl.cpp
line 2315), uses it for the whole fee-processing loop, and commits at the
end (line 2430). Each individual `processOneTxFee(ltx)` call writes into
this wrapper LTX, and the final `ltx.commit()` merges all accumulated
entries into the parent `ltxOuter` map. For soroswap (2000 txs/ledger,
~2000 unique source accounts touched), the per-ledger overhead is one
extra `LedgerTxn` construction, ~2000 hash-table inserts at child commit
time merging into the parent, and one destruction. This is real work but
small relative to the 272 ms soroswap apply baseline.

## Trigger

Run the apply-load soroswap benchmark with meta disabled (the default for
`scripts/run_apply_load_matrix.py`); the wrapper child LTX is allocated
once per ledger close and committed once per ledger close.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:processFeesSeqNums:2302-2440` — the
  wrapper `LedgerTxn ltx(ltxOuter)` and trailing `ltx.commit()`.
- `src/ledger/LedgerTxn.cpp:commitChild` — child-to-parent entry merge work.

## Evidence

- Tracy `processFeesSeqNums` self-time (excluding child zones) is
  16.8 ms across 71 ledgers in the latest soroswap diagnostic trace
  = ~237 µs/ledger of apply-thread serial work outside the per-tx
  `processFeeSeqNum` calls.
- Tracy `processFeeSeqNum` (per-tx) self-time is 23.1 ms / 32945 calls.
  The remaining `processFeesSeqNums` self-time is dominated by
  the wrapper child LTX construct + commit + per-tx `processOneTxFee`
  call dispatch overhead. The child commit itself merges N entries
  through `EntryIterator` into the parent map.
- Total `processFeesSeqNums` zone time per ledger: 152 ms / 71 = 2.1 ms;
  the child LTX overhead is at most a fraction of that.

## Anti-Evidence

- The wrapper LTX provides rollback safety: if any transaction's
  `processFeeSeqNum` throws, the entire fee phase is rolled back without
  corrupting the parent `ltxOuter`. Removing it requires a different
  rollback mechanism (e.g., catching exceptions and explicitly reverting).
- The merge-op tracking (`accToMaxSeq`, `MAX_SEQ_NUM_TO_APPLY` entries)
  is a function-local concern that benefits from a wrapper LTX boundary.
- The `processFeeSeqNum` per-tx implementation also opens its own child
  LTX in some paths (already investigated as fail 003), so the outer
  wrapper is not the dominant LedgerTxn cost in the trace.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — fail 003 covers per-tx (inner) LedgerTxn elimination;
this hypothesis covers the outer wrapper LedgerTxn around the whole loop.

### Why It Failed

Quantified ceiling is well below the Medium severity floor (3% of apply
time = ~8 ms on the 272 ms soroswap baseline). The outer wrapper LedgerTxn
overhead per ledger is at most ~200–300 µs (one construction, one commit
merging ~2000 entries into the parent map, plus dispatch overhead). Even
fully eliminating it would yield <0.15% apply-time reduction, an order of
magnitude below the 3% Medium threshold. The change would also require a
new exception-handling design to preserve rollback semantics, adding risk
disproportionate to the savings.

### Lesson Learned

When evaluating wrapper LedgerTxns whose only purpose is rollback
isolation, quantify the construct + commit cost separately from the
per-element work happening inside; for fee processing, the wrapper cost
is negligible relative to the per-tx `processFeeSeqNum` self time and
cannot reach Medium severity even when fully eliminated.
