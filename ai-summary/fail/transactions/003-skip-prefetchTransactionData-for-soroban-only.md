# H003: Skip prefetchTransactionData for Soroban-Only V26+ Ledgers

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: sequential apply-path setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`prefetchTransactionData` (`ledger/LedgerManagerImpl.cpp:2464`) should only
incur cost proportional to the number of *new* keys it actually warms into
the `LedgerTxnRoot` cache for downstream apply. For a Soroban-only ledger
running the V26 parallel-apply path, the apply phase does not read entries
through the `LedgerTxnRoot` cache for footprint keys (those flow through
the `ApplyLedgerStateSnapshot` / `InMemorySorobanState`), and operation
source accounts are virtually always identical to the transaction source
account already prefetched/loaded by `prefetchTxSourceIds` and mutated by
`processFeesSeqNums`. The expected cost is therefore effectively zero
per ledger.

## Mechanism

Actual behavior: `prefetchTransactionData` allocates a fresh
`UnorderedSet<LedgerKey>`, iterates every phase and every transaction
calling `tx->insertKeysForTxApply(keysToPreFetch)`, then calls
`ltx.prefetch(keysToPreFetch)`. For Soroban transactions:

1. `TransactionFrame::insertKeysForTxApply`
   (`transactions/TransactionFrame.cpp:2033`) iterates operations and
   inserts `accountKey(op->getSourceID())` only when `tx.sourceID !=
   op.sourceID`. The soroswap workload uses no per-op source accounts,
   so the guard is always true and no source-account key is inserted.
2. `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch`
   (`transactions/InvokeHostFunctionOpFrame.cpp:1421`) is an empty
   body — it inserts nothing.

The function thus walks all 14,036 transactions in 71 ledgers and ends
up calling `ltx.prefetch` with an empty set. Tracy attributes
`prefetchTransactionData` self-time at 113 ms / 2.23 % of `applyLedger`.
The mechanism deviates from expected because the loop and set
construction run unconditionally even when the result is provably empty
for the current protocol+workload.

## Trigger

Run `scripts/run_apply_load_matrix.py` against a Soroban-only ledger
(soroswap or max-sac at V26+). Tracy zone
`prefetchTransactionData` (`LedgerManagerImpl.cpp:2468`) shows
total=113 ms across 71 ledgers, with the underlying
`insertLedgerKeysToPrefetch` body being empty for every operation.

## Target Code

- `ledger/LedgerManagerImpl.cpp:2464-2481` —
  `LedgerManagerImpl::prefetchTransactionData` loop body.
- `transactions/InvokeHostFunctionOpFrame.cpp:1421-1424` —
  empty `insertLedgerKeysToPrefetch`.
- `transactions/TransactionFrame.cpp:2033-2043` —
  `insertKeysForTxApply` per-tx body that adds nothing for soroswap.
- Optional: a Soroban-only short-circuit at the start of
  `prefetchTransactionData` keyed on the ledger's phases.

## Evidence

- `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` is `{}`
  (verified at `transactions/InvokeHostFunctionOpFrame.cpp:1421-1424`).
- `prefetchTransactionData` Tracy total 113 ms / 71 ledgers = 1.59 ms
  per ledger of pure overhead (set ctor, virtual calls, equality
  checks, empty `ltx.prefetch`).
- Fee-source accounts are already in `LedgerTxnRoot` cache after
  `prefetchTxSourceIds` + `processFeesSeqNums`, so even if a soroswap
  tx had a distinct op source, parallel apply would consult the
  snapshot/InMemorySorobanState, not the LedgerTxnRoot cache.
- `ExtendFootprintTTLOpFrame::insertLedgerKeysToPrefetch` and
  `RestoreFootprintOpFrame::insertLedgerKeysToPrefetch` are similarly
  empty / footprint-only, so the Soroban-phase short-circuit is safe
  across all three Soroban operation types.

## Anti-Evidence

- Some Soroban transactions in principle may set a distinct
  `op.sourceAccount`. The guard
  `!(getSourceID() == op->getSourceID())` then inserts a key. Such
  a tx would skip prefetch and rely on cold reads in
  `processFeesSeqNums` / `preParallelApply` (but the same cache layer
  is warmed via `prefetchTxSourceIds`, so this is harmless).
- `Config::allBucketsInMemory()` already short-circuits the function
  body (line 2469), so the remaining surface is only when buckets are
  on disk — the apply-load benchmark configuration.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from
`001-merge-and-shortcircuit-prefetch-passes.md` which targeted
merging fee-source and tx-apply prefetches rather than skipping
the latter as a no-op for Soroban-only ledgers.

### Why It Failed

The absolute addressable surface is 113 ms / 5,075 ms `applyLedger`
= 2.23 %, which is **Low** under the objective's severity scale and
below the 3 % Medium floor. Per the objective context, Low-tier
hypotheses (1–3 %) are not promoted to the hypothesis stage. Even
under fully optimistic projection (zeroing out the entire zone) the
saving cannot reach Medium.

### Lesson Learned

When `op->insertLedgerKeysToPrefetch` is empty for every Soroban
operation type, the `prefetchTransactionData` zone is structurally
sub-3 % of `applyLedger` for the soroswap workload — bounded by the
fixed per-tx loop overhead. Future apply-time hypotheses targeting
this code path need new evidence showing substantially higher
per-ledger overlap (e.g., a workload with non-trivial Soroban
`insertLedgerKeysToPrefetch` payloads or a protocol change that
restores a meaningful LedgerTxnRoot cache role in parallel apply).
