# H002: Hoist redundant per-op `loadAccount`/`loadSourceAccount` calls in classic apply path via cached entry handle

**Date**: 2026-05-26
**Subsystem**: ledger (classic apply path / LedgerTxn lookup)
**Severity**: Low (below objective floor)
**Impact**: per-op classic apply time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a transaction with a single source account and a sequence of operations,
the source account `LedgerEntry` should be loaded from `LedgerTxn` once per
transaction (or once per operation when mutation is needed) and the
resulting handle should be threaded through fee processing,
signature checking, and per-op `doApply` paths. The current code reloads
the same source account through `loadAccount` / `loadSourceAccount` /
`loadAccountWithoutRecord` at multiple stages, each paying a fresh
`InternalLedgerKey` hash and `UnorderedMap` lookup in the `LedgerTxn`
`EntryMap`. Even though all reloads after the first are cache hits
(no SQL/BL access), the cumulative per-call overhead (~500–700 ns of
hashing + map probing per call × ~3000 calls per ledger) is non-trivial.

## Mechanism

Apply-window overlap analysis on the diagnostic soroswap trace
(`9e61f0301cf2-…-02-soroswap-tx-2000-t-8.tracy`) shows three account-load
zones inside `applyLedger`:

- `loadAccount` — 3.23% applyLedger, 228 797 calls (~3 223/ledger), ~700 ns/call
- `loadSourceAccount` — 1.42% applyLedger, 83 890 calls (~1 182/ledger), ~750 ns/call
- `loadAccountWithoutRecord` — 1.22% applyLedger, 169 017 calls (~2 380/ledger), ~320 ns/call

Combined: 5.87% applyLedger ≈ 3.65 ms/ledger of EntryMap-lookup work, all
of it post-LedgerTxn-cache-warm (no underlying BL/SQL load — `prefetchTxSourceIds`
already preloads source accounts). With ~365 txs/ledger and an average
of ~9 account loads per tx, most of these are redundant repeated lookups
within the same tx context — different OpFrames re-load the source account
rather than reusing a handle already obtained by the parent
`TransactionFrame`. The actual deviation from expected is therefore
"unnecessary EntryMap hash+probe work", not unnecessary BL/SQL I/O.

## Trigger

Apply-load soroswap benchmark: 252 classic txs/ledger × 9 loadAccount
calls/tx + 113 Soroban txs/ledger × source/header loads = 3 223
loadAccount events per ledger. ChangeTrustOp (18 000 calls), PaymentOp
(18 000), PathPaymentStrictReceiveOp (18 000) each drive multiple
EntryMap probes for source / destination / liabilities accounting.

## Target Code

- `src/ledger/LedgerTxn.cpp` — `loadAccount` / `loadAccountWithoutRecord`
  helpers; per-call hash + `UnorderedMap` lookup in `EntryMap`
- `src/transactions/TransactionFrame.cpp:loadSourceAccount` — per-op
  reload of the source account inside `TransactionFrame::apply`
- `src/transactions/OperationFrame.cpp` — `loadSourceAccount` in
  per-op apply paths (`PaymentOp`, `ChangeTrustOp`, `PathPaymentOp` etc.)
- `src/transactions/TransactionFrame.cpp:checkOperationSignatures` —
  signature path also reloads source for each op

## Evidence

- Aggregate `loadAccount + loadSourceAccount + loadAccountWithoutRecord`
  EntryMap-lookup work inside `applyLedger` is 5.87% (~3.65 ms/ledger)
- Call count ratio (~9 loads per classic tx) implies high redundancy —
  the same source account key hashes and probes the same `EntryMap`
  bucket repeatedly within a single tx's apply window
- `prefetchTxSourceIds` already warmed source accounts in
  `LedgerTxnRoot`'s entry cache, so all reloads here are
  `EntryMap`-resident — pure hash+probe overhead

## Anti-Evidence

- LedgerTxn API contract (`load` returns a mutable handle bound to the
  current child txn) makes "thread the handle through op apply" a
  cross-cutting refactor across `TransactionFrame`, `OperationFrame`,
  and all per-op `doApply` overrides — high risk for a sub-Medium
  projected gain
- Eliminating ALL post-first reloads (best case) would recover at most
  ~2.5 ms/ledger ≈ 4% applyLedger, but realistic recovery (only the
  trivially-redundant within-op reloads, leaving per-op handle
  re-fetch in place for correctness) is ≤1.5 ms/ledger ≈ 2.4%
- The same area has been investigated under different angles:
  `fail/ledger/001-cache-hot-classic-entries-for-apply.md` (BL-load
  layer) and `fail/ledger/004-batch-classic-source-account-prefetch-into-fee-processing.md`
  (prefetch batching), both rejected sub-Medium

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — no prior hypothesis targets `EntryMap` lookup
overhead inside `loadAccount/loadSourceAccount/loadAccountWithoutRecord`
specifically; prior failures targeted the BL-load layer or prefetch
batching

### Why It Failed

The aggregate `EntryMap`-lookup overhead across the three account-load
zones is 5.87% of `applyLedger` (3.65 ms/ledger), but realistic recovery
through handle-threading is bounded at ~2.4% (~1.5 ms/ledger). The
cross-cutting refactor to thread a cached `LedgerTxnEntry` handle through
`TransactionFrame::apply`, `checkOperationSignatures`, and every
`OperationFrame::doApply` override is high-risk for a sub-Medium gain.
The cache-hit nature of the reloads is already known and accounted for
by the existing per-key cache in `LedgerTxn::EntryMap`; only the
hash+probe overhead is recoverable, which is bounded below the 3% floor.

### Lesson Learned

For classic-phase account-load optimizations, always: (1) confirm whether
reloads are cache hits (they almost always are once `prefetchTxSourceIds`
has run); (2) quantify the residual hash+probe overhead, not the wall
time of the full load primitive; and (3) note that the LedgerTxn handle
lifecycle is tightly coupled with the current child txn — refactoring to
thread handles across op boundaries is a cross-cutting change with
real correctness risk. Sub-Medium per-call wins do not justify this
risk on the optimize-soroswap arc.
