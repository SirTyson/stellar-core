# H009: Batch Soroban Refund LedgerTxn in processPostTxSetApply

**Date**: 2026-05-25
**Subsystem**: soroban (ledger apply / post-tx-set serial loop)
**Severity**: Low
**Impact**: Apply-time (serial post-tx-set stage)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `processPostTxSetApply`, the serial per-Soroban-tx refund loop should
amortize `LedgerTxn` open/commit overhead across all refunds in a stage rather
than paying the construction/commit cost per transaction. With ~28 Soroban
transactions per ledger in the soroswap benchmark, batching all refunds under
a single outer `LedgerTxn` (and committing once) should remove ~27 redundant
`LedgerTxn` construction/destruction cycles per ledger from the critical path.

## Mechanism

`TransactionFrame::refundSorobanFee` (`TransactionFrame.cpp:1045`) opens a
fresh `LedgerTxn ltx(ltxOuter)` per refund call, loads the fee-source account,
applies `addBalance`, and calls `ltx.commit()`. This runs serially after the
parallel apply stage completes, once per Soroban tx. Each `LedgerTxn` open
allocates two maps and a header snapshot; each commit walks `mEntry` (1
account entry) and merges it back. The per-tx LedgerTxn lifecycle is the
removable layer; the `loadAccount` work itself cannot be batched because each
refund touches a potentially different fee source.

## Trigger

Soroswap apply: ~28 Soroban refunds per ledger × 70 ledgers = 1960 refunds.
Each pays ~2 map allocs + 1 commit walk overhead in `refundSorobanFee` plus
the unavoidable `loadAccount` work.

## Target Code

- `src/transactions/TransactionFrame.cpp:1045-1083` — `refundSorobanFee`
  opens per-call `LedgerTxn`.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — `processPostTxSetApply`
  drives the serial refund loop.

## Evidence

The per-tx LedgerTxn construction/commit overhead is structurally redundant
when refunds for an entire stage could share an outer `LedgerTxn`. Code
reading confirms the per-call `LedgerTxn` is used only for one account update
and then committed immediately.

## Anti-Evidence

The dominant cost in `refundSorobanFee` is the `loadAccount` call, which must
happen per tx and benefits from success #1 (in-memory bucket scan
polymorphism) at O(1). The removable construction/commit overhead is
estimated at ~10-15µs per refund (small map alloc + 1-entry commit walk). At
28 refunds/ledger that is ~300-400µs/ledger, or ~0.15-0.2% of the ~211ms
soroswap apply median. Sub-Low and well within benchmark noise.

Additionally, `header.current().feePool -= feeRefund` mutates the header per
refund; batching under one outer LedgerTxn would still need to keep these
updates serial under that LedgerTxn's header, so the savings is purely the
per-call map alloc/dealloc/commit-walk overhead.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail #163 (per-tx LedgerTxn meta-capture),
which targeted the meta-emitting LedgerTxn layer in `applyOperations`, not
the post-set refund path.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
Projected savings ~0.15-0.2% of apply time — below the 1% benchmark-noise
floor and far below the 3% Medium threshold. The dominant cost in the refund
path is the `loadAccount` itself, which is not removable by LedgerTxn
batching.

### Lesson Learned

Per-tx LedgerTxn construction overhead in the serial post-tx-set stage is a
recurring micro-target. Per fail meta-pattern #14 (sub-millisecond
apply-thread serial paths exhausted), the total post-tx-set serial cost
ceiling is ~1.5% (fail #170). Any sub-component of that loop is necessarily
sub-Medium. Future agents should size the *whole* post-tx-set serial stage,
not individual refund-loop micro-targets, before proposing changes here.
