# H002: Hoist `loadHeader()` out of per-tx `TransactionFrame::processFeeSeqNum`

**Date**: 2026-05-24
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-path serial fee-phase micro-optimization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`processFeesSeqNums` runs serially on the apply thread for every transaction
in the ledger. For the SAC benchmark (~6000 tx/ledger) it should complete
in time proportional to the actual per-tx work (fee math + a single account
write). Loading the ledger header — which is invariant across the entire
loop — should happen at most once.

## Mechanism

`TransactionFrame::processFeeSeqNum` (TransactionFrame.cpp:1783) calls
`ltx.loadHeader()` once per transaction. The caller
`LedgerManagerImpl::processFeesSeqNums` (LedgerManagerImpl.cpp:2316) has
already loaded the header into a local `header` variable and cached
`ledgerVersion` and `isV19OrLater`. The per-tx `loadHeader()` call is
redundant: every tx in the same ledger sees the same header (modulo
`feePool` which is *written by* `processFeeSeqNum` itself). The per-tx
`loadHeader()` returns a header proxy that takes a (cheap) entry lookup
in `LedgerTxn::Impl::loadHeader` and constructs a transient
`LedgerTxnHeader` wrapper. For 6000 SAC txs that is 6000 redundant
proxy constructions per ledger.

## Trigger

Run the SAC benchmark and profile `processFeesSeqNums` — observe ~4.2 ms
total per ledger. Within `TransactionFrame::processFeeSeqNum` the
`loadHeader()` call is one of multiple operations contributing to the
~700 ns per-tx cost.

## Target Code

- `src/transactions/TransactionFrame.cpp:1777-1817` —
  `TransactionFrame::processFeeSeqNum`, line 1783 `ltx.loadHeader()` and
  line 1802 `header.current().feePool += fee`.
- `src/ledger/LedgerManagerImpl.cpp:2302-2400` —
  `LedgerManagerImpl::processFeesSeqNums`, the per-tx loop that calls
  `tx->processFeeSeqNum`.

## Evidence

- SAC processFeesSeqNums = 4.2 ms / ledger (4.3% of 97 ms apply window).
- Per-tx cost ~700 ns; `loadHeader` proxy construction is one of multiple
  contributors.
- Header is already loaded once by the outer caller.

## Anti-Evidence

- `LedgerTxnHeader` is a thin RAII wrapper around an entry lookup; the
  proxy itself is cheap.
- The `feePool` write occurs inside the inner function, so a refactor
  needs to either pass a mutable header reference or split the function
  into a setup + per-tx delta phase, which adds complexity.
- Bound: even removing 100% of the per-tx `loadHeader` cost across 6000
  SAC tx (say 50 ns each) saves ~300 µs/ledger ≈ 0.3% — well below the
  3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; F008 covered batched
source-account loads but not per-tx `loadHeader` hoisting.

### Why It Failed

Per-tx `loadHeader()` is a constant-time LedgerTxn entry lookup returning
a cheap RAII proxy. Even fully eliminated, the per-ledger savings are
sub-300 µs (~0.3% of SAC apply, ~0.15% of soroswap apply), well below
both the 3% Medium floor and the 1% noise floor. Additionally the
per-tx `feePool += fee` write into `header.current()` would have to be
restructured (either accumulate fees in a local and flush at end of
loop, or pass a header proxy reference into `processFeeSeqNum`),
introducing API churn for a sub-noise win.

### Lesson Learned

Per-tx LedgerTxn proxy constructions on the serial fee-phase loop are
cheap RAII wrappers around entry lookups; eliminating them only saves
~50 ns/tx. With SAC's 6000 tx/ledger ceiling that caps at ~300 µs/ledger,
which is below the noise floor. Future fee-phase micro-optimization
hypotheses must size proposed savings against the absolute
`processFeesSeqNums` ~4 ms ceiling, and a single-site hoist of a cheap
proxy cannot move that needle. Aggregating with other fee-phase hoists
(header proxy, base-fee map lookup, `accToMaxSeq` map ops) is also
bounded under 1% per Meta-Pattern #5 (sub-threshold narrow fixes).
