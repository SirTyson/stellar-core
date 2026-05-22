# H005: Coalesce the three per-tx `computePreApplySorobanResourceFee` call sites into a single shared computation per Soroban tx

**Date**: 2026-05-22
**Subsystem**: soroban / apply-path fee setup
**Severity**: Low (sub-1% — not promoted)
**Impact**: Apply-time, redundant Rust-bridge crossings during serial pre-parallel-apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A Soroban transaction's pre-apply non-refundable resource fee is a pure
function of `(ledgerVersion, sorobanResources(), txSize, sorobanConfig)` —
all of which are immutable for a given `(TransactionFrame, ledger)` pair.
The expected efficient path is therefore that
`TransactionFrame::computePreApplySorobanResourceFee`
(`src/transactions/TransactionFrame.cpp:1204-1219`) is invoked **at most
once** per Soroban tx per ledger, with the resulting `FeePair` plumbed
through to all downstream consumers (fee processing, parallel
pre-apply, and any other call site that needs the non-refundable share).

## Mechanism

Today the function is called three times per Soroban tx during a single
`applyLedger`:

1. `processFeesSeqNums` path — `TransactionFrame.cpp:1936`
   (charges the non-refundable portion against the fee source).
2. Sequential `commonPreApply` — `TransactionFrame.cpp:2109`
   (only reached for classic / pre-v23 paths in soroswap; included for
   completeness).
3. Parallel `commonParallelPreApplyReadOnly` — `TransactionFrame.cpp:2174`
   (initializes the per-tx `RefundableFeeTracker`).

Each call constructs `CxxTransactionResources`, crosses the C++/Rust
bridge into `rust_bridge::compute_transaction_resource_fee`, and the
Rust side recomputes the same arithmetic against the same
`SorobanNetworkConfig`. The deviation from expected behavior is that
two of these three calls produce the same `FeePair` that the first
call already produced; the result is not memoized on the frame or on
`MutableTransactionResult`. For soroswap the relevant pair is (1) +
(3), giving 2× the necessary FFI crossings and arithmetic per tx.

## Trigger

Run the current soroswap apply-load benchmark per
`ai-summary/CURRENT_STATE.md`. Each of ~95 Soroban txs/ledger × 71
ledgers ≈ 6,776 txs goes through both `processFeesSeqNums` and
`preParallelApplyReadOnly` on the apply thread, paying two FFI
crossings + two duplicate fee computations per tx.

## Target Code

- `src/transactions/TransactionFrame.cpp:1204-1219` —
  `computePreApplySorobanResourceFee` (pure function of immutable inputs).
- `src/transactions/TransactionFrame.cpp:1934-1940` — first call inside
  `processFeesSeqNums` path.
- `src/transactions/TransactionFrame.cpp:2107-2112` — second call inside
  sequential `commonPreApply` (not on the soroswap critical path).
- `src/transactions/TransactionFrame.cpp:2170-2182` — third call inside
  `commonParallelPreApplyReadOnly`.

## Evidence

- All three call sites take identical inputs apart from the
  `LedgerSnapshot`/`LedgerTxn` source of `ledgerVersion` (which is
  invariant within a single `applyLedger`).
- The Rust function `compute_transaction_resource_fee` is a pure
  function with no internal caching, so the redundant calls do real
  duplicate work plus FFI marshalling overhead.

## Anti-Evidence

- The non-refundable fee is required at two distinct lifecycle points
  (fee debit + refund-tracker init), so a single computation must be
  stored where both stages can see it; cleanest place is
  `MutableTransactionResultBase`, which already participates in both
  phases. But this raises the next question of *where* to compute it
  first — adding a one-time entry point on the apply thread that all
  downstream paths pull from.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PARTIAL — duplicates the already-rejected
`ai-summary/fail/transaction-ledger/010-cache-pre-apply-soroban-resource-fee.md`
and `ai-summary/fail/transactions/004-cache-soroban-fee-compute-on-frame.md`,
which both bounded `computePreApplySorobanResourceFee`'s aggregate apply-window
cost.

### Why It Failed

Per the prior fails, the aggregate cost of all
`computePreApplySorobanResourceFee` calls within `applyLedger` for the
soroswap benchmark is ≈47.89 ms across 70 ledgers ≈ 0.68 ms/ledger ≈
**0.25% of the 273 ms median apply time** — already inside the 1%
benchmark-noise floor *before* any reduction. Even removing the second
and third calls entirely (the upper bound of this hypothesis) caps the
saving at ~2/3 of that envelope = ≈0.45 ms/ledger ≈ 0.17% of apply time,
**~18× below the 3% Medium floor** required by this objective. The
finer-grained "coalesce-only" framing does not change the envelope and
falls under fail Meta-Pattern 14 ("Sub-Millisecond apply-Thread Serial
Paths Are Exhausted") and Meta-Pattern 9 (pre-parallel-apply phase is
structurally thin).

### Lesson Learned

Before proposing a coalescing variant of a previously rejected caching
hypothesis, project against the *original* hypothesis's measured
envelope: if the parent's full removal is sub-Medium, any narrower
"remove only the duplicates" variant is strictly smaller and cannot
clear the threshold. For the soroswap apply window, the entire
pre-parallel-apply phase's Rust-bridge fee computation is structurally
sub-1% and is not a productive optimization target at the current
baseline.
