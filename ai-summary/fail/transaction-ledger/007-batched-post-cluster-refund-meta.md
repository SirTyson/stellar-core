# H007: Batched / vectorized refundable-fee meta finalization in checkAllTxBundleInvariants post-cluster loop

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Low (sub-Medium)
**Impact**: Apply-thread serial overhead per ledger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After each parallel Soroban stage finishes, `applySorobanStage` is required to
call `checkAllTxBundleInvariants` on the apply thread to (a) optionally
invoke registered invariants and (b) propagate refundable-fee tracker values
into each transaction's `TransactionMetaBuilder` via `maybeSetRefundableFeeMeta`.
On the soroswap apply-load configuration, `INVARIANT_CHECKS` is empty, so the
loop should reduce to a tight per-tx propagation of two `int64_t` values
(`rentFeeCharged`, `totalRefundableResourceFeeCharged`) into the per-tx XDR
metadata structure. The work should be bounded by a few hundred nanoseconds
per transaction.

## Mechanism

`LedgerManagerImpl::checkAllTxBundleInvariants`
(`src/ledger/LedgerManagerImpl.cpp:2577-2620`) runs serially on the apply
thread after every cluster completes its parallel work. The hypothesis was
that this serial post-cluster loop, plus the chain of virtual / templated
accessor calls behind `txBundle.getEffects().getMeta().maybeSetRefundableFeeMeta(...)`
(getter virtual on TxBundle, getter on Effects, getter on TransactionMetaBuilder,
then check of three booleans before mutating the XDR union), could be
contributing meaningfully to the per-ledger sequential apply tail and might
benefit from being either skipped when meta is disabled, vectorized
(`std::for_each` with std::execution::par), or inlined into the parallel
worker so the apply-thread sees zero serial overhead.

## Trigger

Run `scripts/run_apply_load_matrix.py` for the soroswap benchmark and measure
apply time before/after collapsing the post-cluster `maybeSetRefundableFeeMeta`
loop into the parallel cluster workers (so the apply thread does no
per-tx post-cluster work when invariants are disabled).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2577-2620` (`checkAllTxBundleInvariants`)
- `src/ledger/LedgerManagerImpl.cpp:2617-2618` — unconditional
  `txBundle.getEffects().getMeta().maybeSetRefundableFeeMeta(...)` per tx
- `src/transactions/TransactionMeta.cpp:1014-1027`
  (`TransactionMetaBuilder::maybeSetRefundableFeeMeta`)

## Evidence

- The loop is serial on the apply thread, fires once per stage
  (~71 stage invocations across the trace), iterates every bundle in the
  stage, and runs even when invariants are disabled.
- `maybeSetRefundableFeeMeta` mutates a `TransactionMeta` XDR union
  (`metaExt.v(1)`), which can trigger union-variant construction and may
  allocate.
- Conceptually, this work is per-tx data already known by the parallel
  worker that produced the tx's RefundableFeeTracker, so it could in
  principle be folded into the parallel section.

## Anti-Evidence

- Direct Tracy measurement: `csvexport-release` on
  `62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy` shows no
  separately instrumented zone for `checkAllTxBundleInvariants`; the
  enclosing `applySorobanStage` zone aggregates 32M ns / 71 invocations
  ≈ 450 µs per stage including all clusters + this loop.
- `maybeSetRefundableFeeMeta` has an early-out at the top of the function
  (`if (mEnabled && refundableFeeTracker && mSorobanMetaExtEnabled)`). On
  the soroswap benchmark `mEnabled` is `false` (meta disabled), so the
  body never executes: the per-call cost reduces to one virtual dispatch
  plus three boolean loads.
- Bounded estimate at 2000 tx/ledger × 100 ns/call ≈ 200 µs/ledger
  sequential. Against a ~218 ms median apply time that's ~0.09% — far
  below the 1% benchmark-noise floor and well below the Low (1-3%)
  threshold.
- Even an optimistic "save everything" scenario (skip the loop entirely
  when both invariants and meta are disabled) cannot exceed the ~200 µs
  bound, since the loop body is already a no-op chain of disabled checks.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in fail/hypothesis/reviewed/poc

### Why It Failed

When meta is disabled (the soroswap apply-load configuration), the
`maybeSetRefundableFeeMeta` body is a no-op behind an early-out boolean
check, and `INVARIANT_CHECKS` is empty so the invariant branch is also
skipped. The remaining cost is a handful of inlined-or-virtual accessor
calls per tx, bounded above by ~200 µs / ledger sequential against a
~218 ms apply-time baseline — under 0.1%, well below the 1% noise floor
and the 3% Medium severity threshold. Even a perfect-elimination patch
cannot move the apply-time needle.

### Lesson Learned

Post-cluster serial loops on the apply thread are tempting optimization
targets, but their cost must be sized against the existing early-out
fast paths. When the loop body short-circuits on the benchmark's
configuration (meta disabled, invariants empty), the residual virtual
dispatch / boolean checks are sub-µs per tx and the whole loop is
sub-millisecond per ledger. This adds to Meta-Pattern #6's parallel-
apply normalization advice a complementary rule: **post-cluster serial
loops also need to be sized against the early-out cost on the actual
benchmark config, not the worst-case body cost.**
