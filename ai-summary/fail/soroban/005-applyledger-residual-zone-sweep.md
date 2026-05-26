# H005: applyLedger Residual-Zone Sweep — Carry Source Account from processFeesSeqNums to preParallelApply

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction via avoided source-account re-load in parallel phase
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `LedgerManagerImpl::processFeesSeqNums` has fully loaded each
transaction's source account (`AccountEntry`) to charge fees and bump the
sequence number, the subsequent parallel-apply path
(`LedgerManagerImpl::applyParallelPhase` → `TransactionFrame::preParallelApply`
→ `TransactionFrame::commonValid`) should reuse that already-fetched
`LedgerEntry` snapshot for signature verification and the final
seq-num/extra-signers check rather than performing a second `loadAccount`
on the parent `LedgerTxnRoot` (which goes through `InMemorySorobanState` /
`SearchableLiveBucketListSnapshot` and a fresh active-entry insertion in
the per-thread `LedgerTxn`). The fully-loaded `AccountEntry` could be
attached to the per-tx `MutableTxResult` (or the `TxBundle` carried into
the cluster worker) so the per-worker `preParallelApply` consumes the
cached entry instead of re-reading it.

## Mechanism

`processFeesSeqNums` walks every tx in the txset, loads the source
account through the apply-thread `LedgerTxn` (which retains it in
`mActive`), charges the fee, and bumps the seq num. The Soroban parallel
phase then constructs per-cluster `ThreadParallelApplyLedgerState`
instances whose state-load path goes back to `InMemorySorobanState` for
each footprint key. The `preParallelApply` call path for each tx
re-loads the source account (a classic account key, not in
`InMemorySorobanState`), going through the parent live-snapshot. Because
the source account is already cache-hot in the apply-thread `LedgerTxn`'s
`mActive` map after `processFeesSeqNums`, the second load is "cheap" but
not free: each lookup costs an `UnorderedMap` probe in the parent chain
plus the cost of installing a new active entry in the per-thread
`LedgerTxn`.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark from
`ai-summary/CURRENT_STATE.md`. Instrument `preParallelApply` source-account
loads with a Tracy zone and measure self-time per ledger.

## Target Code

- `src/transactions/TransactionFrame.cpp:preParallelApply` — second
  source-account load
- `src/transactions/TransactionFrame.cpp:commonValid` — signature/seq num
  check that uses the loaded account
- `src/ledger/LedgerManagerImpl.cpp:processFeesSeqNums` — first
  source-account load (could attach snapshot to `MutableTxResult`)
- `src/transactions/MutableTransactionResult.h` — candidate carrier for
  cached snapshot

## Evidence

Tracy zone search across the soroswap trace shows no dedicated zone for
`preParallelApply` source-account load (it's inlined inside
`parallelApply`). The most relevant aggregate is the gap between
`applyTransactions` (3.786 s) and `applyParallelPhase` (3.020 s) plus the
classic `applyTransaction` zone (607 ms), leaving ~159 ms unaccounted for
across 71 ledgers (~2.25 ms/ledger, ~1.08 % of the 207 ms baseline). The
source-account re-load is one tributary into that 1.08 % bucket.

## Anti-Evidence

The most directly comparable prior investigation — fail #205 in
`summary.md` — already explored fusing source-account loads across
`processFeesSeqNums` and `processSeqNum` and concluded the saving was
≤0.01 % because the `mActive` map probe is essentially free. The
incremental gain from carrying that snapshot one extra hop into
`preParallelApply` is bounded by the same ceiling: the `mActive` probe is
already cache-hot, and the per-thread `LedgerTxn` would still have to
materialize an entry record for the loaded account to satisfy
`preParallelApply`'s mutation path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — extends fail #205 to a different consumer
(`preParallelApply` rather than `processSeqNum`)

### Why It Failed

The source-account load in `preParallelApply` reuses the parent
`LedgerTxn`'s `mActive` cache (populated by `processFeesSeqNums`) on the
same apply thread before the parallel split, and the per-thread snapshot
constructor for the parallel phase only forwards the dirty classic-entry
deltas — not the active-entry cache. Even if we attached the loaded
`LedgerEntry` to `MutableTxResult`, `preParallelApply` would still need
to register a per-thread active entry to drive its mutation API, and the
saving collapses to the same ≤0.01 % already measured in fail #205. The
projected impact is well below the Low threshold (1–3 %) and far below
the objective's Medium floor (3 %).

### Lesson Learned

Per Meta-Pattern #14, sub-millisecond apply-thread serial work that
duplicates an already-cache-hot map probe cannot reach Medium even when
fully eliminated. Future investigations of the `applyTransactions` -
`applyParallelPhase` residual gap (~2.25 ms/ledger, 1.08 % of baseline)
should be skipped unless they identify a single redesign capturing
>50 % of that bucket — individual tributaries are below noise.
