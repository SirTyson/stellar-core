# H208: Inline TxEffects Allocation for Meta-Disabled Parallel Soroban Apply

**Date**: 2026-05-25
**Subsystem**: soroban / transactions
**Severity**: Low
**Impact**: per-Soroban-tx heap allocation and disabled-meta construction overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `DISABLE_TX_META_FOR_TESTING=true` and ledger-close metadata is not emitted,
the parallel Soroban apply path should avoid per-transaction heap allocation and
metadata object construction that cannot affect ledger results, transaction
results, or emitted metadata. `TxBundle` should be able to store its `TxEffects`
inline, or otherwise use a stage-local contiguous effects buffer, while still
providing each transaction with its independent result payload, pre-apply info,
and ledger delta.

## Mechanism

`LedgerManagerImpl::applyParallelPhase` builds a `TxBundle` for every Soroban
transaction, and `TxBundle` constructs `mEffects` with `new TxEffects(...)`.
`TxEffects` immediately constructs a `TransactionMetaBuilder`, which still
allocates operation-meta containers and builders even when meta is disabled.
Inlining `TxEffects` or allocating effects in a stage arena would remove one
heap allocation per transaction and a little pointer indirection on the apply
thread.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) with the
accepted baseline from `ai-summary/CURRENT_STATE.md`. Every parallel Soroban
transaction enters `LedgerManagerImpl::applyParallelPhase`, constructs a
`TxBundle`, allocates `TxEffects`, then later uses the effects object in
`applyThread` and `processPostTxSetApply`.

## Target Code

- `src/transactions/ParallelApplyStage.h:19-84` — `TxEffects` owns the
  `TransactionMetaBuilder`; `TxBundle` currently stores `std::unique_ptr<TxEffects>`.
- `src/ledger/LedgerManagerImpl.cpp:2982-3019` — `applyParallelPhase` constructs
  `TxBundle`s and emits fee events while building apply clusters.
- `src/transactions/TransactionMeta.cpp:924-974` — `TransactionMetaBuilder`
  constructs operation-meta containers/builders even when `mEnabled` is false.

## Evidence

The structural allocation exists: every `TxBundle` constructor calls
`new TxEffects(enableTxMeta, *tx, ledgerVersion, app)`, and `TxEffects`
constructs `TransactionMetaBuilder`. The current soroswap trace places this
path inside `applyLedger`: `applyParallelPhase` at
`ledger/LedgerManagerImpl.cpp:2973` is an apply descendant, and the benchmark
uses meta-disabled testing configuration according to the objective context and
existing fail records.

## Anti-Evidence

`csvexport-release -e` on the current soroswap trace reports only
7,445,848 ns self-time for `applyParallelPhase` across 71 apply windows.
Even impossibly deleting the entire self-time of that zone would save about
0.105 ms per ledger, roughly 0.05% of the 207.590 ms soroswap median baseline.
The actual removable `TxEffects` allocation/meta-disabled construction slice is
only a subset of that already tiny parent zone.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — adjacent fail records cover per-tx LedgerTxn/meta capture
and worker-side meta paths, but not the `TxBundle` heap allocation itself.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage). The
entire parent setup zone is about 0.05% of soroswap apply time, and the proposed
allocation/layout change can only remove a subset of it. The change may be a
reasonable cleanup, but it cannot plausibly reach the 3% Medium threshold.

### Lesson Learned

Per-transaction apply-thread setup work must first be bounded by the enclosing
setup zone. If a parent zone such as `applyParallelPhase` self-time is already
sub-0.1% of apply time, removing one allocation or pointer indirection inside it
is not a performance hypothesis for this objective.
