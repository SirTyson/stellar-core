# H028: Overlap Sequential Classic-Phase Apply With Parallel Soroban-Phase Apply

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / phase orchestration in `applyTransactions`
**Severity**: Low
**Impact**: Apply-thread serialization between txset phases when a ledger contains both classic and Soroban transactions
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyTransactions`
(`src/ledger/LedgerManagerImpl.cpp:2785`) iterates txset phases and dispatches
each phase to either `applySequentialPhase` (classic) or `applyParallelPhase`
(Soroban). For a ledger with both phases, the classic phase runs to completion
on the apply thread before the Soroban phase begins. The expected efficient
behavior is that, when phase footprints are *demonstrably disjoint* — i.e., no
classic-phase tx writes a `LedgerKey` that any Soroban-phase tx footprint
references in either readOnly or readWrite — the apply thread could dispatch
the Soroban parallel phase concurrently with the classic phase apply loop, so
the apply-thread serial classic work overlaps with worker-thread Soroban work.

## Mechanism

In the soroswap apply-load shape, classic operations (`ChangeTrustOp`,
`PaymentOp`, `PathPaymentStrictReceiveOp`) run in the sequential phase before
Soroban transactions. From the diagnostic Tracy trace, classic op apply
zones — `ChangeTrustOp apply` (94.6 ms / 18000 calls), `PaymentOp apply`
(71 ms / 18000), `PathPaymentStrictReceiveOp apply` (66 ms / 18000) — total
**~232 ms aggregate** across the 71-ledger benchmark, or **~3.3 ms/ledger
serial**. If the Soroban parallel phase could begin while the classic phase is
still applying, this serial work overlaps with the (much larger) parallel
Soroban execution window, recovering the entire classic-phase wall time as
overlap.

## Trigger

Run the soroswap apply-load benchmark (`apply-load --mode soroswap-tps`).
Classic txs (~170/ledger) apply sequentially before the Soroban txs
(~95/ledger) launch into parallel cluster execution.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2870–2920` — phase loop in
  `applyTransactions` that calls `applyParallelPhase` and `applySequentialPhase`
  inline.
- `src/ledger/LedgerManagerImpl.cpp:2966–3032` — `applyParallelPhase`
  constructs `applyStages` and immediately calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:3034–3091` — `applySequentialPhase` runs
  classic ops on the apply thread.

## Evidence

- Classic-op apply Tracy zones in the soroswap trace total ~232 ms across 71
  ledgers, of which the sequential phase wait is on the apply critical path.
- Soroswap classic phase appears to run on disjoint state: classic ops touch
  trustlines and accounts; Soroban txs read SAC balances and contract data.
  The apparent disjointness suggests a parallelization opportunity.
- The Soroban parallel phase already uses `std::async` workers, so adding
  the apply thread itself as a "phase 0 worker" appears mechanically simple.

## Anti-Evidence

- **Footprints overlap in practice**: Soroswap soroban txs include classic
  trustline keys in their readWrite footprints (the SAC transfer path mutates
  user trustline balances on lumen and asset transfers). The apparent
  disjointness is illusory; classic-phase trustline mutations of source
  accounts (paying fees, doing PathPaymentStrictReceive) collide with the same
  trustline keys that Soroban txs include in readWrite footprints.
- **`processFeesSeqNums` already mutated source account state** for *all*
  txs (classic and Soroban) before the phase loop begins, so the snapshot
  the Soroban readonly preParallelApply pass takes (`mLCLSnapshot`,
  established in `GlobalParallelApplyLedgerState::ctor`) deliberately predates
  classic-phase mutations. This is required for correctness because Soroban
  parallel apply uses snapshots of pre-classic-apply state plus a tracked
  modified-classic-key set (see
  `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`
  at `src/transactions/ParallelApplyUtils.cpp:432–468`, which after V_26
  walks every footprint key and calls `requiresSequentialPreParallelApply`
  to detect classic-phase modifications).
- **CAP-0063 explicit ordering**: the protocol design explicitly orders
  classic-phase first, Soroban second, so that Soroban readonly snapshots can
  see all classic-phase mutations. Overlapping the phases would require
  changing the snapshot model and, fundamentally, the protocol-visible
  apply order. This is consensus-breaking.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — phase-overlap is a structurally distinct angle from the
prior `H012-parallel-fee-seqnum-processing.md` (parallelism within
`processFeesSeqNums`), `H003-async-prefetch-overlap-fee-processing.md`
(prefetch pipelining), and `H024-async-thread-state-destruction-between-stages.md`
(post-stage destruction). No prior fail entry covered overlapping the
*classic and Soroban phases of the same ledger*.

### Why It Failed

The optimization is consensus-breaking. The protocol's two-phase ordering
(classic, then Soroban) is a deliberate CAP-0063 design choice: Soroban
parallel apply must see a snapshot of state *after* all classic-phase
mutations, because Soroban readWrite footprints frequently include classic
trustline keys (every SAC transfer that moves XLM or a credit through a
classic trustline declares the trustline in its footprint). Overlapping the
two phases would require:

1. Snapshotting pre-classic-phase state for Soroban reads (changing the
   semantics of `LedgerSnapshot` taken in
   `GlobalParallelApplyLedgerState::ctor`), or
2. Detecting and rolling back overlap conflicts at runtime (a transactional
   memory model that does not currently exist).

Both options change observable apply behavior across nodes — exactly the
"determinism breaks" out-of-scope failure mode listed in the objective. Even
under the optimistic case of fully disjoint footprints, the serial classic
phase only contributes ~3.3 ms/ledger (~1.2% of the 272 ms soroswap median),
which is below the Medium 3% floor even before accounting for the
synchronization cost a hybrid-phase scheduler would impose.

### Lesson Learned

Phase ordering between classic and Soroban transactions is consensus-visible.
Any optimization that proposes to overlap or reorder phases must establish
that the cross-phase data dependencies are empty for *all* possible
soroswap-shape txs, not just the dominant pattern. For SAC-heavy workloads
this is structurally false: SAC transfers always declare classic trustline
keys in their footprints, so classic-phase trustline mutations are always
within the Soroban readonly snapshot dependency cone. Future
"phase-pipelining" hypotheses must either propose a CAP-grade protocol
change or target overlap windows that are entirely within one phase
(e.g., serial-glue between Soroban stages, which has already been
investigated and rejected).
