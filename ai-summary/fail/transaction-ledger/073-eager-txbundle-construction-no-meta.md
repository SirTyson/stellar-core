# H073: Lazy TxBundle Construction in applyParallelPhase When Meta Disabled

**Date**: 2026-05-25
**Subsystem**: transactions / ledger orchestration
**Severity**: Low
**Impact**: per-tx allocation in apply orchestration
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When meta is disabled (`DISABLE_TX_META_FOR_TESTING`), the per-tx setup in
`LedgerManagerImpl::applyParallelPhase` (`LedgerManagerImpl.cpp:2966-3032`)
should avoid eagerly allocating per-tx infrastructure whose only purpose
is to record meta — specifically:
- the `TxBundle` object that owns
  `MutableTxResultPtr` + `TxEffects` (initial entries map + restored
  entries map) + `OperationMetaBuilder` (which holds
  `OpEventManager`+`DiagnosticEventManager`+`TransactionMetaBuilder`'s
  meta variant).

Instead, the per-tx loop should construct only the minimum state needed
to drive `parallelApply` (mutable result + thin no-meta event
managers), and defer/skip allocation of the meta variant in
`TransactionMetaBuilder` and its associated
`processOpLedgerEntryChanges` infrastructure that is gated entirely
behind `if (mEnabled)` checks downstream.

## Mechanism

`applyParallelPhase` builds a `TxBundle` for every transaction up-front
in a sequential per-thread/per-cluster loop before parallel apply starts.
Each `TxBundle` allocates a `TransactionMetaBuilder` (which selects a
versioned XDR meta variant), an `OperationMetaBuilder` per operation
(with its `LedgerEntryChanges` xvector), event managers (each holding
short-lived `xvector<ContractEvent>` and diagnostic-event xvectors),
plus `TxEffects` maps (`UnorderedMap<LedgerKey, ...>`) that are
populated only for invariants/meta.

With meta disabled and `INVARIANT_CHECKS` empty (the apply-load
configuration), most of this state is allocated, written to (e.g.
`OpEventManager::mEnabled = false`, then early-outs on every
`pushContractEvent` / `setEvents` / `setLedgerChangesFromSuccessfulOp`),
and freed without ever producing meta. The deviation from "expected"
is that 2000 txs × per-tx-bundle allocations run sequentially on the
apply thread before parallelism kicks in, when much of the allocation
could be elided.

## Trigger

Run the soroswap apply-load benchmark (2000 txs/ledger, meta disabled,
`INVARIANT_CHECKS` empty) and profile the `applyParallelPhase` zone
or the parallel-apply prologue inside `applyTransactions`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2966-3032` —
  `LedgerManagerImpl::applyParallelPhase`: per-tx `TxBundle`
  construction loop.
- `src/transactions/ParallelApplyStage.h` — `TxBundle`/`TxEffects`
  definitions.
- `src/transactions/TransactionMeta.h/.cpp` —
  `TransactionMetaBuilder` / `OperationMetaBuilder` constructors;
  `mEnabled` gating.
- `src/transactions/EventManager.cpp:236-253` —
  `OpEventManager` constructor (sets `mEnabled = metaEnabled && ...`).

## Evidence

- Sequential per-tx setup in `applyParallelPhase` happens on the apply
  critical path before workers are dispatched.
- Each `TxBundle` allocation chain involves several heap allocations
  (variant for `TransactionMeta`, vectors inside each
  `OperationMetaBuilder`, two short-lived xvectors per event manager,
  unordered_map buckets for `TxEffects`).
- Multiple downstream consumers early-out when meta is disabled
  (`OperationMetaBuilder::setLedgerChangesFromSuccessfulOp` at
  `TransactionMeta.cpp:390-393`, `OpEventManager::setEvents` at
  `EventManager.cpp:506-509`, the various `pushContractEvent` /
  `pushDiagnosticEvent` no-op branches).

## Anti-Evidence

- `TxBundle` is also the carrier for `MutableTxResultPtr`,
  `restoredEntries`, post-apply result merging, and (in meta builds)
  ledger meta output. Refactoring it requires touching the
  `commitChangesFromThreads` ordering invariant (meta-pattern 23) and
  the post-apply result-merge path used in production.
- Tracy does not expose a dedicated zone for the per-tx
  `TxBundle` construction; estimated cost from raw allocation count
  is on the order of 5-15 µs per tx × 2000 txs / cluster fan-out, but
  much of the work is per-tx state that the parallel workers also need
  (mutable result, footprint book-keeping). The truly meta-only chunk
  (variant init + xvector buffers + UnorderedMap buckets) is a
  fraction of that.
- Optimistic ceiling: even if all meta-only allocation were elided,
  saved CP is bounded by a few hundred µs per ledger — below the
  1.86 ms Tracy / 6.2 ms benchmark Medium threshold. The diff would
  also have to thread through `TransactionMetaBuilder` /
  `OperationMetaBuilder` / `EventManager` constructors with a
  "no-meta lite" code path, expanding the API surface significantly
  for a sub-1% win.
- Meta-pattern 7 (LedgerManagerImpl apply-thread orchestration is
  already lean), meta-pattern 23 (cluster-order canonicalization
  blocks streaming-completion overlap), and meta-pattern 25 (per-tx
  allocations are dwarfed by host execution) all point at this being
  a low-ceiling optimization area.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Prior fail records cover
post-tx refund parallelization (071), TX envelope size caching (070),
and various host-side allocator angles, but nothing targets `TxBundle`
eager construction specifically.

### Why It Failed

The per-tx setup loop in `applyParallelPhase` is on the apply path, but
the portion of the work that is *meta-only* (and therefore safely
elidable when meta is disabled) is a few heap allocations per tx whose
aggregate cost is well below the Medium-tier 3% threshold. The
`MutableTxResultPtr` and `TxEffects` maps that drive `parallelApply` are
needed regardless of meta state, so the elidable portion is just
`TransactionMetaBuilder`'s variant init plus the
`OperationMetaBuilder`'s `LedgerEntryChanges` xvector and two short
xvectors per event manager. With ~2000 txs/ledger this is on the order
of ~200-400 µs CP — under 1% of Tracy `applyLedger`. The required diff
(carving a no-meta code path through three constructor layers) is also
high-surface-area relative to the projected win.

### Lesson Learned

In stellar-core's apply orchestration, "code that runs only to produce
meta" usually does early-out cheaply at the call site, but its
*construction* still pays allocation cost. The right way to attack this
class of overhead is **batched arena allocation** (one allocator per
cluster reused across txs), not per-tx if-meta-enabled gating, because
the gating cost itself approaches the saved allocation cost when amortized
across 2000 small allocations. Future hypotheses targeting per-tx setup
overhead should compare against an arena-allocator baseline rather than
proposing per-call-site elision.
