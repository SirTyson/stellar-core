# H026: Batch or Skip Per-Tx TxEffects/TransactionMetaBuilder Allocation in applyParallelPhase

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Per-tx serial heap allocations and constructor work for `TxBundle`/`TxEffects`/`TransactionMetaBuilder` in the apply-thread bundle-construction loop, before parallel workers start.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyParallelPhase` (`src/ledger/LedgerManagerImpl.cpp:2967-3032`)
runs serially on the apply thread before any Soroban worker is launched. For
each transaction in the txset it constructs a `TxBundle` which heap-allocates
a `TxEffects` (`unique_ptr<TxEffects>`, see
`src/transactions/ParallelApplyStage.h:83`) which in turn holds a
`TransactionMetaBuilder mMeta` and a `LedgerTxnDelta mDelta`. Even when meta
is disabled (the apply-load benchmark default with
`DISABLE_TX_META_FOR_TESTING`) the embedded builder still default-initializes
its operation-meta vector and event managers. The expected efficient path
would either (a) allocate `TxEffects` lazily on the worker thread that first
needs it, or (b) place all `TxEffects` for a stage into a single contiguous
block (vector pre-sized to `numTxs`) so the per-tx heap allocation and
allocator round-trip amortizes into one allocation rather than O(numTxs).

## Mechanism

For each soroswap tx the bundle-construction loop performs: a `unique_ptr<TxEffects>`
heap allocation, a default-init of `TransactionMetaBuilder` (which constructs
internal `std::vector<OperationMetaBuilder>` reserving op slots, plus three
event-manager objects), and a `newFeeEvent` call on `getTxEventManager()`.
The allocator round-trip and small-vector default constructions are small but
repeat once per tx serially before workers can start.

## Trigger

Run the apply-load benchmark with `--mode soroswap-tps`. With ~95 txs/ledger
the apply thread walks the bundle-construction loop sequentially before
launching parallel workers; the work shows up as the `applyParallelPhase`
self-time minus its descendant `applySorobanStages` zone.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2982-3019` — bundle-construction loop.
- `src/transactions/ParallelApplyStage.h:74-114` — `TxBundle` heap-allocates
  `TxEffects` via `unique_ptr<TxEffects>(new TxEffects(...))`.
- `src/transactions/ParallelApplyStage.h:19-69` — `TxEffects` embeds
  `TransactionMetaBuilder mMeta` and `LedgerTxnDelta mDelta`.
- `src/transactions/TransactionMeta.h:95-135` — `TransactionMetaBuilder`
  constructor.

## Evidence

- The Soroban event manager and operation-meta vector are default-constructed
  per tx even when meta is disabled — only their *content writes* are
  guarded.
- The per-tx `unique_ptr<TxEffects>` is necessary today because workers rely
  on stable references to `TxBundle::getEffects()` after `Cluster` vectors
  are moved during `applySorobanStages`. A pooled allocator could break that
  per-tx allocation.

## Anti-Evidence

- Tracy zones `applyParallelPhase` minus `applySorobanStages` is ~7 ms total
  across 71 ledgers, i.e. ~0.1 ms/ledger (≪ the 1% noise floor and far below
  the 3% Medium threshold of ~8 ms/ledger).
- The benchmark already disables most of the meta-related work via
  `DISABLE_TX_META_FOR_TESTING`; remaining cost is the allocator round-trip
  itself, not meaningful builder work.
- Placing `TxEffects` in a contiguous arena would not change the dominant
  cost on this path — the allocator is already amortized very well in
  glibc's tcache for objects of this size.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — the per-tx bundle-construction allocation pattern was not
previously isolated in fail/transaction-ledger summary. Closest neighbors are
`001-skip-transaction-meta-builder-when-disabled.md` (which targeted only the
construction of `TransactionMetaBuilder` itself, not the surrounding
`TxBundle`/`TxEffects` heap-allocation pair) and `024-async-thread-state-destruction-between-stages.md`
(targeting destruction, not construction).

### Why It Failed

Direct measurement on the accepted Tracy trace
(`9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`) shows
`applyParallelPhase` total 3,842,725,964 ns and the descendant
`applySorobanStages` total 3,835,000,197 ns. The serial bundle-construction
loop and the surrounding non-Soroban-stage work together account for at most
the ~7.7 ms difference across 71 ledgers, i.e. **~0.11 ms/ledger ≈ 0.04% of
the 272 ms apply window**. Even an idealized full removal of every
`TxEffects`/`TransactionMetaBuilder` allocation cannot exceed this ceiling.

This is below the **Low (1–3%)** band — and Low hypotheses are not accepted
at the hypothesis stage for this objective. The required Medium floor of
~8 ms/ledger is two orders of magnitude above what this code path can yield.

### Lesson Learned

`applyParallelPhase` minus `applySorobanStages` self-time is an upper bound
for *all* serial bundle/event/meta setup work that runs on the apply thread
during the parallel phase. On the soroswap shape this bound is ~0.1 ms/ledger,
so any further hypothesis targeting heap allocation or per-tx default
construction in this loop is automatically sub-Medium. Future structural
changes here only become viable if they additionally pull *worker-side*
work (e.g. metering setup, footprint preparation) into the same arena and
size the combined removable cost above ~8 ms/ledger.
