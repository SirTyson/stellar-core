# H074: Hoist per-TX `loadHeader().current().ledgerVersion` and inline fee-event emission out of TxBundle construction loop

**Date**: 2025-05-25
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Low
**Impact**: Apply-time reduction (allocation/branch removal in TX-bundle build phase)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The TxBundle-construction loop in
`LedgerManagerImpl::applyParallelPhase`
(`src/ledger/LedgerManagerImpl.cpp:2982-3020`) should call
`ltx.loadHeader().current().ledgerVersion` **once** per phase invocation
(not once per TX), because the ledger version is invariant across all TXs
in the same ledger close, and `loadHeader()` is a non-trivial LTX entry
load that follows the LTX parent chain. Similarly, the per-TX
`newFeeEvent` emission (lines 3008-3015) should be deferred to the lazy
TxBundle materialization path introduced in H073, instead of being eagerly
emitted in the construction loop where it forces an `OperationMetaBuilder`
and `TxEventManager` allocation per TX even in the no-meta benchmark mode.

## Mechanism

In `applyParallelPhase`, every TX iteration in the cluster construction
loop dereferences `ltx.loadHeader().current().ledgerVersion`. Even though
the LTX header load is cached after the first call, it still walks the
LTX parent chain via virtual dispatch and re-reads the header entry
pointer per call. With 122 Soroban TXs per soroswap ledger, this is
~122 redundant header loads (~0.1 µs each → ~12 µs total).

The eager `newFeeEvent` call on every constructed bundle (lines 3008-3015)
allocates an event record via `getEffects().getMeta().getTxEventManager()`
even in the no-meta benchmark path. Fail entry H073
(`073-eager-txbundle-construction-no-meta.md`) introduced lazy TxBundle
construction; this fee-event call is the residual eager work that may
defeat the no-meta fast path.

## Trigger

Run soroswap apply-load benchmark. The savings would manifest in
`applyParallelPhase` zone self-time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2982-3020` — `applyParallelPhase`
  TxBundle construction loop. Hoist `ledgerVersion` out before the outer
  `for (auto const& stage : txSetStages)` loop.
- `src/ledger/LedgerManagerImpl.cpp:3008-3015` — per-TX
  `newFeeEvent`. Move into lazy TxBundle materialization or skip
  entirely in no-meta mode.

## Evidence

1. `loadHeader().current().ledgerVersion` is invariant for the entire
   `applyLedger` call — there is no possible execution path that mutates
   the ledger version mid-apply (upgrades are applied AFTER all TXs).
2. The fee-event emission is unconditional even when `enableTxMeta`
   parameter is `false`, defeating the no-meta optimization H073 partly
   enabled.

## Anti-Evidence

1. The total estimated savings are ~12 µs (header hoist) plus ~50–100 µs
   (eager fee-event allocation × 122 TXs at <1 µs each) ≈ **0.05 ms per
   ledger** — well below benchmark noise (<0.05% of `total-apply`).
2. `loadHeader()` already returns a cached header reference after the
   first call within an LTX scope — repeated calls are O(1) virtual
   dispatch.
3. Fee-event allocation may be required by post-apply meta builders even
   in the no-meta benchmark mode if any consumer (invariants,
   diagnostic) reads the events.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2025-05-25
**Failed At**: hypothesis
**Novelty**: PASS — specific to the post-H073 residual eager work, not
previously investigated as a standalone hypothesis.

### Why It Failed

Both micro-hoists are **below the 1% benchmark-noise floor** (and well
below the 3% Medium-severity threshold required by the objective
SEVERITY_SCALE). The per-call cost of `loadHeader()` after the first
hit is dominated by virtual dispatch (~10 ns) and the eager
`newFeeEvent` call is a single small allocation per TX. Total upper-bound
savings ≈ 0.1 ms per ledger out of ~207 ms `total-apply` → 0.05%.

Per Meta-Pattern #5 (Sub-threshold narrow fixes), the transaction-ledger
subsystem has already absorbed many similar micro-optimizations
(xdr_size, medida, CxxBuf, recordStorageChanges, lazy TxBundle); each
one comes back at 0.2–2.5% individually and the long tail is exhausted.
Per Meta-Pattern #15 (Future hypothesis rounds should target
Soroban-host changes; pure C++ paths are sub-threshold), residual eager
work in the C++ orchestration is structurally bounded below Medium
severity.

### Lesson Learned

After the lazy-TxBundle optimization (H073) lands, **further nibbling at
the construction loop is dead capacity for this objective**. Any
remaining Medium-severity gains in `applyParallelPhase` must come from
restructuring (parallelizing setup — see H001) or from the Soroban-host
side (Meta-Pattern #15), not from incremental C++ micro-hoists in the
TxBundle build path. Stop proposing single-call hoists in this loop.
