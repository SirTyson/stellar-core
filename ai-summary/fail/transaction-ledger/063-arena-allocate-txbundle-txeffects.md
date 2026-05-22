# H063: Arena-Allocate `TxBundle`/`TxEffects` to Eliminate Per-Tx Heap Allocations in `applyParallelPhase`

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (sub-threshold)
**Impact**: Apply-time critical-path reduction by removing per-tx
`new TxEffects` + per-tx `OperationMetaBuilder` heap allocations in the
serial bundle-construction loop of `applyParallelPhase`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The serial bundle-construction loop in `applyParallelPhase`
(`src/ledger/LedgerManagerImpl.cpp:2982-3020`) should be able to construct N
`TxBundle`s into a single contiguous arena buffer in one allocation, instead of
performing N `make_unique<TxEffects>` heap allocations (line 83 of
`ParallelApplyStage.h`) plus the nested `OperationMetaBuilder` per-tx vector
allocation inside `TransactionMetaBuilder` (line 940/951/964 of
`TransactionMeta.cpp`). A single bumping arena per ledger would reduce the
allocator round-trips and improve locality during the subsequent parallel
apply phase that reads from these structures.

## Mechanism

Per soroswap ledger, the bundle-construction loop allocates:

- 2000 × `TxEffects` (heap-allocated via `std::unique_ptr` in `TxBundle`
  constructor)
- 2000 × `OperationMetaBuilder` (vector elements; reserved up-front but each
  contains owned `EventManager`/`DiagnosticEventManager` references and a
  member `OperationMeta` XDR)
- 2000 × `OperationMeta` (resized inside `TransactionMetaBuilder` ctor)
- additional internal allocations for `Cluster`/`ApplyStage` move-into vector

A single arena per ledger would replace all of these with a few large bump
allocations. Total allocator work removed would be on the order of
2000 × 200 ns ≈ 0.4 ms per ledger.

## Trigger

Run the soroswap apply-load benchmark; the bundle-construction loop runs
once per ledger.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2982-3020` — bundle-construction loop
- `src/transactions/ParallelApplyStage.h:74-114` — `TxBundle`/`TxEffects`
  ownership model
- `src/transactions/TransactionMeta.cpp:924-974` — per-tx
  `TransactionMetaBuilder` allocations

## Evidence

- H026 directly measured the serial bundle-construction loop at ~17 ms
  / `applyParallelPhase` = 0.44%. The allocator portion of that is a strict
  subset.

## Anti-Evidence

- glibc `malloc` for small objects already uses tcache, so per-allocation
  cost is on the order of 50–200 ns; for 2000 allocations, the maximum
  saving is bounded at ~0.4 ms/ledger.
- Arena-allocation also requires careful management of `unique_ptr`'s
  custom deleter (or replacing it with raw pointers + arena lifetime),
  which adds non-trivial refactor risk for sub-millisecond benefit.
- Locality benefit during parallel apply is muted because the apply itself
  touches the C++ `OperationMetaBuilder` only via accessor calls — most
  per-tx work is inside the Rust Soroban host, which does its own
  allocations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — H143 covered inline storage for `TransactionFrame::mOperations`,
H157 covered allocator-reuse pools for `ThreadParallelApplyLedgerState`, but no
prior record investigated arena allocation for `TxBundle`/`TxEffects` and
their nested per-op meta-builder allocations together.

### Why It Failed

Even an idealized arena replacing all per-tx heap allocations in the
bundle-construction loop saves at most ~0.4 ms/ledger (≈0.17% of the
~230 ms soroswap median apply time). This is deep below both the 3% Medium
floor and the 1% noise floor. The refactor cost (custom deleters,
lifetime management of arena-backed `OperationMeta` XDR objects, custody
of `OperationMetaBuilder` references handed to parallel workers) is
disproportionate to the recoverable savings. The lesson recorded in meta-pattern
#5 ("Sub-Threshold Narrow Fixes") and applied across H121, H026, H058,
H143, H149, H157 applies again here: small-object allocator-reuse
optimizations on the apply path are individually bounded under
~1 ms/ledger by the underlying glibc tcache cost.

### Lesson Learned

Before proposing arena allocation for an apply-path data structure, size
the absolute per-allocation cost (typically 50–200 ns with glibc tcache)
against tx-count-per-ledger and compare against the 3% Medium floor
(~7 ms/ledger). For 2000-tx soroswap, any per-tx allocation-only
optimization is ceiling-bounded at ~0.4 ms/ledger and cannot reach
Medium severity on its own. Combine with a structural change (e.g.,
inlining `TxEffects` into `TxBundle` plus pre-reserved storage for
`OperationMetaBuilder` plus removing the `LedgerTxnDelta` map allocation)
only if a larger goal motivates the same refactor — never as a
performance-only change.
