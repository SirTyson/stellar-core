# H005: Hoist `getCachedLedgerInfo` out of per-tx `getLedgerInfo()` virtual call in parallel apply

**Date**: 2026-05-02
**Subsystem**: soroban
**Severity**: Low
**Impact**: Apply-time reduction (per-tx parallel apply orchestration)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionParallelApplyHelper::getLedgerInfo()`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:1260-1267`) is the
per-tx virtual override that supplies the `CxxLedgerInfo` reference
passed across the Rust bridge in `invokeHostFunction`
(`InvokeHostFunctionOpFrame.cpp:582`). It currently delegates to
`getCachedLedgerInfo` (`InvokeHostFunctionOpFrame.cpp:75-94`), which
keys a `thread_local std::optional<CxxLedgerInfo>` on `ledgerSeq` and
rebuilds the entry on a miss. For a single ledger this should be one
allocation per worker thread amortized across all txs the worker
processes. The per-tx call should reduce to a TLS lookup + `optional`
check + an `equality` check on a `uint32_t`.

## Mechanism

Each soroban tx in `applyThread` (`LedgerManagerImpl.cpp:2484-2521`)
runs `parallelApply` → `InvokeHostFunctionOpFrame::doParallelApply` →
the helper's `invokeHostFunction`, which calls
`getLedgerInfo()` exactly once. The override goes through:

1. virtual call dispatch (vtable jump),
2. construction of args from the `ParallelLedgerInfo` member,
3. `getCachedLedgerInfo` body: TLS lookup of two `thread_local
   optional` fields, `optional` non-empty check, integer compare,
   `optional::value()` access, return by `const&`.

For 5093 invokes/benchmark this is 5093 TLS-touching hot-loop calls.
A simple optimization is to hoist the `CxxLedgerInfo const&` to the
worker thread's `applyThread` frame (or better, into the
`ThreadParallelApplyLedgerState`) and pass it directly into the helper
constructor, eliminating per-tx TLS lookups and one virtual call.

## Trigger

Run the soroswap apply-load benchmark; instrument `getLedgerInfo` to
count calls and average per-call cost.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:75-94` —
  `getCachedLedgerInfo` thread_local cache
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1260-1267` —
  per-tx `getLedgerInfo()` override
- `src/ledger/LedgerManagerImpl.cpp:2484-2521` — `applyThread` worker
  loop where the per-tx ledger info could be hoisted

## Evidence

- The thread_local cache exists, suggesting a prior author noticed
  per-tx ledger-info construction was non-trivial. Hoisting eliminates
  the residual TLS + optional + virtual call cost per tx.
- The function is called in the inner per-tx hot path of every soroban
  invoke.

## Anti-Evidence

- TLS lookup + optional check + integer compare is roughly 2-5 ns on
  modern x86 (a single cache hit + branch). For 5093 calls per
  benchmark, total work is ~25 µs worker-summed = ~8 µs wall with
  effective parallelism 3.
- 8 µs / 5092 ms = 0.0002% of apply time. Six orders of magnitude
  below the 3% Medium threshold and four orders below the 1% noise
  floor.
- The function does not appear in the csvexport top zones at any
  granularity — confirming per-call cost is in the noise.
- The diff would touch the helper constructor signature and the
  `applyThread` orchestration; the risk of regressing the existing
  cache invariant (one rebuild per ledger per worker thread) outweighs
  any measurable gain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — getCachedLedgerInfo TLS-hoist not previously investigated

### Why It Failed

The thread_local cache already collapses per-tx work to a TLS lookup
on cache hit. The residual cost is in the low nanoseconds per call, so
even eliminating it entirely produces sub-microsecond savings per
ledger — orders of magnitude below the 1% noise floor.

### Lesson Learned

When a hot-path function already has a thread-local cache with an
integer-keyed hit check, the residual cost is a TLS access plus a few
branches, which is below any meaningful severity tier. Before
targeting a per-tx accessor, measure the per-call cost (Tracy zone or
microbenchmark) — if the function does not surface as a top-N
self-time zone in csvexport at any depth, the savings ceiling is
already in noise territory.
