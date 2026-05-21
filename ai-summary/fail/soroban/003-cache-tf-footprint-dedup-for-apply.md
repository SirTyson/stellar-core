# H003: Cache TransactionFrame footprint-dedup result for apply-side reuse

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Low
**Impact**: redundant per-tx work during apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`commonValidPreSeqNum` checks Soroban transaction footprint for duplicate
LedgerKeys by building an `UnorderedSet<LedgerKey>` from `readOnly + readWrite`
(`TransactionFrame.cpp:1461-1489`). For a given `TransactionFrame` instance,
this dedup result is invariant — the footprint never changes after
construction. The check SHOULD be done at most once per TF instance, with the
result memoized on the frame.

## Mechanism

The dedup constructs a fresh `UnorderedSet`, hashes every footprint key with
SHA256-backed `LedgerKey` hashing, and inserts/checks for duplicates. The
ACTUAL behavior re-runs this work on every call to `commonValidPreSeqNum`.
The set construction is non-trivial: a soroswap tx with ~5-10 footprint keys
costs a few hundred ns–µs per call. If apply called `commonValidPreSeqNum`
multiple times per TF, memoization would compound — but inspection of the
parallel apply path shows it does not (see Anti-Evidence).

## Trigger

Soroswap benchmark (`scripts/run_apply_load_matrix.py soroswap`), measure
the cumulative time spent in the dedup block of `commonValidPreSeqNum`
during the apply window only (`preParallelApplyReadOnly` callers).

## Target Code

- `src/transactions/TransactionFrame.cpp:1461-1489` — UnorderedSet dedup loop
- `src/transactions/TransactionFrame.cpp:2277` — `preParallelApplyReadOnly`
  apply-side caller
- `src/transactions/TransactionFrame.cpp:2392` — `parallelApply` op-frame
  entry (verified does NOT re-call `commonValidPreSeqNum`)

## Evidence

Tracy self time for `commonValidPreSeqNum`: 5.49s / 145782 calls. Apply-side
calls are 14036 (`preParallelApplyReadOnly` invocations). The dedup block is
a meaningful constant slice of each call.

## Anti-Evidence

The `parallelApply` worker path (`TransactionFrame.cpp:2392` → `OperationFrame::parallelApply` → `InvokeHostFunctionOpFrame::doParallelApply`) does NOT
re-call `commonValidPreSeqNum`. Apply-side calls are exactly 1 per TF
(in `preParallelApplyReadOnly`). With no second call to short-circuit, the
cache would never pay back. Additionally, the most recent admission-time call
(at `tryAdd`/herder validation) is on a *different* TF instance and cannot
share state (fail #003 / meta-pattern noted: admission and apply have
distinct TF instances under the current architecture).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior fails which all targeted the
admission-to-apply caching boundary; this targets *within-apply* reuse and
shows it is structurally absent.

### Why It Failed

Apply-side calls `commonValidPreSeqNum` exactly once per TF (in
`preParallelApplyReadOnly`). The parallel worker `parallelApply` path does
not re-enter `commonValid*`. With one call per TF in the apply window,
memoization has nothing to memoize against. Even an optimistic full-skip
on a hypothetical second call would save ≤1.3% (the apply-side share of
`commonValidPreSeqNum` total Tracy self time), and the actual saving is
zero.

### Lesson Learned

Before proposing a per-instance cache, count the actual repeat-call rate
on the target path. For Soroban TFs in parallel apply, `commonValidPreSeqNum`
runs exactly once; the call multiplicity that makes caching pay back lives
on the admission side (out of scope) and cannot reach apply because
admission and apply use distinct TF instances.
