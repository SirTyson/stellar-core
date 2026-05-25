# H003: Share `ApplyLedgerStateSnapshot` across thread states instead of per-cluster copy

**Date**: 2026-05-25
**Subsystem**: ledger / parallel apply state setup
**Severity**: Low
**Impact**: Avoid per-cluster `ApplyLedgerStateSnapshot` copy in `ThreadParallelApplyLedgerState` ctor
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ThreadParallelApplyLedgerState`'s ctor at
`src/transactions/ParallelApplyUtils.cpp:988` initializes
`mLCLSnapshot(global.mLCLSnapshot)` — copying the `ApplyLedgerStateSnapshot`
from the global state into each of the 8 thread states. The header comment
on the field (`ParallelApplyUtils.h:74-76`) notes "Copy of the LCL state
snapshot from the global state, with fresh file caches for thread safety."
Expected correct behavior is that each worker thread has its own
independently-usable bucket-list snapshot.

If the copied state is heavyweight (e.g., per-thread file-cache
materialization, copies of bucket index structures, large allocator
churn), eliminating the per-cluster copy by holding a single shared
snapshot (with internal thread-local file caches lazily allocated per
access thread) would reduce apply-thread serial setup time in
`applySorobanStageClustersInParallel`.

## Mechanism

Per-cluster snapshot copy runs serially on the apply thread between
clusters, contributing to the `applySorobanStageClustersInParallel`
self-time wrapper of ~38 ms/ledger.

## Trigger

Any apply-load run that exercises the parallel Soroban phase with
multiple clusters.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` ctor copy site.
- `src/transactions/ParallelApplyUtils.h:74-76` — field declaration.
- `src/ledger/LedgerStateSnapshot.cpp:525-529` — `ApplyLedgerStateSnapshot` ctor.

## Evidence

The comment in `ParallelApplyUtils.h:75-76` explicitly mentions "fresh
file caches for thread safety," suggesting non-trivial per-thread state.

## Anti-Evidence

The `ApplyLedgerStateSnapshot` ctor at
`src/ledger/LedgerStateSnapshot.cpp:525-529` is a thin pass-through that
just forwards `state` (a `CompleteConstLedgerStatePtr`, a shared_ptr
to immutable global state) to the `LedgerStateSnapshot` base. The "fresh
file caches" comment refers to internal members of `LedgerStateSnapshot`
that are constructed once per `ApplyLedgerStateSnapshot` instance — but
the underlying `CompleteConstLedgerState` (bucket-list snapshot, hot
archive snapshot, soroban config, header, HAS) is already shared by
shared_ptr. The per-cluster copy is essentially copying a few shared_ptrs
plus a small `MetricsRegistry&` reference and lazily-initialized file-cache
maps that start empty.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone hypothesis

### Why It Failed

The per-cluster `ApplyLedgerStateSnapshot` copy is essentially copying
shared pointers (`CompleteConstLedgerStatePtr` is a shared_ptr to immutable
state) plus reference fields. The dominant snapshot data
(bucket-list snapshot, hot archive snapshot, soroban config, header, HAS)
is already structurally shared. Per-cluster copy cost is on the order of
shared_ptr increments + small map default-construction — single-digit
microseconds per cluster, ~50 µs/ledger total across 8 clusters. Far
below the 1% Low floor (~2 ms/ledger), and orders of magnitude below the
3% Medium objective threshold.

### Lesson Learned

Comments mentioning "thread-safe copies" can describe lazily-populated
per-thread caches over already-shared immutable backing data; copy cost
must be measured against the actual deep-copy payload, not inferred from
the comment. Per-thread file caches in `LedgerStateSnapshot` start
empty and populate on demand, so the construction cost is trivial. For
real savings in this region, the target is the deep-copy of
`LedgerEntry` instances during footprint preload (see ledger hypothesis
`003-zero-copy-cluster-footprint-preload.md`), not the snapshot wrapper.
