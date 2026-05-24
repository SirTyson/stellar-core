# H005: Shared Read-Only Base for `mThreadEntryMap` via Copy-on-Write Layered View

**Date**: 2026-05-23
**Subsystem**: soroban
**Severity**: Medium (claimed) → rejected to Low
**Impact**: Eliminate the 8× sequential per-cluster
`collectClusterFootprintEntriesFromGlobal` walk inside
`ThreadParallelApplyLedgerState`'s constructor by sharing a read-only
view of `mGlobalEntryMap` and giving each worker only a small dirty
overlay.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ThreadParallelApplyLedgerState` needs *read-only* access to all entries
the cluster will touch, plus the ability to *upsert* changes locally
during apply. The initial population of `mThreadEntryMap` from
`mGlobalEntryMap` is purely a copy — no work the worker does requires
those base entries to be in a thread-local container. A correct design
would let workers read straight from the shared, immutable
`mGlobalEntryMap` and write only to a small per-thread overlay,
collapsing the layered view at commit time. This eliminates the
sequential per-cluster `fetchFromGlobal` walks on the main apply thread.

## Mechanism

`ThreadParallelApplyLedgerState::ThreadParallelApplyLedgerState`
(`src/transactions/ParallelApplyUtils.cpp:988`) is constructed for each
of `NUM_CLUSTERS` (=8) clusters **sequentially on the main apply
thread**, before `applySorobanStageClustersInParallel` issues
`std::async` calls (`src/ledger/LedgerManagerImpl.cpp:2545..2554`).
Each construction calls `collectClusterFootprintEntriesFromGlobal`
(line 925), which walks every tx's RO+RW footprint (plus TTL keys) and
does a `mGlobalEntryMap.find` + conditional `emplace` for each. For
soroswap that is ~250 txs/cluster × ~16 keys = ~4k operations/cluster ×
8 clusters = ~32k serial operations per ledger.

The hypothesis: replace `mThreadEntryMap` with a
`(shared_ptr<GlobalParallelApplyEntryMap const>, thread-local overlay)`
pair. Reads first probe the overlay, then fall through to the shared
base. Writes go only to the overlay. Construction becomes O(1) per
cluster (just shared_ptr copies), eliminating the serial pre-launch
window.

## Trigger

Soroswap apply-load benchmark; every ledger goes through 8 sequential
`ThreadParallelApplyLedgerState` constructions before workers can run.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:988` — Thread state ctor
- `src/transactions/ParallelApplyUtils.cpp:925..986` —
  `collectClusterFootprintEntriesFromGlobal`
- `src/transactions/ParallelApplyUtils.cpp:1085..1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt` (read path)
- `src/transactions/ParallelApplyUtils.cpp:1124..1162` — `upsertEntry`
  / `eraseEntry` (write path)
- `src/ledger/LedgerManagerImpl.cpp:2545..2554` — sequential ctor loop

## Evidence

- The ctor loop is structurally serial on the apply thread: 8 ctor calls
  before any worker can launch.
- `applySorobanStageClustersInParallel` self-time is 2.69s / 43 calls =
  62.6ms/ledger average. Some unknown portion of that "self" time is
  the pre-launch ctor loop and the post-future-get drain loop (since
  Tracy's `self` excludes only child-zone time on the *same* thread —
  worker `applyThread` zones run on different threads and are not
  children).
- Reducing the pre-launch window directly shortens the apply-thread
  critical path before parallelism begins.

## Anti-Evidence

- The dedicated zones `collectModifiedClassicEntries` (72 calls,
  204µs/ledger) and `fetchSorobanReadOnlyEntries from footprints` (72
  calls, 123µs/ledger) are measured. By analogy, `collectClusterFootprintEntriesFromGlobal`
  is similarly cheap per cluster (≈ 250µs ÷ 8 ≈ 30µs/cluster × 8 =
  ~240µs/ledger total). At 240µs/ledger = ~0.11% of 218ms — below the
  1% Low noise floor.
- The 62.6ms/ledger "self" attributed to
  `applySorobanStageClustersInParallel` is dominated by *blocking on
  the slowest worker future*, not by the pre-launch ctor loop. Tracy
  counts that wait as self-time because the worker zones live on
  different threads. Reducing the ctor loop will not shorten the
  critical path because workers are bounded by their own work.
- Layered-view reads introduce a per-`getLiveEntryOpt` extra probe
  (overlay-then-base instead of one map lookup). `getLiveEntryOpt` is
  called from every per-tx storage access in workers; even a few-ns
  extra cost over millions of calls could regress more than the ctor
  savings.
- `mThreadEntryMap` is *mutated* during apply (upsert/erase per write).
  An overlay design must preserve mIsNew tracking and the dirty-flag
  semantics in `ThreadParallelApplyEntry`; the design effort is
  non-trivial for a sub-Low projected win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail/hypothesis/reviewed/poc dirs for
soroban or transaction-ledger.

### Why It Failed

Two reasons:

1. **Sub-Low projected savings.** The serial work eliminated
   (`collectClusterFootprintEntriesFromGlobal` × 8) is bounded by
   analogy to the measured `collectModifiedClassicEntries` zone
   (~200µs/ledger): the per-cluster walk is the same shape and similar
   per-key cost. Total per-ledger ≈ 200–400µs ≈ 0.1–0.2% of the
   218ms soroswap baseline, well under the 1% Low floor and an order
   of magnitude below the 3% Medium floor.

2. **Wrong critical path.** The 62.6ms/ledger
   `applySorobanStageClustersInParallel` self-time is dominated by the
   main thread *waiting on the slowest worker future*, not by the
   pre-launch ctor loop. Shortening the pre-launch window does not
   shorten the wall-clock critical path; workers still take as long as
   they take.

Per objective rules ("Low not accepted at hypothesis stage"), this is
self-rejected to fail/.

### Lesson Learned

Tracy `self_ns` on a zone whose children run on *other threads* counts
the parent's wait-time as self. Before attributing such self-time to
serial work inside the parent function, identify which portion is
actual on-cpu work vs. blocking on cross-thread completions. Optimizing
the on-cpu portion only helps if it lies on the critical path; optimizing
pre-launch setup is only useful if launch latency dominates worker time,
which is not the case here.
