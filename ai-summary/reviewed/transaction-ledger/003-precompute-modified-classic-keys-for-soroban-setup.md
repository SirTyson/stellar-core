# H003: Precompute Modified-Classic-Key Set to Eliminate the Per-Tx requiresSequentialPreParallelApply Scan

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (parallel apply orchestration)
**Severity**: Medium
**Impact**: Critical-path setup phase reduction in `soroban_setup_glbl`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState`'s constructor should classify each Soroban tx
as either "requires sequential pre-apply" or "can take the read-only fast path"
in time proportional to the *number of classic entries the classic phase
actually modified* (typically ≪ 100 entries per soroswap ledger), not in time
proportional to `Σ(numTxs × footprintSize)`. Classification is a pure
membership check: a tx requires sequential pre-apply iff any classic key it
references (source, fee-source, op-source accounts, plus the classic subset of
its footprint) was modified earlier this ledger.

## Mechanism

Today the constructor runs `requiresSequentialPreParallelApply` per
transaction
(`src/transactions/ParallelApplyUtils.cpp:170-208`,
called from line 450), and that helper invokes
`isModifiedClassicKey` (line 152) twice per classic key:
`current.load(key)` against the in-flight `LedgerTxn` and `previous.load(key)`
against the LCL `mLCLSnapshot`. With 244 Soroban txs/ledger × ≥4 classic
account checks (source + fee-source + op-source + extra footprint accounts) ×
2 loads × LedgerSnapshot wrapper overhead, this runs **thousands of
per-tx LedgerSnapshot loads on the apply thread, sequentially, before any
worker future is launched.** This is precisely the dominant unaccounted slice
of the 24.7 ms/ledger `soroban_setup_glbl` zone (the Tracy-instrumented
descendants — `preParallelApplyReadOnly`, `preParallelApplyWrite`,
`collectModifiedClassicEntries`, `fetchSorobanReadOnlyEntries` — together sum
to <5 ms/ledger; the rest is this scan plus the sequential
`preParallelApply` calls that follow it).

The classic phase already knows the exact set of classic accounts/trustlines
it modified (it is the writer); we can capture that set once and turn the
per-tx check into an O(footprintSize) hash-set lookup. This eliminates ~1500
LedgerSnapshot.load() invocations per soroswap ledger and removes the cost
asymmetry where Soroban setup pays a tax proportional to the classic phase's
state.

## Trigger

Run the soroswap apply-load matrix
(`scripts/run_apply_load_matrix.py --benchmarks soroswap --threads 8`) and
compare median `apply_transactions` and `soroban_setup_glbl` timings before
and after the change. Expected: `soroban_setup_glbl` drops from ~24.7 ms to
≤10 ms (the irreducible parallel `readOnlyPreParallelApply` critical path
plus the small sequential `preParallelApply` and commit work), yielding
≥4-5% reduction in median `apply_transactions`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:151-208` —
  `isModifiedClassicKey` and `requiresSequentialPreParallelApply`. Replace
  the per-call double-`load()` with a `contains()` against a precomputed set.
- `src/transactions/ParallelApplyUtils.cpp:431-468` —
  `preParallelApplyAndCollectModifiedClassicEntries` body where the per-tx
  classification loop runs serially on the apply thread before
  `readOnlyPreParallelApply`.
- `src/ledger/LedgerManagerImpl.cpp:1670-1690` and surrounding fee/seq
  processing — the producer side that needs to capture the modified-classic
  key set during/after the classic apply phase. Likely entry points are
  the `processFeesSeqNums` and classic apply paths that already mutate
  classic entries via `LedgerTxn`.
- `src/transactions/ParallelApplyUtils.cpp:386-429` —
  `GlobalParallelApplyLedgerState` constructor; takes the new
  `std::unordered_set<LedgerKey> const&` (or equivalent) as a constructor
  argument and threads it through.
- `src/ledger/LedgerManagerImpl.cpp:2672-2705` — `applySorobanStages` call
  site; passes the captured set into the global state.

## Evidence

1. **Phase-timing breakdown** from
   `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.log`
   shows `soroban_setup_glbl` consuming **24.70 ms per soroswap ledger
   (~7.5% of close time)**, running entirely on the apply thread before any
   worker is launched.
2. **Tracy zone aggregates** for the constructor's instrumented descendants
   (csvexport totals divided by 41 ledgers): `preParallelApplyReadOnly`
   2.14 ms (parallelized across 8 workers → ~0.27 ms critical path),
   `preParallelApplyWrite` 0.56 ms, `collectModifiedClassicEntries` 0.37 ms,
   `fetchSorobanReadOnlyEntries from footprints` 0.15 ms. These descendants
   sum to <5 ms/ledger, leaving **~20 ms unaccounted** — and the only
   un-instrumented work in the constructor is the
   `requiresSequentialPreParallelApply` scan + the small fraction of txs
   that take the sequential `preParallelApply` branch.
3. **Structural observation**: the scan calls `LedgerSnapshot::load` against
   *both* sides for *every* classic key referenced by every tx, even though
   for soroswap nearly all classic accounts are *unmodified* by the classic
   phase (the workload is Soroban-only past fee/seq processing). Most loads
   return the same value on both sides — pure waste.
4. **Determinism preserved**: the proposed precomputed set is a pure
   function of the classic-phase outputs, which already run deterministically
   ahead of `applySorobanStages`. The set has no observable effect on
   ledger output; only the classification mechanism changes.
5. **No worker-count concern**: the change *removes* serial work; it does
   not introduce new threads. Existing `LEDGER_CLOSE_WORKER_THREADS`-bounded
   parallelism in `readOnlyPreParallelApply` is unchanged.

## Anti-Evidence

- The "modified classic keys" set must include any account whose sequence
  number was bumped or fee was charged during `processFeesSeqNums`, plus
  any classic entry mutated during the sequential classic phase. If the
  capture point misses an entry kind, the classification becomes
  unsound — a tx that should take the sequential path takes the read-only
  path and observes stale data. Implementation must capture the set
  *after* all classic-phase writes complete and *before* `applySorobanStages`
  begins, with an audit of every `LedgerTxn` write site that could reach
  a key referenced by a Soroban footprint.
- Fee-bump and Soroban fee-source accounts are always modified by
  `processFeesSeqNums`. The set must therefore include every Soroban tx's
  fee-source account; this may shrink the savings if many txs reuse fee
  sources. For soroswap (unique source per tx), this is not a concern.
- A precomputed `std::unordered_set<LedgerKey>` build itself has cost; if
  the classic phase modifies thousands of entries, the set build could
  approach the cost of the existing scan. For soroswap, the classic phase
  modifies on the order of (numTxs × few accounts) = a few hundred entries —
  set construction is microseconds.
- Fail H001 (`parallelize-thread-state-construction`) targeted a different
  phase: per-cluster `ThreadParallelApplyLedgerState` construction
  (post-`std::async`), and was rejected because the zone time was
  worker-execution behind `future.get()`. This hypothesis targets a
  *different* zone (`soroban_setup_glbl`, measured directly via
  `mLastPhaseTimings.sorobanSetupGlobalMs`) which is unambiguously serial
  apply-thread time.
- Fail H004 (`parallelize-commit-changes-from-threads`) targeted the
  *post-stage* `commitChangesFromThreads`, not the *pre-stage*
  classification scan in the constructor. Different code path, different
  zone, different mechanism.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`applyLedger` charges fees in `processFeesSeqNums`, then `applyTransactions` reaches the parallel Soroban phase and constructs `GlobalParallelApplyLedgerState` before any worker futures are launched. In protocol 26, that constructor calls `preParallelApplyAndCollectModifiedClassicEntries`, which classifies every Soroban tx by repeatedly comparing the in-flight `LedgerTxn` snapshot against the LCL bucket snapshot. The exact inefficiency exists: `isModifiedClassicKey` performs two `LedgerSnapshot::load` calls per tested classic key, while the `LedgerTxn` already exposes an O(1) `isModifiedKey` predicate for the same "was this key modified in this ledger" safety decision. A correct implementation should prefer the existing `AbstractLedgerTxn::isModifiedKey`/EntryMap predicate, or an equivalent dynamically maintained set, over a one-time set that cannot observe sequential pre-apply writes.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1673-1688` — fee/sequence processing runs before transaction application, so Soroban source/fee-source accounts are already present in the in-flight `LedgerTxn` when parallel setup begins.
- `src/ledger/LedgerManagerImpl.cpp:2784-3030` — `applyTransactions` builds Soroban `ApplyStage`s and calls `applySorobanStages`; this is the hot `closeLedger` path for the soroswap parallel phase.
- `src/ledger/LedgerManagerImpl.cpp:2672-2690` — `GlobalParallelApplyLedgerState` construction is timed as `soroban_setup_glbl` and completes before stage worker launch.
- `src/transactions/ParallelApplyUtils.cpp:151-208` — `isModifiedClassicKey` rejects Soroban keys, then loads `current` and `previous` and compares full `LedgerEntry` values; `requiresSequentialPreParallelApply` calls it for tx source, fee source, op sources, and classic footprint entries.
- `src/transactions/ParallelApplyUtils.cpp:431-468` — protocol-26 setup runs the classification loop serially; txs classified as sequential immediately call `preParallelApply`, while others are buffered for read-only pre-apply and later write commit.
- `src/transactions/ParallelApplyUtils.cpp:600-719` — `collectModifiedClassicEntries` runs after classification, so it cannot reduce the classification loads; its classic-key collection is for populating the global map.
- `src/ledger/LedgerStateSnapshot.cpp:157-160,224-228,296-299` — `current.load` goes through `LedgerTxn::loadWithoutRecord`, while `previous.load` goes through the bucket snapshot, confirming the repeated wrapper/snapshot lookup cost.
- `src/ledger/LedgerTxn.h:687-690` and `src/ledger/LedgerTxn.cpp:1767-1778` — `AbstractLedgerTxn::isModifiedKey` already provides an O(1) check against the `LedgerTxn` EntryMap.
- `src/bucket/BucketManager.cpp:1180-1189` — another close-ledger path already uses `isModifiedKey` specifically to avoid building/scanning modified-key sets.
- `src/transactions/TransactionFrame.cpp:2145-2248,2315-2333` and `src/transactions/FeeBumpTransactionFrame.cpp:86-145` — pre-apply read-only validation records whether sequence/signature writes are needed; `preParallelApplyWrite` can mutate source, op-source, and fee-source accounts, which the optimized classifier must observe for later txs.

### Findings

The inefficiency is real and in scope. The serial protocol-26 classifier sits inside `soroban_setup_glbl`, and the current helper performs expensive current/LCL loads when the safety property only needs to know whether a classic key has been touched in the in-flight ledger state. Source/fee-source keys are particularly important in soroswap because `processFeesSeqNums` modifies them before the global setup phase, causing the classifier to pay at least one current/LCL account comparison per Soroban tx even when it short-circuits early.

There is no existing optimization covering this classifier. Source-account prefetching feeds the mutable ledger transaction/root path, not the separate LCL bucket snapshot used by `previous.load`, and `collectModifiedClassicEntries` happens after classification. The existing `LedgerTxn::isModifiedKey` API is a better implementation target than building a separate one-shot set: it is already O(1), avoids sealing the `LedgerTxn`, and automatically reflects mutations committed by earlier sequential `preParallelApply` calls during the same classification loop.

Correctness is the main constraint. `isModifiedKey`/write-set semantics can over-classify a tx as sequential if a key was touched and later restored to its previous value, but that is safe and only loses optimization opportunity. Under-classification is unsafe, so a precomputed set must not be frozen before the loop unless it is also updated after every sequential `preParallelApply`/`preParallelApplyWrite` that can bump sequence numbers or remove one-time signers from source/op-source/fee-source accounts.

Estimated impact is Medium. The measured soroswap `soroban_setup_glbl` median is 24.70 ms out of 308.80 ms `apply_transactions`, and the traced uninstrumented classifier is the only large serial work in that constructor not covered by the already-small descendant zones. Eliminating hundreds to thousands of LCL/current snapshot loads per ledger is plausibly in the 3-10% apply-time band, especially because the work is entirely on the apply thread before parallelism starts.

### PoC Guidance

- **Target code**: `src/transactions/ParallelApplyUtils.cpp`, especially `isModifiedClassicKey`, `requiresSequentialPreParallelApply`, and `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`.
- **Change description**: replace the `LedgerSnapshot current/previous` value-comparison classifier with a classic-key predicate based on `AbstractLedgerTxn::isModifiedKey(key)` or an equivalent mutable modified-key set. Keep the `isSorobanEntry` guard. If using a set rather than `isModifiedKey`, initialize it after fee/classic processing and update it after any sequential `preParallelApply` write before classifying later txs.
- **Correctness check**: existing protocol-26 Soroban and fee-bump pre-auth signer tests exercise the sequence/signature side effects that make stale read-only pre-apply unsafe; any PoC should also cover a later tx whose source/op-source/footprint references an account modified by an earlier sequential pre-apply.
- **Benchmark focus**: compare median `soroban_setup_glbl` and top-line `apply_transactions` in `scripts/run_apply_load_matrix.py --benchmarks soroswap --threads 8` over repeated runs. The expected signal is a multi-millisecond drop in `soroban_setup_glbl`; promote only if top-line apply time improves by at least the objective's 3% Medium threshold.
