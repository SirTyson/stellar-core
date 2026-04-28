# H001: Parallelize processFeesSeqNums Per Cluster

**Date**: 2026-04-28
**Subsystem**: ledger
**Severity**: Medium
**Impact**: 3–7% reduction in soroswap apply time by parallelizing a currently-sequential per-tx phase
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Fee processing and sequence-number bumping for a soroswap-style tx set should
scale with available cores. Each tx with a unique source account performs
key-disjoint LTX mutations (`accountKey(getSourceID())` only) and is
independent of every other tx, so the apply thread should be able to dispatch
this work across the same `NUM_CLUSTERS` worker pool that already runs
`applySorobanStageClustersInParallel`. After parallel processing the per-tx
mutations should be merged into the parent `LedgerTxn` in deterministic
cluster/tx-index order, producing exactly the same fee charges, seq-num
increments, and tx-result objects (and, when `ledgerCloseMeta` is non-null,
the same per-tx fee-meta change vector) as the current serial implementation.

## Mechanism

`LedgerManagerImpl::processFeesSeqNums` (`ledger/LedgerManagerImpl.cpp:2308`)
loops phases × txs serially on the apply thread, calling
`tx->processFeeSeqNum(activeLtx, baseFee)` and pushing into a single
`txResults` vector. For 4000 soroswap txs this serial loop costs 286 ms total
in the baseline trace (zone `processFeesSeqNums,ledger/LedgerManagerImpl.cpp,2308`,
6.2% of `applyLedger`'s 4591 ms). Soroswap uses a unique source account per
tx (per `src/simulation/ApplyLoad.cpp:3395-3407`), and Soroban txs have no
`accToMaxSeq` participation (the `isV19OrLater && !tx->isSoroban()` branch
is dead for soroswap). The benchmark also runs with
`DISABLE_TX_META_FOR_TESTING=true`, so `ledgerCloseMeta` is null and the
fast path that operates directly on the parent LTX is taken — meaning each
tx's fee-processing work is purely a per-source-account update with no
shared per-tx LCM tracking. Splitting the loop across the same cluster
partitioning used by `applyParallelPhase` (which already proves the
footprints are key-disjoint per cluster) lets fee processing overlap on N
workers; merging cluster-local results back into the parent LTX in cluster
index order preserves determinism.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`
with `--mode soroswap`, the default soroswap config TX=4000, T=8) with
`APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS=8`. Tracy zone
`processFeesSeqNums,ledger/LedgerManagerImpl.cpp,2308` reports 286 ms total
self-time over 66 ledgers (mean 4.34 ms/ledger). Direct benchmark output
(per the reviewed H001 PoC, `processFeesSeqNumsMs` in
`mLastPhaseTimings`) should show a 3–5× reduction with 8-way cluster
parallelism.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2305-2440` — `processFeesSeqNums` serial
  loop and the post-loop `accToMaxSeq` write that must remain sequential
  but only fires for V19+ classic-with-merge txs.
- `src/transactions/TransactionFrame.cpp` — `processFeeSeqNum` (the per-tx
  callee); confirm it does not touch shared state outside `activeLtx`.
- `src/transactions/ParallelApplyUtils.cpp:925-1000` — existing
  per-cluster footprint partitioning for parallel apply (re-use the same
  cluster grouping built later for `applyParallelPhase`).
- `src/ledger/LedgerManagerImpl.cpp:2966-3030` — `applyParallelPhase` builds
  the `ApplyStage`/`Cluster` partitioning that fee processing can mirror.
- `src/main/ApplicationImpl.cpp:172-206,1300-1305` — only main, eviction,
  worker, overlay, and ledger-close threads are registered as `APPLY`;
  any cluster workers used here must avoid `threadIsType(APPLY)` asserts
  or be invoked through the same dispatch path as parallel apply.

## Evidence

The Tracy export confirms `processFeesSeqNums` is a measured descendant of
`applyLedger` (286 ms self-time, 66 calls, mean 4.34 ms, max 30.4 ms) and
not a TX-set construction zone. Soroswap's per-tx source IDs are unique
(`src/simulation/ApplyLoad.cpp:3395-3407`), so the tx-set partitions
naturally into cluster-disjoint fee-processing buckets. The benchmark's
`DISABLE_TX_META_FOR_TESTING=true` (`docs/apply-load-benchmark-sac.cfg:24`)
disables the per-tx child LTX path, so the inner work is exactly
`txResults.push_back(tx->processFeeSeqNum(parentLtx, baseFee))` — a small
mutation per source account. The benchmark uses
`APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS=8` (matching `NUM_CLUSTERS`),
giving an 8× ceiling. The reviewed H001 establishes the precedent of
running cluster-keyed work via `std::async` while keeping commit-order
deterministic by indexing into the futures vector.

The parallel apply path (`applySorobanStageClustersInParallel`) already
demonstrates that cluster footprints are key-disjoint by construction, so
parallel fee processing on the same partition cannot create source-account
conflicts. Cluster-local txResult vectors merged in cluster index order
yield the same `txResults` vector as the serial loop.

## Anti-Evidence

`processFeeSeqNum` reads/writes the `LedgerHeader` (`ltx.loadHeader()`),
which is a single per-LTX object guarded by the LTX active-handle
machinery. Concurrent header access from multiple threads on the same LTX
is unsafe; the implementation must use cluster-local child LTXs (each on
top of the parent) and commit them in cluster order, mirroring how
`ThreadParallelApplyLedgerState` carries thread-local state during
`applyParallelPhase`. Per-tx `processFeeSeqNum` may also call into the
parent's `LedgerTxnRoot` entry cache on first source-account miss; that
cache is not thread-safe, so the PoC must verify all source accounts are
prefetched (existing `prefetchTxSourceIds` already populates the cache)
and any further loads are served from the cluster-local LTX rather than
re-entering the root. Finally, the V19+ classic path computes
`accToMaxSeq` and `mergeOpInTx` — for soroswap this branch is dead, but
the implementation must keep the post-loop `loadMaxSeqNumToApply` write
sequential to avoid changing classic-tx semantics.

If the per-tx work is dominated by the LTX entry-handle activation
machinery (which is intrinsically serial within a single LTX), the
parallel speedup may be lower than the 5–7% projection. A PoC must
isolate `processFeesSeqNumsMs` (already in `mLastPhaseTimings`) before
and after, and run the benchmark ≥3 times to confirm the win exceeds
benchmark noise (>1%) and clears the Medium threshold (≥3%).

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The serial hot path exists: `LedgerManagerImpl::applyLedger` calls
`prefetchTxSourceIds` and then `processFeesSeqNums` before
`applyTransactions`, and `processFeesSeqNums` loops over
`getPhasesInApplyOrder()` pushing each result from
`tx->processFeeSeqNum(...)`. For current soroswap-style Soroban transactions,
`TransactionFrame::processFeeSeqNum` loads the source account, charges the
fee, updates `LedgerHeader::feePool`, and returns a success result, while the
classic-only `accToMaxSeq` path is skipped.

The proposed mechanism is not viable as written because concurrent
cluster-local `LedgerTxn` children cannot exist on the same parent and cannot
be moved to worker threads. `LedgerTxn::Impl::addChild` calls
`throwIfChild()` and records a single `mChild`; `LedgerTxn::Impl` also stores
the creating thread id and `abortIfWrongThread()` guards `addChild`,
`loadHeader`, `load`, `commit`, `commitChild`, and other mutation paths. Thus
creating several children on the apply thread and using them in `std::async`
would abort on thread-affinity checks, while creating them inside workers would
call `addChild` on the parent from the wrong thread and still violate the
single-child invariant. `LedgerTxnRoot` has the same shape: one active child,
an active-thread invariant, and non-thread-safe caches.

The existing Soroban parallel apply path does not provide precedent for
parallel child `LedgerTxn` use. It avoids `LedgerTxn` in workers by building a
`GlobalParallelApplyLedgerState`, creating `ThreadParallelApplyLedgerState`
objects on the apply thread, executing against thread-local entry maps, and
then committing those maps back sequentially. A fee-processing implementation
that merely reuses the stage/cluster partitioning but calls
`processFeeSeqNum` on child LTXs would break those ownership and threading
constraints.

### Alternative Angle

A refined hypothesis should avoid `LedgerTxn` in worker threads entirely. For
the benchmark-relevant fast path (`ledgerCloseMeta == nullptr`, Soroban
parallel phase, no classic merge tracking), workers could operate on detached
copies of fee-source account entries plus an immutable header snapshot, produce
per-tx fee-charged results and per-account updated entries indexed by original
apply order, and return only data. The apply thread would then update the
parent `LedgerTxn` in deterministic apply order and add the aggregate fee to
the single ledger header. This is closer to the existing
`GlobalParallelApplyLedgerState` / `ThreadParallelApplyLedgerState` model than
to nested `LedgerTxn` children.

That refined version must explicitly handle or gate out fee-bump transactions,
shared fee-source/source accounts, `ledgerCloseMeta` fee-processing changes,
pre-v10 sequence-number updates, and the V19+ classic `accToMaxSeq` merge path.
It also needs a fresh severity projection because the measured target is only
about 6.2% of `applyLedger`; any extra detached-copy, validation, and
sequential-commit overhead could easily push the end-to-end win below the
objective's Medium threshold.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches
  source accounts, then runs `processFeesSeqNums`, then applies transactions.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — serial fee/sequence loop,
  optional per-tx child LTX for metadata, direct-parent fast path when metadata
  is disabled, and sequential `accToMaxSeq` handling.
- `src/transactions/TransactionFrame.cpp:1776-1817` — normal transaction fee
  processing mutates the source account and the ledger header fee pool.
- `src/transactions/FeeBumpTransactionFrame.cpp:764-795` — fee-bump fee
  processing uses the fee source account and also mutates the ledger header fee
  pool.
- `src/ledger/LedgerTxn.cpp:443-453,481-487,532-540,604-617,2111-2127` —
  `LedgerTxn` construction registers one child with the parent, enforces
  creating-thread affinity, and rejects concurrent child/header use.
- `src/ledger/LedgerTxn.cpp:2872-2895,2979-3047` — `LedgerTxnRoot` likewise
  owns one active child and clears thread-bound SQL/cache state on commit.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` and
  `src/transactions/ParallelApplyUtils.cpp:893-922,925-1001` — Soroban
  parallel apply uses thread-local parallel-apply state, not worker
  `LedgerTxn` children.
