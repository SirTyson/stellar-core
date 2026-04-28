# H002: Parallelize processFeesSeqNums over disjoint fee-source accounts (Soroban-only ledger fast path)

**Date**: 2026-04-27
**Subsystem**: transactions
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the sequential per-tx fee-debit + seqnum-bump walk that today serializes ~4.4 ms of work on the apply thread per ledger.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::processFeesSeqNums` debits inclusion fee from each
tx's fee-source account, bumps that account's sequence number when
appropriate, and produces a `MutableTxResultPtr` per tx. For a soroban-
only ledger whose fee-source accounts are pairwise disjoint across the
tx set (the common case for soroswap apply-load, where every tx has a
unique source account, and is also expected on production soroban
traffic dominated by per-user invocations), the per-tx work is
**independent**: each tx mutates exactly one account that no other tx
touches and reads only its own footprint. The expected behavior is
therefore that fee processing for such ledgers runs in parallel across
the existing `LEDGER_CLOSE_WORKER_THREADS` pool (capped by `NUM_CLUSTERS`),
with the same observable order of writes to the parent `AbstractLedgerTxn`
as today, the same `MutableTxResultPtr` content, the same
`pushTxFeeProcessing` meta order, and the same error semantics on
insufficient balance. When disjointness or non-Soroban tx mix prevents
the fast path, processing falls back to the existing sequential loop.

## Mechanism

`processFeesSeqNums` (lines 2302–2400) walks
`txSet.getPhasesInApplyOrder()` sequentially and calls
`tx->processFeeSeqNum(ltx, baseFee)` for every tx, mutating the parent
`LedgerTxn` directly (or via a per-tx child `LedgerTxn` when meta is
enabled). The Tracy trace shows this zone consumes ~4.3 ms per ledger
on the apply thread (~6% of `applyLedger` wall time), and unlike
`preParallelApply` (which has already been parallelized for the
read-only stage in `ParallelApplyUtils::readOnlyPreParallelApply`),
fee processing remains a single-threaded walk. Because the soroswap
benchmark's tx generator (`src/simulation/ApplyLoad.cpp:3395-3407`) and
typical Soroban traffic produce pairwise-disjoint fee sources, the
existing reason for serialization (handling overlapping fee accounts
from classic txs and the `accToMaxSeq` / `mergeSeen` tracking for
ACCOUNT_MERGE detection) is not exercised on Soroban-only ledgers. The
fix is a fast path that (1) verifies the ledger contains no classic txs
and that fee-source IDs are pairwise disjoint (one O(N) pass building an
`UnorderedSet<AccountID>`), (2) shards the tx vector across worker
threads with each worker writing into a per-tx scratch `LedgerTxn`
child off a shared snapshot, and (3) sequentially commits the per-tx
deltas back to the parent ltx in original tx order, preserving meta and
result order. The soroban tests already mandate `accToMaxSeq` is unused
when `!tx->isSoroban()` is false for every tx, so the bookkeeping
collapses cleanly on the fast path.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap config (4000
tx/ledger, 8 clusters). In Tracy, the `processFeesSeqNums` zone shows
~4.3 ms/ledger of self time (286 ms aggregate / 65 ledgers) entirely on
the apply thread. After the fix, the zone should drop to approximately
the disjointness scan + commit cost (~0.5–1 ms) with the per-tx
`processFeeSeqNum` work moving onto worker threads. Median apply time
should drop by ~3 ms/ledger (~4–5%) reproducibly across at least three
matrix runs.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2302-2434` — `processFeesSeqNums`,
  the sequential fee-and-seqnum walk this hypothesis parallelizes.
- `src/ledger/LedgerManagerImpl.cpp:2785-2964` — `applyTransactions`,
  the caller; needs an updated meta path so that
  `pushTxFeeProcessing` is still emitted in tx order even when
  computation runs in parallel.
- `src/transactions/TransactionFrame.cpp` (`processFeeSeqNum`
  implementation) — must be reviewed for any shared mutable state
  (it currently only loads/mutates the fee-source `AccountEntry`).
- `src/transactions/ParallelApplyUtils.cpp:526-583` —
  `readOnlyPreParallelApply` is the existing precedent for sharding
  per-tx work across workers via `std::async` with a chunked range.
- `src/simulation/ApplyLoad.cpp:3395-3407` — the soroswap generator
  guaranteeing per-tx unique source accounts; useful for an apply-
  load–level assertion validating the fast-path activation on the
  benchmark.

## Evidence

- Tracy: `processFeesSeqNums` total 286 ms / 65 ledgers = 4.4 ms/
  ledger, and `prefetchTxSourceIds` total 94 ms / 65 = 1.4 ms/ledger
  — both today serial walks over the same per-tx data.
- The benchmark memory states: "Soroswap swap generation uses a unique
  account per tx and source-account Soroban credentials"
  (`src/simulation/ApplyLoad.cpp:3395-3407`). Disjointness holds by
  construction.
- The non-Soroban-specific bookkeeping at lines 2369-2383 (`accToMaxSeq`,
  `mergeSeen`) is gated on `!tx->isSoroban()`; on a Soroban-only ledger
  these branches are dead and the per-tx body reduces to
  `tx->processFeeSeqNum(activeLtx, baseFee)` plus optional
  `pushTxFeeProcessing` of the recorded changes.
- `LedgerTxn` already supports per-tx child transactions
  (`LedgerTxn ltxTx(ltx); ... ltxTx.commit();` pattern at lines
  2386-2394), so per-worker scratch ltx is a localized change of an
  established idiom.
- The `readOnlyPreParallelApply` parallelization (~7 ms aggregate /
  ledger) ships today with deterministic chunked `std::async` workers
  and a sequential commit step — the same scaffold can be
  factored/reused for fee processing.
- Worker count cap at `LEDGER_CLOSE_WORKER_THREADS` (which mirrors
  `NUM_CLUSTERS`) is consistent with the objective's parallelism
  ceiling.

## Anti-Evidence

- `LedgerTxn` is not thread-safe: the parallel fee compute must run
  on per-worker scratch ltxs that are merged into the parent on the
  apply thread. The merge step itself is sequential (~hundreds of
  microseconds on the bench, far cheaper than 4.4 ms saved) but it
  must preserve write ordering so that `pushTxFeeProcessing` still
  emits in tx order — this requires careful design.
- Fast-path activation requires *both* "no classic txs in this ledger"
  *and* "pairwise-disjoint fee sources". Production may not always
  satisfy both — but soroswap apply-load definitely does, and Soroban-
  only ledgers (the dominant production pattern for this benchmark)
  do too. The fallback is the existing serial loop, so the worst-case
  perf is unchanged.
- Determinism: the fee-debit amount and seqnum bump for an isolated
  account must produce byte-identical `LedgerEntryChanges` regardless
  of execution order. Because each tx touches a unique account, this
  holds. But the meta merging step must commit child ltxs in original
  tx order to keep `pushTxFeeProcessing` order identical — easy to get
  wrong if the worker just commits in completion order.
- The win is "only" ~3 ms/ledger (~4–5%) — squarely Medium but not
  High. PoC must show the gain survives multiple soroswap runs and
  does not regress max-sac. If meta is enabled, the per-tx child-ltx
  cost grows and the parallel benefit may shrink; the headline
  benchmark runs with meta disabled (per the
  `apply-load-benchmark-sac.cfg` template), so the fast-path
  activation aligns with the measured workload.
- Past attempts to parallelize related areas (`fail/transactions/
  001-parallelize-thread-state-setup`) were rejected for breaking the
  per-cluster invariant; this hypothesis targets a different code
  path (fee processing, before parallel apply), so the same rejection
  rationale does not directly apply, but PoC must verify the parent-
  ltx commit order remains observable as today.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The hot-path observation is real and novel, but the stated mechanism is not correct against the actual ledger-transaction semantics. `LedgerManagerImpl::processFeesSeqNums` creates a single main-thread `LedgerTxn ltx`, then either mutates it directly when meta is disabled or creates one ordered child `LedgerTxn ltxTx(ltx)` per transaction when meta is enabled. `TransactionFrame::processFeeSeqNum` loads the source/fee account, debits the fee, and increments `LedgerHeader::feePool`; for current Soroban protocol versions it does **not** bump sequence numbers, which are updated later by `preParallelApplyWrite`.

The proposed "per-tx scratch `LedgerTxn` child off a shared snapshot" cannot be implemented by simply moving the current `processFeeSeqNum` body to workers. `LedgerTxn::Impl` stores the thread id that created it and aborts on `addChild`, `loadHeader`, `load`, `commit`, and related operations from any other thread; it also allows only one active child. In addition, every scratch transaction would modify the ledger header's `feePool`; committing multiple independently-based header deltas in tx order would overwrite rather than naturally accumulate fee-pool changes unless the implementation adds a custom aggregation path outside normal `LedgerTxn` commit semantics. Fee-source disjointness only proves the account debits do not conflict; it does not make the header update disjoint.

### Alternative Angle

A viable version would need to avoid worker-owned mutable `LedgerTxn` children entirely. The parallel phase could use a read-only snapshot to load fee-source accounts, compute each tx's fee charge and mutable result into per-index scratch storage, and separately sum the fee-pool delta; then the main thread would apply account debits, cumulative header update, meta `LedgerEntryChanges`, replay expected-results handling, and any fee-bump/source-side effects in deterministic transaction order. That refined design must explicitly show that the remaining ordered write/metadata pass is small enough for the soroswap benchmark to retain a 3-10% top-line apply-time improvement.

### Additional Code Paths

- `src/ledger/LedgerManagerImpl.cpp:1645-1688` — `closeLedger` prefetches fee/source accounts, calls `processFeesSeqNums`, then calls `applyTransactions`; this places fee processing on the apply critical path before parallel Soroban apply.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — `processFeesSeqNums` performs the sequential fee-result loop, maintains test replay ordering, skips `accToMaxSeq`/`mergeSeen` for Soroban txs, optionally pushes per-tx fee-processing meta, and commits the enclosing `LedgerTxn`.
- `src/transactions/TransactionFrame.cpp:1777-1817` — regular tx fee processing loads the source account, debits `min(balance, fee)`, increments `header.feePool`, and only updates sequence numbers before protocol 10.
- `src/transactions/FeeBumpTransactionFrame.cpp:764-795` — fee-bump fee processing mutates the outer fee-source account and `header.feePool`, with inner fee accounting for older protocols; a Soroban-only fast path must account for fee-bump Soroban txs because `FeeBumpTransactionFrame::isSoroban()` delegates to the inner tx.
- `src/transactions/TransactionFrame.cpp:2145-2195,2315-2371` — parallel Soroban pre-apply validates against a read-only snapshot, records whether the sequence number and one-time signers need mutation, and then applies those writes later on the main/apply thread.
- `src/ledger/LedgerTxn.cpp:531-538,563-608,2111-2117` — `LedgerTxn` enforces same-thread access for child creation, header loading, commit, and commit-child operations.
- `src/ledger/LedgerTxn.cpp:1416-1455` and `src/ledger/LedgerCloseMetaFrame.cpp:70-91` — fee-processing metadata is derived from ordered child `LedgerTxn::getChanges()` and appended in tx order.
- `src/transactions/ParallelApplyUtils.cpp:526-583` — `readOnlyPreParallelApply` is a valid precedent for sharding read-only work, but not for worker-side mutable `LedgerTxn` children.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generation uses one unique source account per tx, so the benchmark likely satisfies source/fee-account disjointness for non-fee-bump generated swaps.
