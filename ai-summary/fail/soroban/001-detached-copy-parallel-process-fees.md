# H001: Parallel processFeesSeqNums via detached fee-source-account snapshots (no LedgerTxn in workers)

**Date**: 2026-04-28
**Subsystem**: ledger / transactions (apply-thread fee processing)
**Severity**: Medium
**Impact**: 3–5% reduction in soroswap apply time by removing a fully-serial per-tx loop from the apply critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Fee processing for a Soroban-only phase (soroswap shape: every tx is a single
`InvokeHostFunctionOp`, every tx has a unique source account, the benchmark
runs with `DISABLE_TX_META_FOR_TESTING=true` so `ledgerCloseMeta == nullptr`,
and `accToMaxSeq` is dead because `tx->isSoroban()` is true) should be able to
run concurrently across the same `NUM_CLUSTERS` worker pool already used by
`applySorobanStageClustersInParallel`. Each tx's fee charge is a pure
function of `(sourceAccount, baseFee, ledgerHeader)` and produces:

1. an updated `AccountEntry` (balance debit equal to `min(acc.balance, fee)`)
2. a `MutableTxResultPtr` carrying the charged fee
3. a `feePool` delta (the same charged-fee value)

Because the soroswap generator gives every tx a unique source account
(`src/simulation/ApplyLoad.cpp:3395-3407` — one fresh account per swap),
the per-tx work is **key-disjoint by construction** for the entire phase.
Workers can therefore operate on detached `LedgerEntry` copies pulled out
of the parent `LedgerTxn` snapshot up-front; no worker ever touches
`AbstractLedgerTxn` directly. The apply thread then merges results back
into the parent in deterministic apply order:

- For each tx in apply order, write the worker-produced `AccountEntry`
  back into the parent LTX (`getLiveEntry().data.account() = ...`).
- Sum all charged fees and add once to `header.feePool`.
- Append worker-produced `MutableTxResultPtr` entries to `txResults` in
  apply order.

Output is byte-for-byte identical to today's serial loop because the only
serial dependency the current code has is `header.feePool +=` accumulation,
and aggregating per-tx charged-fee values commutes (`feePool` is monotonic
and the sum is associative under the existing
`std::min(acc.balance, fee)` semantics — each account's balance is
independent of every other account, so the parent-LTX merge step does not
need to re-evaluate per-tx ordering).

## Mechanism

`LedgerManagerImpl::processFeesSeqNums`
(`src/ledger/LedgerManagerImpl.cpp:2302-2440`) iterates phases × txs
serially on the apply thread, calling `tx->processFeeSeqNum(activeLtx, baseFee)`.
For 4036 soroswap txs/ledger × 65 ledgers, the Tracy zone
`processFeesSeqNums,ledger/LedgerManagerImpl.cpp,2308` reports
**270 ms self-time across 65 calls (mean 4.15 ms/ledger) = 6.2% of
`applyLedger` (4.33 s)**. The serial loop is the hot critical-path work
between the prefetch phase and `applyTransactions`.

The reviewer of `ai-summary/fail/ledger/001-parallelize-process-fees-seq-nums.md`
correctly rejected the prior naïve approach (multiple `LedgerTxn` children
on the apply thread used by workers) on `LedgerTxn` thread-affinity and
single-child invariants
(`src/ledger/LedgerTxn.cpp:443-453,481-487,532-540,604-617`) and pointed
to the `GlobalParallelApplyLedgerState` /
`ThreadParallelApplyLedgerState` model as the proper template
(`src/transactions/ParallelApplyUtils.cpp:893-1001`).

This refined hypothesis applies that template:

1. **On the apply thread** — pre-load every Soroban tx's source-account
   `LedgerEntry` from the parent LTX snapshot (the prefetch from
   `prefetchTxSourceIds` has already warmed the entry cache, so this is
   in-cache hits). Build a per-tx work item containing
   `(tx, AccountEntry copy, baseFee)` and partition into
   `NUM_CLUSTERS` shards.
2. **On worker threads** — for each work item, replicate the body of
   `TransactionFrame::processFeeSeqNum`
   (`src/transactions/TransactionFrame.cpp:1776-1817`) against the
   detached `AccountEntry` copy: compute `fee = min(acc.balance, fee)`,
   subtract from balance, build the success
   `MutableTxResultPtr`. Workers never call `LedgerTxn::load`,
   `loadHeader`, or any LTX mutation method, so the
   thread-affinity and single-child invariants are preserved.
3. **On the apply thread** — merge worker outputs in deterministic
   apply order: write each updated `AccountEntry` back into the parent
   LTX, append to `txResults`, accumulate per-tx charged fees into a
   single `header.feePool +=` add at the end.

Determinism is preserved because (a) the per-tx work is data-dependent
only on its own source account and the immutable header snapshot, and
(b) the apply-thread merge writes results in the same fixed order as
today's loop. Concurrency is capped at `NUM_CLUSTERS` per the objective.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py --mode soroswap`, default config TX=4000,
T=8, `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS=8`). Tracy zone
`processFeesSeqNums,ledger/LedgerManagerImpl.cpp,2308` reports a
~5× wall-time reduction (4.15 ms → ~1 ms per ledger). The
`run_apply_load_matrix.py` median apply-time should fall by 3–5% on
soroswap (and is neutral or slightly positive on max-sac since
max-sac also uses unique source accounts per tx and the same Soroban-only
phase shape).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2302-2440` —
  `LedgerManagerImpl::processFeesSeqNums`. Add a fast-path branch
  that detects (a) `ledgerCloseMeta == nullptr` and (b) all txs in
  the phase satisfy `tx->isSoroban()`. Inside the fast path, replace
  the serial inner loop with a partition + `std::async` dispatch into
  `NUM_CLUSTERS` workers, then a deterministic-order merge.
- `src/transactions/TransactionFrame.cpp:1776-1817` —
  `processFeeSeqNum` body to be replicated against a detached
  `AccountEntry` copy. The implementation must remain authoritative;
  the parallel path is a refactoring of the data-flow, not a
  reimplementation of fee semantics.
- `src/transactions/ParallelApplyUtils.cpp:893-1001` — existing
  `ThreadParallelApplyLedgerState` shows the precedent pattern:
  detached entry maps owned by workers, with sequential commit-back
  on the apply thread. Reuse the same shape for fee work items.
- `src/ledger/LedgerManagerImpl.cpp:2238-2280` —
  `copyApplyLedgerStateSnapshot` is already constructed once per
  ledger; the source-account snapshot reads happen against that
  snapshot, not the live LTX, so the apply-thread pre-load step can
  use the existing snapshot.
- `src/simulation/ApplyLoad.cpp:3395-3407` — confirms unique source
  account per soroswap tx (key-disjointness is structural).

## Evidence

- Tracy: `processFeesSeqNums` self = 270 ms across 65 calls (4.15 ms/ledger)
  in the current accepted trace
  (`/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`).
  This zone has its own `ZoneScoped` at line 2308 and is a direct
  descendant of `applyLedger` via `applyTransactions`.
- `applySorobanStageClustersInParallel` already proves the same
  workload is safely partitionable into `NUM_CLUSTERS` clusters
  for parallel execution; reusing the partitioning for fee
  processing reuses an already-validated parallel decomposition.
- The benchmark fast path runs with `DISABLE_TX_META_FOR_TESTING=true`,
  so `ledgerCloseMeta == nullptr` and the existing
  "operate directly on parent LTX" branch
  (`LedgerManagerImpl.cpp:2395-2399`) confirms there is no per-tx LCM
  fee-meta dependency for the optimized path. Production nodes that
  do collect meta fall through to the existing serial path with no
  behavior change.
- The reviewer of the prior fail explicitly proposed this exact
  alternative ("workers could operate on detached copies of
  fee-source account entries plus an immutable header snapshot,
  produce per-tx fee-charged results and per-account updated
  entries indexed by original apply order, and return only data")
  but did not promote it to a new hypothesis. This file picks up
  that direction.

## Anti-Evidence

- The 6.2% Tracy share is the upper bound assuming perfect
  parallelism. Realistic gain depends on:
  (a) detached `AccountEntry` copy cost per tx (one
  `loadWithoutRecord(accountKey)` + `LedgerEntry` clone per tx; the
  source account is already cache-hot from `prefetchTxSourceIds`);
  (b) merge-back cost on the apply thread (one LTX write per tx;
  this is a strictly *smaller* operation than the current serial
  `processFeeSeqNum` because no header reload or fee-pool update is
  done per tx); (c) thread-launch overhead (`NUM_CLUSTERS = 8`
  std::async launches, amortized per-ledger). PoC must benchmark
  end-to-end to confirm the win clears the Medium 3% threshold and
  is reproducible across ≥3 runs.
- For workloads with `ledgerCloseMeta != nullptr` (production
  nodes), the optimization is gated off and the existing serial
  per-tx-child-LTX path runs unchanged. This means the optimization
  does not regress any production behavior, but it also will not
  appear in non-`DISABLE_TX_META_FOR_TESTING` benchmarks.
- For mixed phases (classic + Soroban together), the gate
  `tx->isSoroban()` for ALL txs in the phase falls through to the
  existing serial path. Soroswap and max-sac both run pure-Soroban
  phases, so the optimization applies to both target benchmarks.
- Fee-bump txs (`FeeBumpTransactionFrame::processFeeSeqNum`,
  `src/transactions/FeeBumpTransactionFrame.cpp:764-795`) are not
  exercised by soroswap or max-sac, but a defensive gate
  (`!tx->isFeeBump()`) inside the fast-path detection prevents
  unintended fast-path entry for any future workload that mixes
  fee-bumps into a Soroban phase.
- The detached-copy path consumes additional transient memory
  (one `AccountEntry` per tx; ~200 bytes × 4036 = ~800 KB peak per
  ledger). This is well within bench harness limits and is freed
  immediately after the merge step.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in soroban fail/success records
**Failed At**: reviewer

### Trace Summary

`applyLedger` prefetches fee-source keys, then calls `processFeesSeqNums`, which currently iterates transactions in apply order and calls `TransactionFrame::processFeeSeqNum` on the apply thread. For metadata-disabled benchmark runs, the code mutates the parent `LedgerTxn` directly, charges `min(balance, fee)`, updates `header.feePool`, and records a `MutableTransactionResult` whose `feeCharged` is later hashed into the transaction result set. The soroswap generator does use a unique source account per generated swap, but the proposed fast-path eligibility condition is only `ledgerCloseMeta == nullptr && all txs are Soroban`, which does not prove fee-source disjointness for general Soroban phases.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches source accounts, then calls `processFeesSeqNums` before `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2302-2440` — `processFeesSeqNums` walks phases and transactions in apply order, uses direct parent-LTX mutation when `ledgerCloseMeta == nullptr`, and only skips merge-op tracking for Soroban txs.
- `src/transactions/TransactionFrame.cpp:1776-1817` — `processFeeSeqNum` loads the source account, computes `fee = min(acc.balance, getFee(...))`, subtracts the balance, increments `header.feePool`, and returns a success result carrying that exact charged fee.
- `src/transactions/MutableTransactionResult.cpp:250-255` — success result construction stores the charged fee in `mTxResult.feeCharged`, so per-transaction fee distribution is observable in ledger results, not just the aggregate fee-pool sum.
- `src/herder/TxSetFrame.h:482-492` — apply order is deterministic, but the txset API does not imply that all transactions in a Soroban phase have unique source accounts.
- `src/transactions/TransactionFrame.cpp:2026-2030` and `src/transactions/FeeBumpTransactionFrame.cpp:750-754` — fee-processing prefetch keys include source/fee-source accounts; uniqueness is not asserted by the fee-processing interface.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap benchmark generation does create one fresh account per swap, making the benchmark shape disjoint, but this is a benchmark-specific property.
- `src/ledger/LedgerTxn.h:628-640,642-660` and `src/ledger/LedgerTxn.cpp:1939-1981` — normal online mutation requires `LedgerTxn::load`/`LedgerTxnEntry`; unsafe `updateWithoutLoading` exists but is explicitly discouraged for normal transaction processing.

### Why It Failed

The proposed correctness argument assumes that `tx->isSoroban()` implies independent fee-source accounts, but the production txset path does not enforce that. Two Soroban transactions from the same source account in the same phase must be charged in apply order because each transaction's `feeCharged` is stored in its `TransactionResult`; if the account balance is insufficient for the sum of fees, independent detached copies can produce the wrong per-transaction fee distribution even if the aggregate fee-pool delta is the same. A benchmark-specific observation from `generateSoroswapSwaps` is not a safe ledger-code precondition.

Even after adding a necessary unique-fee-source gate, the Medium performance claim is not established. Workers cannot mutate `LedgerTxn`, so the apply thread must still perform one normal `LedgerTxn::load`/entry update per source account during merge; preloading detached account copies either duplicates the current serial account-load work or only offloads cheap fee arithmetic and result allocation. The measured 4.15 ms/ledger zone is therefore an upper bound, and the remaining serial LedgerTxn write path makes the claimed 3-5% top-line apply-time reduction too speculative for this objective.

### Lesson Learned

For fee processing, deterministic apply order matters not only for final balances and `feePool`, but also for the per-transaction `feeCharged` values committed to the ledger result set. Any future parallel fee-processing hypothesis must first prove fee-source disjointness with an explicit runtime gate or preserve per-account sequential fee charging, and must separately quantify how much of `processFeesSeqNums` remains serial due to required `LedgerTxn` mutation.
