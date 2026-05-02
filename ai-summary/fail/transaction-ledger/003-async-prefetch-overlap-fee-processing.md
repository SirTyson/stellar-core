# H003: Pipeline prefetchTransactionData asynchronously to overlap processFeesSeqNums and preParallelApply

**Date**: 2026-05-02
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: apply-time reduction via overlap of disk-bound prefetch with CPU-bound fee/seqnum work
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`closeLedger`'s sync setup chain currently runs strictly sequentially:
`prefetchTxSourceIds` → `processFeesSeqNums` → `prefetchTransactionData` →
`preParallelApply` → parallel apply. `prefetchTxSourceIds` only needs to
load source-account / fee-source AccountID rows so `processFeesSeqNums`
can charge fees and bump sequence numbers; `prefetchTransactionData`
loads the rest of every Soroban tx's footprint (TTLs, classic
trustlines, contract data not already in `InMemorySorobanState`) needed
later by `parallelApply`. Since `processFeesSeqNums` and
`preParallelApply` only read source/fee AccountIDs (already cached by
`prefetchTxSourceIds`) and write to ltx, the second prefetch's loads
are *independent* of those two phases. Correctly pipelining the
benchmark would launch `prefetchTransactionData` on a worker as soon as
`prefetchTxSourceIds` completes and let it run concurrently with
`processFeesSeqNums` + `preParallelApply`, joining before the parallel
apply phase.

## Mechanism

`LedgerTxnRoot::prefetchClassic` (called by `prefetchTransactionData` at
`LedgerManagerImpl.cpp:2468`) walks LiveBucket levels via
`loadKeysFromBucket`, doing `IndexT::scan` and disk reads when the bucket
isn't fully in memory. The Tracy trace shows `prefetchTransactionData`
self-time = 12.8ms / 71 ledgers ≈ 0.18ms/ledger and `prefetch` total
89.2ms / 142 calls (so the second prefetch is roughly half ≈ 44ms total
≈ 0.62ms/ledger). `processFeesSeqNums` self-time is 16.3ms total =
0.23ms/ledger and `preParallelApply` covers ~13767 calls totalling
1.69ms self + ~9.4ms write + 6.5ms readonly ≈ 17.6ms / 71 ≈
0.25ms/ledger. Maximum theoretical overlap savings = min(prefetch ≈
0.62ms, fees+pre ≈ 0.48ms) ≈ 0.5ms/ledger ≈ 0.7% of applyLedger
self+children (73ms/ledger). Even if the benchmark's apply window is
larger than Tracy applyLedger and the overlap fraction scales
proportionally, the absolute upper bound is well under 1.5% of the
278ms benchmark median.

## Trigger

Standard soroswap apply-load benchmark; effect would be visible as a
shift of `prefetchTransactionData` Tracy zone overlapping with
`processFeesSeqNums` + `preParallelApply` when running asynchronously.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2444-2480` — sync setup chain in
  `applyLedger` between `prefetchTxSourceIds`, `processFeesSeqNums`,
  `prefetchTransactionData`, `preParallelApply`.
- `src/ledger/LedgerTxn.cpp:3103` — `prefetch` zone implementation
  (LedgerTxnRoot::prefetchInternal) that would run on a worker.

## Evidence

- Tracy self-times (above) confirm the four sync phases sum to
  ~1.5ms/ledger and prefetchTransactionData is the largest component
  (~0.62ms/ledger of `prefetch` zone is its share).
- The two prefetched key sets are disjoint (source AccountIDs vs.
  full footprint keys), so asynchronous launch is logically safe.

## Anti-Evidence

- `LedgerTxnRoot::mEntryCache` is not designed for concurrent
  prefetch-write while `processFeesSeqNums` mutates ltx parent — would
  require either holding the prefetch results in a side buffer or
  adding a mutex around the cache, both adding overhead.
- The actual win is bounded by the smaller of the two phase durations
  and is a small fraction of apply time even in the optimistic case.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail/hypothesis/reviewed/poc dirs

### Why It Failed

Total combined sync-setup work for the four phases is roughly
1.5ms/ledger out of a 73ms/ledger applyLedger Tracy window (and out of
278ms benchmark median). The maximum overlap obtainable by pipelining
prefetchTransactionData with processFeesSeqNums + preParallelApply is
strictly less than the prefetch's own duration (~0.6ms/ledger), i.e.
< 1% of apply time — below the 3% Medium floor and within benchmark
noise. Adding the synchronization overhead and risking concurrent
writes into `LedgerTxnRoot`'s mEntryCache makes the cost-benefit
clearly negative.

### Lesson Learned

Sync-setup phases inside applyLedger (prefetch, fees, preParallelApply)
together account for under 2% of apply time on the soroswap benchmark.
Any future pipelining proposal in this region needs a reason the
expected critical-path savings exceed ~3ms/ledger, which is unlikely
given the absolute self-times.
