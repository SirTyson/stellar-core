# H003: Eliminate sort+copy overhead in `convertToBucketEntry` during level-0 ingestion

**Date**: 2026-05-23
**Subsystem**: ledger / bucket
**Severity**: Low
**Impact**: Bucket-list level-0 ingestion CPU
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each ledger, the apply path takes the unsorted `initEntries`, `liveEntries`, and `deadEntries` vectors produced by `LedgerTxn::getAllEntries()`, sorts them by ledger-entry id, materializes a `std::vector<BucketEntry>` for the snap bucket, and then merges that snap into the level-0 curr bucket. Producing this snap should not require an allocation pass for ref pointers, a full sort, and a second pass that XDR-copies every `LedgerEntry` into a freshly default-constructed `BucketEntry`. The end state should be: a snap bucket whose in-memory `BucketEntry` list is byte-identical to today's, ready to feed `mergeInMemory`.

## Mechanism

`convertToBucketEntry` (bucket/LiveBucket.cpp:381) builds a temporary `std::vector<EntryRef>` of small `{type, livePtr, deadPtr}` triples covering all init/live/dead entries, sorts it with `LedgerEntryIdCmp` via pointer-indirect comparisons, then walks the sorted refs and emplaces a default `BucketEntry` into the output vector and assigns `ce.liveEntry() = *r.livePtr;` (or `ce.deadEntry() = *r.deadPtr;`) for each entry. The XDR copy of `LedgerEntry` is non-trivial (it contains nested `xdr::xvector` of asset/issuer/ContractData fields and a sponsorship array). The hypothesis was that a fused single-pass that swaps `LedgerEntry` into `BucketEntry::liveEntry()` via move (the input vectors are about to be discarded by `sealLedgerTxnAndStoreInBucketsAndDB`) plus an in-place sort over `BucketEntry` indices could remove one allocation pass and one round of XDR copies.

## Trigger

Run `scripts/run_apply_load_matrix.py` for the soroswap workload and inspect the trace under `applyLedger -> finalizeLedgerTxnChanges -> addLiveBatch -> addBatchInternal -> prepareFirstLevel -> freshInMemoryOnly -> convertToBucketEntry`. Every ledger close that ingests entries into the live BucketList exercises this path.

## Target Code

- `src/bucket/LiveBucket.cpp:381-484` — `convertToBucketEntry` two-pass build (refs sort + materialize).
- `src/bucket/LiveBucket.cpp:531-560` — `freshInMemoryOnly` invokes `convertToBucketEntry` and wraps the result.
- `src/bucket/BucketListBase.cpp:202-238` — `BucketLevel<LiveBucket>::prepareFirstLevel` calls `freshInMemoryOnly` and feeds the result to `mergeInMemory`.

## Evidence

`convertToBucketEntry` appears in the diagnostic Tracy trace with a real `ZoneScoped` self-time and is structurally a sort-then-copy pipeline that is run synchronously on every apply.

## Anti-Evidence

Quantified from the current diagnostic Tracy trace
(`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`):

- `convertToBucketEntry` total: 38,301,381 ns across 72 calls
  ≈ 0.53 ms/ledger
- `freshInMemoryOnly`: 38,786,173 ns / 72
  ≈ 0.54 ms/ledger
  (essentially identical — `convertToBucketEntry` is the whole of it)
- `applyLedger` mean per call: 63 ms (4,475,605,676 ns / 71)
- Fraction of applyLedger: 0.53 / 63 ≈ 0.84%

Even a move-based fused single-pass implementation can at best halve this — bounded by ~0.27 ms/ledger ≈ 0.43% of `applyLedger`. That is well below the 1% Low floor and three orders of magnitude below the Medium 3% floor for this objective. The dominant cost in level-0 ingestion remains the `mergeInMemory put loop` (XDR encode + SHA256 hash + file write at 1.06 ms/ledger) and `mergeInMemory merge` (0.28 ms/ledger), neither of which is removable by changing `convertToBucketEntry`'s representation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — `convertToBucketEntry` sort/materialize structure has not been targeted in prior fail entries; existing addLiveBatch failures (008 cache-encoded-bytes, 005 eliminate-merged-vector, 014 defer-bucket-write) all target the merge or write loop, not the pre-merge snap construction.

### Why It Failed

Below objective severity threshold. Quantified self-time of `convertToBucketEntry` is ≈0.53 ms/ledger (≈0.84% of `applyLedger`). Even an ideal move-based single-pass fusion is bounded above by ~0.43% of `applyLedger`, far below the 3% Medium floor (and below the 1% Low floor that this objective excludes anyway).

### Lesson Learned

The pre-merge snap construction in level-0 ingestion is a small fraction of `addLiveBatch` cost; the dominant `addLiveBatch` costs are inside `mergeInMemory` (put-loop XDR encode + SHA256 hash + file write), which are inherent to producing a canonical bucket file and not removable by upstream representation changes. Future ingestion-side hypotheses should target the put loop or the entire `addLiveBatch` critical path as a wholesale redesign rather than localized snap construction.
