# H004: Narrow `requiresSequentialPreParallelApply` Classifier Avoiding BucketList Loads via Fee-Modified Key Set

**Date**: 2026-05-23
**Subsystem**: soroban
**Severity**: Medium (claimed) → rejected to Low
**Impact**: Reduce serial pre-parallel-apply classifier cost on the soroswap path by replacing per-tx `LedgerSnapshot::load` against the LCL BucketList with O(1) lookups in a fee-modified key set.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban tx, the V_26+ classifier
`requiresSequentialPreParallelApply` decides whether the tx can take the
read-only pre-parallel-apply dispatcher path. The decision needs only to
know whether any classic account/key the tx touches has been *modified*
between LCL and the current `AbstractLedgerTxn`. After
`processFeesSeqNums`, the set of modified classic keys is exactly the set
of fee-source / source accounts whose sequence numbers or balances we just
mutated. A correct classifier should therefore answer in O(1) per key by
testing membership in this precomputed set, without ever calling
`LedgerSnapshot::load(key)` against the LCL bucket-list snapshot.

## Mechanism

The current implementation
(`src/transactions/ParallelApplyUtils.cpp:151..208` —
`isModifiedClassicKey` + `requiresSequentialPreParallelApply`) calls
`current.load(key)` and `previous.load(key)` for the source account, fee
source account, every op source, and every classic footprint entry. The
`previous` snapshot is a `LedgerSnapshot(mLCLSnapshot)` whose `load` goes
through `BucketSnapshotState::load` →
`SearchableBucketListSnapshot<LiveBucket>::load`
(`src/bucket/BucketListSnapshot.cpp:315`), walking every BucketList level
until the key is found. For soroswap this is invoked at
~3 account loads per tx × 2 (current+previous) ≈ 6 loads per tx ×
~2000 txs/ledger ≈ 12k loads per ledger of serial-thread work. The
hypothesis: precompute the fee-modified key set during
`processFeesSeqNums`, and replace `isModifiedClassicKey` with set
membership, eliminating the BucketList scans on the serial critical path.

## Trigger

Run the soroswap `run_apply_load_matrix.py` benchmark; in V_26+ apply,
every soroswap tx exercises `requiresSequentialPreParallelApply`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:151` — `isModifiedClassicKey`
- `src/transactions/ParallelApplyUtils.cpp:170` — `requiresSequentialPreParallelApply`
- `src/transactions/ParallelApplyUtils.cpp:432` — caller `preParallelApplyAndCollectModifiedClassicEntries`
- `src/bucket/BucketListSnapshot.cpp:315` — `load` per-call cost
- `src/ledger/LedgerStateSnapshot.cpp:225` — `BucketSnapshotState::load`

## Evidence

- Tracy zone `load` (BucketListSnapshot.cpp:317): 551,218 calls /
  234ms aggregate self / ~424ns each.
- Tracy zone `scan` (InMemoryIndex.cpp:253): 956,502 calls /
  2.245s aggregate self.
- The classifier is on the *serial* apply thread, before
  `applySorobanStageClustersInParallel` launches workers, so its cost
  is not amortized by NUM_CLUSTERS.

## Anti-Evidence

- Fail `ai-summary/fail/soroban/001-fused-soroban-fee-preapply-state.md`
  (reviewer rejection) measured the combined
  `processFeesSeqNums + serial preParallelApply` across 71 ledgers and
  found it normalizes below the 3% Medium floor against the authoritative
  ~218ms/ledger soroswap baseline. Since the classifier is a *strict
  subset* of that phase, its isolated wall-clock cost is necessarily
  below the same cap.
- The dominant `scan` / `load` Tracy counts come from worker-thread
  `addReads` and `storage get` paths (fails `004-xdr-bridge-serialization`
  and meta-pattern #12), not from the serial classifier. Attribution of
  the 426k account-shaped loads to the classifier was speculative.
- For soroswap source accounts, the `previous.load` likely hits the
  newest bucket level early (small bucket-level depth), so per-load cost
  is closer to a few hundred nanoseconds than the ~4µs aggregate average.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS (narrower than fail `001-fee-aware-preparallel-classic-diff`,
which targeted *path selection* after the classifier; this one targets the
*classifier's load cost itself*) but bounded by the same phase-total cap.

### Why It Failed

The wall-clock cost of `requiresSequentialPreParallelApply` is a strict
subset of the V_26+ serial pre-parallel-apply phase, whose total
(`processFeesSeqNums + serial preParallelApply` across 71 ledgers) was
already measured below the 3% Medium floor in fail
`001-fused-soroban-fee-preapply-state`. Optimizing only the classifier
cannot exceed that cap. Projected savings ≤1% — below the objective's
Medium threshold; "Low not accepted at hypothesis stage" for this
objective.

### Lesson Learned

Before promoting a "narrow" classifier-cost optimization, normalize
against the parent phase total established by prior fails. If the parent
phase is sub-Medium, no sub-phase optimization can clear Medium without a
new mechanism reaching beyond the phase boundary (e.g., eliminating the
phase entirely, not just speeding it up).
