# H006: Run `processPostTxSetApply` refund pass in parallel with `finalizeLedgerTxnChanges`

**Date**: 2026-05-24
**Subsystem**: ledger / post-apply refund + finalize
**Severity**: Medium (claimed); actually below threshold
**Impact**: Overlap the serial per-tx Soroban refund pass (`post_tx_set_apply`, ~3.07 ms / ledger) with the seal/bucket-list/in-memory-state finalize phase (`seal_and_bucket`, ~8.12 ms / ledger) by running them concurrently after `applySorobanStages`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After Soroban worker stages finish and the global parallel state has been
committed back to `ltx` (`commitChangesToLedgerTxn`), the close path does two
independent things on the main thread:
1. `processPostTxSetApply` walks every Soroban tx and calls
   `TransactionFrame::processRefund` (Soroban resource-fee refund). This
   credits the fee source account in `ltx` and emits a refund event.
2. `sealLedgerTxnAndStoreInBucketsAndDB` →
   `finalizeLedgerTxnChanges` runs eviction scan, hot-archive batch (async),
   in-memory-state update (async), and `addLiveBatch` (the dominant serial
   step).

In principle, if the refund pass operates on the same `ltx` that
`finalizeLedgerTxnChanges` later snapshots, the refund work could overlap a
prefix of the finalize work that does not depend on the post-refund ltx state
(e.g., the eviction scan, which reads pre-refund modified keys; or it could
start while the async hot-archive/in-memory tasks run).

## Mechanism

Currently the order is strictly serial:
`applySorobanStages` → `processPostTxSetApply` (post_tx_set_apply = 3.07 ms)
→ `sealLedgerTxnAndStoreInBucketsAndDB` (seal_and_bucket = 8.12 ms). With
overlap, refund processing could run on a worker thread while the main
thread starts finalize, recovering up to 3.07 ms of wall-clock.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8 — every Soroban tx
generates a refund (declared fee > consumed fee), and `processPostTxSetApply`
iterates serially over the parallel phase's stages.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2925` — `processPostTxSetApply` call
  immediately after the parallel apply loop.
- `src/ledger/LedgerManagerImpl.cpp:3094-3140` —
  `LedgerManagerImpl::processPostTxSetApply`, the serial per-tx refund loop.
- `src/transactions/TransactionFrame.cpp:2782-2820` —
  `TransactionFrame::processPostTxSetApply` → `processRefund` →
  `refundSorobanFee` (credits fee source account in `ltx`).
- `src/ledger/LedgerManagerImpl.cpp:3222-3370` — `finalizeLedgerTxnChanges`,
  the seal/bucket-list/in-memory-state finalize that immediately follows.

## Evidence

- soroswap apply-load p50 phase breakdown shows
  `post_tx_set_apply = 3.07 ms` (1.4% of 213.6 ms close), entirely serial,
  on the main thread, immediately preceding `seal_and_bucket = 8.12 ms`
  (also on the main thread but with `hotArchiveBatch` and
  `updateInMemorySorobanState` already launched as `std::async` futures).
- The combined window is ~11 ms (5.2% of close); overlap could in theory
  recover the refund cost.

## Anti-Evidence

- **`processRefund` mutates `ltx`** (credits fee source account, emits fee
  events, modifies `MutableTransactionResultBase`). `finalizeLedgerTxnChanges`
  reads from the same `ltx`: it calls `getAllEntries(initEntries, liveEntries,
  deadEntries)` which seals the ltx and snapshots all modified entries. Running
  the refund pass concurrently with finalize would create a race on the
  `ltx` write set — finalize could capture a partial set of refund credits,
  producing a non-deterministic ledger output. `AbstractLedgerTxn` has only one
  active child (Meta-Pattern #5 from fail/ledger), so the refund pass cannot be
  safely walled into a child ltx in parallel with the finalize step that itself
  needs an unaffected parent ltx view.
- Even if we restructured to do the entire refund pass FIRST and then start
  finalize, that is what the code already does. The only overlap window is
  with the async sub-tasks inside finalize (`addHotArchiveBatch`,
  `updateInMemorySorobanState`) — but those need the post-refund ltx state
  via `evictedState`/`initEntries`/`liveEntries`/`deadEntries`, all gathered
  AFTER refund processing completes. So there is no real overlap available.
- Refunds also modify fee-source account balances which downstream `addLiveBatch`
  hashes into the bucket. Any reordering that allows finalize to capture
  pre-refund entries would change ledger hashes — out of scope (determinism).
- The 3.07 ms ceiling is already below the 3% Medium floor (1.4% of close),
  so even if a hypothetical determinism-preserving overlap existed, the
  ceiling alone disqualifies the hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — overlap of `processPostTxSetApply` with `finalizeLedgerTxnChanges`
not previously investigated; nearest neighbor is
`fail/ledger/020-short-circuit-post-txset-apply.md` (which proposed to skip
post-tx-set-apply entirely, rejected on semantic grounds), and
`fail/ledger/013-async-addlivebatch-overlap-in-finalize.md` (which addressed
overlap *inside* finalize). The "run refund concurrently with finalize" angle
is new but blocked by the same architectural constraints.

### Why It Failed

Two independent blockers:
1. **Ceiling**: `post_tx_set_apply` is 1.4% of soroswap close time — below
   the 3% Medium floor even with full elimination. The objective explicitly
   rejects Low-tier (<3%) hypotheses at hypothesis stage.
2. **Architectural**: Refund processing mutates the same `AbstractLedgerTxn`
   that `finalizeLedgerTxnChanges` immediately snapshots via `getAllEntries`.
   `AbstractLedgerTxn` permits only a single writer/child (Meta-Pattern #5),
   so refund cannot be partitioned into a sibling ltx running in parallel
   with finalize without violating ledger determinism. The async sub-tasks
   *inside* finalize (`addHotArchiveBatch`, `updateInMemorySorobanState`)
   all depend on the post-refund entry set computed after `getAllEntries`,
   so there is no determinism-safe window for the overlap.

### Lesson Learned

Any "overlap phase X with phase Y" hypothesis on the apply path must (a) clear
the Medium severity floor *before* design work and (b) prove the two phases
genuinely read/write disjoint state. For ledger-close phases that all funnel
through the same `AbstractLedgerTxn`, the single-writer rule effectively
serializes the work even when wall-clock timing suggests independence. Future
hypotheses targeting refund work should look at *reducing per-tx refund cost*
(e.g., shared SAC fee-source caching) rather than overlapping the phase with
adjacent finalize work.
