# H047: Share one `LedgerSnapshot ls(ltx)` across all txs in the serial pre-parallel-apply loop

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / serial pre-parallel-apply phase
**Severity**: Low
**Impact**: Sub-noise — projected ≤ 0.5 ms/ledger critical-path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In the v26+ serial pre-parallel-apply loop in
`GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`
(`src/transactions/ParallelApplyUtils.cpp:443-462`), each Soroban transaction
that requires sequential pre-apply (`requiresSequentialPreParallelApply == true`)
calls `TransactionFrame::preParallelApply`, which internally constructs a fresh
`LedgerSnapshot ls(ltx)` per tx
(`src/transactions/TransactionFrame.cpp:2367`). The expected efficient path is
to construct one read-side `LedgerSnapshot` once at the top of the serial
pre-apply loop (the same place that already constructs `LedgerSnapshot
current(ltx)` and `LedgerSnapshot previous(mLCLSnapshot)` for
`requiresSequentialPreParallelApply`) and reuse it across every tx's
`preParallelApplyReadOnly` call, since `ltx` is not mutated between iterations
for the read-only check.

## Mechanism

`LedgerSnapshot::LedgerSnapshot(AbstractLedgerTxn&)` constructs a
`LedgerTxnReadOnly` wrapper plus a `LedgerHeaderWrapper`. Each construction
allocates the read-only adapter object on the stack but also performs a
`loadHeader()` call into the LedgerTxn, which crosses into the LedgerTxn `Impl`
hot path and acquires a transient handle. The actual deviation from the
expected behavior is that on every tx in the serial pre-apply phase, we
re-instantiate this wrapper rather than passing the once-built snapshot
into the per-tx call sites that already exist in
`commonParallelPreApplyReadOnly`.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.
The serial pre-apply loop iterates every tx in the parallel-stage tx set and
constructs a new `LedgerSnapshot` per tx for the read-only `commonValid` /
`processSignaturesReadOnly` calls. For a soroswap ledger with ~250 txs, this is
~250 redundant `LedgerSnapshot` constructions.

## Target Code

- `src/transactions/TransactionFrame.cpp:2362-2370` —
  `TransactionFrame::preParallelApply` constructs `LedgerSnapshot ls(ltx)` per tx
- `src/transactions/ParallelApplyUtils.cpp:443-462` — serial pre-apply loop
- `src/transactions/FeeBumpTransactionFrame.cpp:94` — same pattern on fee-bump path

## Evidence

- Per-tx `LedgerSnapshot` construction is structurally redundant across all txs
  in the serial pre-parallel-apply loop, since `ltx` is not mutated between
  iterations during the read-only phase (writes are buffered into
  `ParallelPreApplyInfo` and committed only later, in
  `commitBufferedPreParallelApplyWrites`).
- The serial pre-apply loop is on the apply-thread critical path before the
  parallel cluster phase can start.

## Anti-Evidence

- `LedgerSnapshot` is a thin stack object; its constructor performs no heap
  allocation in the common path — it stores a `LedgerSnapshotBackend` variant
  containing a `LedgerTxnReadOnly` view.
- The Tracy `preParallelApply` zone aggregate is 166 ms across the full
  soroswap trace (≈ 2.3 ms/ledger across the 71-ledger trace, or ≈ 3-4
  ms/hot-ledger), of which only a tiny fraction is the `LedgerSnapshot ls(ltx)`
  construction itself; the bulk is `commonValid` + signature checking.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `005-eliminate-per-tx-child-ltx-in-fees-seqnums.md`
(which targets `LedgerTxn` child construction in `processFeesSeqNums`, not
`LedgerSnapshot` in `preParallelApply`) and from
`003-precompute-modified-classic-keys-for-soroban-setup.md` (which precomputes
the modified-classic-keys set, not the per-tx LedgerSnapshot adapter).

### Why It Failed

Sizing against the Medium 3% floor (≈ 8.2 ms/ledger on the 272 ms soroswap
baseline):

- The full `preParallelApply` Tracy zone is ≈ 2.34 ms/ledger across the soroswap
  trace (166 ms / 71 ledgers). Even fully eliminating the zone is sub-Low
  (0.86%), below the 1% noise floor.
- `LedgerSnapshot::LedgerSnapshot(AbstractLedgerTxn&)` is a stack-only
  constructor that wraps `ltx` in a `LedgerTxnReadOnly` view and grabs a
  `LedgerHeaderWrapper`. There is no heap allocation in the common path; the
  per-call cost is dominated by `loadHeader()` (already lazily cached on the
  innermost `LedgerTxn::Impl`).
- Per-tx removable cost upper bound: ≈ 100-200 ns per
  `LedgerSnapshot` reconstruction × ~250 txs/hot-ledger = 25-50 µs/ledger.
  That is 0.01-0.02% of apply time — three to four orders of magnitude below
  the Medium floor.
- The optimization also requires changing the `preParallelApply` /
  `preParallelApplyReadOnly` signatures to accept an externally-constructed
  `LedgerSnapshot` reference, which propagates through `TransactionFrame`,
  `FeeBumpTransactionFrame`, and the
  `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries`
  call site. The review burden is disproportionate to the sub-noise saving.

### Lesson Learned

Per-tx `LedgerSnapshot ls(ltx)` constructions in the serial pre-parallel-apply
phase are essentially free (stack-only, lazily-cached header). The dominant
cost in this region is `commonValid` and signature processing inside
`commonParallelPreApplyReadOnly`, both already covered by prior failed
hypotheses. Future optimizations to the serial pre-parallel-apply window must
target either `commonValid`/`checkAllTransactionSignatures` *inside* the apply
window (not TX-set construction), or move further along (i.e. fold work into
the parallel workers), since the whole pre-apply window is bounded under ~3
ms/ledger.
