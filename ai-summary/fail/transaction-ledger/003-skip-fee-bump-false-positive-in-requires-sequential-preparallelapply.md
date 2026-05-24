# H003: Eliminate False-Positive Sequential Routing in `requiresSequentialPreParallelApply` Caused by `processFeesSeqNums` Fee/Seq-Num Bumps

**Date**: 2026-05-24
**Subsystem**: transaction-ledger
**Severity**: Medium (initial projection) — re-sized to Low (sub-1.6 ms/ledger ceiling) on review
**Impact**: parallelize-serial-pre-apply-phase
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For p26 soroswap-shaped ledgers (≈2000 Soroban-only txs, no classic ops),
`preParallelApplyAndCollectModifiedClassicEntries` in
`ParallelApplyUtils.cpp` should be able to route the vast majority of
txs through the parallel `readOnlyPreParallelApply` path (which fans
out across `LEDGER_CLOSE_WORKER_THREADS` workers, see
`ParallelApplyUtils.cpp:526-583`) and only a small minority through
the sequential `preParallelApply` path. The sequential path's purpose
is to handle txs whose read footprint touches classic entries that
*another tx in the same parallel pre-apply phase* may have just
mutated; benign mutations introduced by an earlier *apply-phase*
(specifically the fee charge + seq-num bump applied by
`processFeesSeqNums`) should not force a tx into the sequential path,
because those modifications are already visible identically to every
worker thread reading from the post-fee LedgerTxn snapshot.

## Mechanism

`requiresSequentialPreParallelApply` (ParallelApplyUtils.cpp:170-204)
compares the current `ltx` snapshot against `LCLSnapshot` (previous
ledger's published state) via `isModifiedClassicKey`. For soroswap,
every tx's fee source account was modified earlier in
`applyLedger` by `processFeesSeqNums` (LedgerManagerImpl.cpp:2308):
fee charged + seq-num bumped. Therefore
`isModifiedClassicKey(current, previous, accountKey(tx.getFeeSourceID()))`
returns true for **every** soroswap tx, and the routing check at
ParallelApplyUtils.cpp:450 hits the sequential
`preParallelApply` branch for the entire ledger. The parallel
`readOnlyPreParallelApply` path that exists explicitly for p26 is
therefore *never exercised* on the soroswap benchmark — all
≈2000 txs/ledger × Tracy-measured ~10.9 µs each go through the
serial path on the apply thread.

A snapshot-comparison fix (compare against a snapshot taken
*after* `processFeesSeqNums` rather than against `LCLSnapshot`, or
filter the comparison to exclude fee-bump-only modifications) would
let every soroswap tx use the parallel readOnly path while preserving
correctness — the workers all read the same post-fee state.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap workload with
LEDGER_CLOSE_WORKER_THREADS=8. Add a counter in
`preParallelApplyAndCollectModifiedClassicEntries` to log the count
of txs taking the sequential branch vs the `txBundles` (parallel-
candidate) branch; the sequential count will equal the ledger's
total tx count and the parallel branch will be empty.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:170-204`
  `requiresSequentialPreParallelApply` — the false-positive check
- `src/transactions/ParallelApplyUtils.cpp:431-468`
  `preParallelApplyAndCollectModifiedClassicEntries` p26 branch — the
  router that consumes the false positive
- `src/transactions/ParallelApplyUtils.cpp:526-583`
  `readOnlyPreParallelApply` — the parallel path that is bypassed
- `src/ledger/LedgerManagerImpl.cpp:2308`
  `processFeesSeqNums` — the earlier apply phase whose benign
  modifications cause the false positive

## Evidence

- Soroswap Tracy `preParallelApply` zone = 175 ms aggregate / 72
  ledgers = 2.43 ms/ledger sequential on apply thread.
- Per-call Tracy mean ~10.9 µs × 2000 calls/ledger matches the
  aggregate, confirming serial dispatch.
- p26 added the split `preParallelApplyReadOnly` /
  `preParallelApplyWrite` design specifically so the read-only
  portion could be parallelized via `readOnlyPreParallelApply` —
  the infrastructure exists but is dead code on this workload.
- Fee-bump-only modifications are deterministic; every cluster
  worker reading from `ltx` after `processFeesSeqNums` sees the
  same state, so there is no read-modify-write hazard within the
  parallel readOnly phase.

## Anti-Evidence

- Apply-thread-side ceiling: 2.43 ms/ledger × 0.85 readOnly fraction
  ÷ 8 workers + 0.15 sequential writes + std::async dispatch
  overhead (~0.5 ms for 8 launches) ≈ 1.13 ms/ledger residual.
  Savings ceiling = 2.43 − 1.13 = **~1.30 ms/ledger ≈ 0.62% of
  211 ms soroswap baseline**.
- The same structural ceiling was independently identified by
  fail H005 (`005-fold-preparallelapply-readonly-into-cluster-workers.md`)
  which fixed the ceiling at ≈1.6 ms/ledger.
- The sibling H003
  (`003-precompute-modified-classic-keys-for-soroban-setup.md`)
  has already targeted the same serial pre-apply zone via a
  different mechanism (faster per-tx scan) and PoC'd; even with
  PoC-measured improvements, both this hypothesis and H005 sit
  below the 3% Medium floor on a critical-path basis.
- Modifying the snapshot semantics of
  `requiresSequentialPreParallelApply` is non-trivial: the function
  also checks the readOnly/readWrite footprint keys, so the fix
  must preserve those legitimate hazard detections while only
  filtering fee/seq-num bumps. Implementation risk is moderate
  for a sub-Low payoff.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H003 (scan-precompute) and H005
(fold-into-cluster-workers); this targets the *false-positive
classification* rather than the scan cost or the consumer location

### Why It Failed

Even with a perfect fix that routes 100% of soroswap txs through the
parallel `readOnlyPreParallelApply` path and respects the
LEDGER_CLOSE_WORKER_THREADS cap, the recoverable critical-path
savings are bounded by the size of the serial `preParallelApply`
zone itself (≈2.43 ms/ledger). After deducting the unavoidable
sequential write-phase residual (`commitBufferedPreParallelApplyWrites`),
std::async fan-out overhead, and assuming an ideal 8-way split,
the ceiling sits at ~1.30 ms/ledger ≈ 0.62% of baseline — below
the objective's 1% Low floor, far below the 3% Medium floor that
this stage requires.

Meta-pattern 6 (aggregate vs critical-path) and the explicit
ceiling derived by fail H005
(`005-fold-preparallelapply-readonly-into-cluster-workers.md`)
both apply: a serial pre-cluster zone of size *X* ms/ledger
cannot be reduced below *X/T + overhead* by *T*-way
parallelization, and for the soroswap `preParallelApply` zone
this ceiling is sub-Low regardless of the mechanism used to
unlock the parallel path.

### Lesson Learned

When an existing parallel infrastructure (here,
`readOnlyPreParallelApply`) appears to be "dead code on this
workload" due to a classification check (here,
`requiresSequentialPreParallelApply`), the maximum recoverable
savings is still bounded by the serial zone the parallel path
would replace. Re-derive the ceiling before proposing a fix
to the classifier — and reject if the underlying serial zone
is already sub-threshold (as is the case for the apply-thread
`preParallelApply` zone after the H005 ceiling analysis).
