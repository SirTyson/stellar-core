# H005 (self-rejected): Pre-compute Modified-Classic-Keys Set to Eliminate Per-Tx LedgerSnapshot Loads in requiresSequentialPreParallelApply

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: High (projected)
**Impact**: ~10% of close time (soroban_setup_glbl reduction)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When deciding whether each Soroban transaction must take the sequential
pre-apply path (because a classic footprint/source key was modified earlier
in the same ledger), the routing decision should be O(footprint) hash
lookups against a small pre-built "modified-this-ledger classic keys" set
constructed once per ledger.

## Mechanism

`requiresSequentialPreParallelApply` (`src/transactions/ParallelApplyUtils.cpp:171`)
is called for every Soroban tx and performs two `LedgerSnapshot::load()`
calls per classic footprint key, with no caching. Instrumented Tracy
sub-zones inside `soroban_setup_glbl` sum to only ~3 ms but the phase total
is ~24.4 ms; the missing ~21 ms is in this un-instrumented loop. A
pre-built modified-keys set would collapse this to <1 ms.

## Trigger

Run soroswap apply-load benchmark (`tx=2000, t=8`); the phase consistently
measures 22–26 ms in the per-run breakdown log.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:151-208` — isModifiedClassicKey and requiresSequentialPreParallelApply
- `src/transactions/ParallelApplyUtils.cpp:431-468` — preParallelApplyAndCollectModifiedClassicEntries V_26+ branch
- `src/transactions/ParallelApplyUtils.cpp:386-429` — GlobalParallelApplyLedgerState constructor

## Evidence

- Tracy csvexport on the current soroswap trace: instrumented sub-zones in
  `soroban_setup_glbl` (preParallelApply 2.43 ms, collectModified 0.34 ms,
  fetchSorobanRO 0.13 ms) account for ~3 ms; phase total ~24.4 ms.
- Breakdown log: `soroban_setup_glbl 24.40 ms (~11% of close)`.
- `readOnlyPreParallelApply` 73 ns/call and `commitBufferedPreParallelApplyWrites`
  25 ns/call confirm 100% of soroswap txs take the sequential path because
  every tx has its source/fee/trustline footprint modified by earlier txs.

## Anti-Evidence

`LedgerSnapshot::load` may be cheaper than estimated if LedgerTxn hash-map
hits are dominant; even so the saving is structurally Medium-tier.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (duplicate of prior viable PoC)
**Novelty**: FAIL — duplicate of failed hypothesis
`003-precompute-modified-classic-keys-for-soroban-setup.md +
002-precompute-modified-classic-keys-set.md` per
`ai-summary/fail/transaction-ledger/summary.md`. That prior attempt was
technically viable (the PoC source change exists) but failed at the
final-review stage because the working-tree change was not committed to
the handoff branch and the p26 submodule was still at baseline. The
underlying optimization design is identical; re-proposing it here would
be a duplicate.

### Why It Failed

The optimization itself is sound, but the hypothesis pipeline already
recorded it as attempted. The correct path forward is for the orchestrator
to re-handoff the previously-built PoC with a clean commit on both the
outer branch and the p26 submodule, not to re-generate the same hypothesis.

### Lesson Learned

When a hypothesis's only failure mode is a procedural handoff issue
(uncommitted PoC, missing submodule bump) rather than a technical
rejection, the orchestrator should re-run the PoC stage on the existing
design rather than expect a new hypothesis. Hypothesis-agent inspection
of the fail summary's "Failed At" column distinguishes
procedural-handoff failures from technical rejections.
