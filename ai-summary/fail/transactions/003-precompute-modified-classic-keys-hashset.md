# H003: Precompute Modified-Classic-Keys Hashset for requiresSequentialPreParallelApply

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Low
**Impact**: Minor reduction in pre-parallel-apply serial setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`preParallelApplyAndCollectModifiedClassicEntries` should classify each Soroban
tx as "needs sequential pre-apply" or "safe for read-only parallel pre-apply"
in O(footprint) per tx, with no per-key snapshot loads. It should perform
exactly one pass over the LedgerTxn delta to materialize the set of
classic-entry keys modified since LCL (by `processFeesSeqNums` etc.), then
test each tx's source/fee-source/op-source/footprint keys against that
hashset.

## Mechanism

Today `requiresSequentialPreParallelApply`
(`src/transactions/ParallelApplyUtils.cpp:171-208`) calls
`isModifiedClassicKey` (lines 152-168) for each candidate key, and
`isModifiedClassicKey` does **two ledger snapshot loads per key**: one against
the `current` LedgerSnapshot wrapping the live ltx, one against the
`previous` LedgerSnapshot wrapping `mLCLSnapshot`. For every Soroban tx this
is at minimum 2 (source) + 2 (fee source) + 2*N_ops + 2*|RO footprint| + 2*|RW
footprint| snapshot loads, all on the serial main thread before parallel
apply launches. A precomputed hashset of modified classic keys would replace
each load pair with a single `unordered_set::find` call. The expected gain
would be the reduction of LedgerTxn parent-chain traversals and bucket
snapshot lookups on a known-serial path inside `applyLedger`.

## Trigger

Run apply-load with `--mode soroswap --txs 2000`. Every Soroban tx triggers
the per-key snapshot load loop. The cost scales with txs/ledger × footprint
size.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:152-208` —
  `isModifiedClassicKey` and `requiresSequentialPreParallelApply`.
- `src/transactions/ParallelApplyUtils.cpp:431-523` —
  `preParallelApplyAndCollectModifiedClassicEntries` calls the above per tx.
- `src/ledger/LedgerTxn.cpp` — `getDelta()` exposes the modified entries for
  precomputation.

## Evidence

- Per-tx loop with multiple snapshot loads is structurally O(footprint) per
  tx with a non-trivial constant (BucketListSnapshot lookups are ~4.5us
  in the trace: `load,bucket/BucketListSnapshot.cpp,317` → 2278M ns over
  509k calls).
- Soroswap fee processing modifies every tx's fee-source account, so every
  tx hits the first `isModifiedClassicKey` check and the result is always
  "true" — the per-footprint loop is dead work for soroswap, but still
  pays the cost of two snapshot loads on the source/fee-source check
  itself.

## Anti-Evidence (why it's NOT viable for this objective)

Tracy zone measurements show the entire pre-parallel-apply serial section
is well under the Medium threshold:

- `preParallelApply,transactions/TransactionFrame.cpp,2359` —
  148ms total / 70 ledgers = **2.1ms/ledger / ~280ms close = 0.75%** of
  benchmark close time.
- `preParallelApplyReadOnly` — 115ms / 70 = 1.6ms/ledger = 0.6%.
- `collectModifiedClassicEntries` — 18ms / 70 = 0.26ms/ledger = 0.09%.
- The unzoned `requiresSequentialPreParallelApply` work happens in the
  parent `applyParallelPhase` self-time: `applyParallelPhase` (3726ms)
  − `applySorobanStages` (3720ms) ≈ 6ms total / 70 = 0.09ms/ledger.

The total addressable surface — even if eliminated entirely — is on the
order of 0.5–1% of close time. That places this firmly in the Low band
(1–3%), and possibly below the 1% benchmark-noise floor entirely.

The objective explicitly excludes Low-tier hypotheses
("Minimum severity: Medium ... If your projected impact is Low (1–3% apply
time reduction), do not write the hypothesis to ai-summary/hypothesis/
— write it to ai-summary/fail/").

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from fail/001
(parallelize-thread-state-setup) which targeted ThreadParallelApplyLedgerState
construction, and from fail/003 (preparallel-validation-fast-path) which
proposed a Tracy-trap zone outside `applyLedger`.

### Why It Failed

Below objective severity threshold. The total time spent across all
zones touched by this optimization (`preParallelApply` + nephews +
`requiresSequentialPreParallelApply` self-time) is under 3% of soroswap
close time, so even a 100% elimination cannot reach Medium (3–10%).
A more realistic fraction — replacing snapshot loads with hash lookups
shaves perhaps half the cost — projects under 1% wall-clock impact,
inside benchmark noise.

### Lesson Learned

When evaluating a per-tx-loop optimization in the pre-parallel-apply
phase, sum up ALL of (a) the zoned children plus (b) the parent's
self-time delta (`applyParallelPhase` − `applySorobanStages`). If the
combined budget is under ~3% of close time, the change cannot reach
Medium severity even under perfect-elimination assumptions, and should
be filed as Low/fail rather than promoted to hypothesis.
