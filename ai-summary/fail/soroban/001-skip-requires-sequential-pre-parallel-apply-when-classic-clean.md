# H001: Short-Circuit `requiresSequentialPreParallelApply` When Classic Phase Made No Modifications

**Date**: 2026-05-22
**Subsystem**: soroban (parallel apply orchestration)
**Severity**: Low
**Impact**: Apply-path per-tx serial setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`requiresSequentialPreParallelApply`
(`src/transactions/ParallelApplyUtils.cpp:171-208`) is consulted serially
for every Soroban tx in the parallel phase to decide whether the tx must
go through the sequential pre-apply path
(`preParallelApplyAndCollectModifiedClassicEntries` at
`src/transactions/ParallelApplyUtils.cpp:431-523`) instead of the parallel
read-only fast path. For each tx it performs `LedgerSnapshot::load(key)`
in **both** `current` and `previous` snapshots for: the source account, the
fee source account, every operation source account, every readOnly
footprint key, and every readWrite footprint key. The function therefore
performs ~4–10 snapshot loads per Soroban tx.

For workloads where the preceding classic phase produced **zero**
modifications (soroswap's classic phase is empty by construction —
meta-pattern #7), no Soroban tx can possibly have its source/fee/op-source
or footprint key modified by classic apply. The check is guaranteed to
return `false` for every tx. The expected optimal behavior is a single
global "classic-phase made no modifications" flag computed once after
`applySequentialPhase`, short-circuiting all per-tx, per-key snapshot
probes.

## Mechanism

`isModifiedClassicKey` calls `current.load(key)` and `previous.load(key)`
for every probe. Each `LedgerSnapshot::load` translates to either an
`AbstractLedgerTxn::loadWithoutRecord` walk or a bucket-list snapshot
lookup, both of which compute a `LedgerKey` hash and probe one or more
maps. The per-tx serial cost is bounded but non-zero, and is paid even
when the answer is trivially `false`.

The proposed fix: in `preParallelApplyAndCollectModifiedClassicEntries`,
compute `bool anyClassicModified = (current.has_modified_classic_keys())`
once. If `false`, route every Soroban tx straight to
`readOnlyPreParallelApply` and skip the per-tx call to
`requiresSequentialPreParallelApply` entirely.

## Trigger

Soroswap apply-load run. All txs are Soroban, classic phase is empty,
every `requiresSequentialPreParallelApply` call returns `false` after
performing 4–10 snapshot probes.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:171-208` — `requiresSequentialPreParallelApply`
- `src/transactions/ParallelApplyUtils.cpp:431-523` — `preParallelApplyAndCollectModifiedClassicEntries`
- `src/ledger/AbstractLedgerTxn.{h,cpp}` — would need a cheap
  "modified-classic-keys-empty" query

## Evidence

Function reads source code show the per-tx probe count is real and
unavoidable in the current implementation. Trace confirms classic phase
is empty for soroswap (meta-pattern #7).

## Anti-Evidence

Tracy does not surface `preParallelApplyAndCollectModifiedClassicEntries`
or `requiresSequentialPreParallelApply` as instrumented zones; the only
way to measure the cost is via wall-clock timing. Bounding from the
enclosing `applySorobanStages` (3.72 s / 71 ledgers = 52.4 ms/ledger)
minus its dominant children `applySorobanStage` (3.49 s / 71 = 49.2
ms/ledger) and `applySorobanStageClustersInParallel` (3.43 s / 71 = 48.3
ms/ledger) leaves a serial-residual of at most ~3.2 ms/ledger that must
cover: stage setup, the entire `preParallelApplyAndCollectModifiedClassicEntries`
including `collectModifiedClassicEntries` global map preload work
(which is **necessary** even on the proposed fast path), result merging,
and any other serial work. The
`requiresSequentialPreParallelApply` calls themselves are a fraction of
that residual.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail summaries (the closest entry is
`fail/soroban/001-fused-soroban-fee-preapply-state` which targets fusing
fee+pre-apply state, not the dependency-check probe itself)

### Why It Failed

Total cost upper-bound is too small to clear the Low (1%) floor, let alone
Medium (3%):

  - 197 Soroban txs/ledger × ~5 probes/tx × 2 snapshots = ~1970 snapshot
    `load` calls/ledger devoted to dependency checking.
  - At ~500 ns per warm in-memory snapshot probe (the LCL snapshot for
    classic accounts is in-memory; the `current` LedgerTxn parent is
    also in-memory at this point), that is ~1 ms/ledger total.
  - 1 ms / 250 ms baseline = 0.4%, which is **below the 1% Low floor
    and far below the 3% Medium objective floor**.

Even an optimistic 5× per-probe cost estimate (2.5 µs warm) yields ~5
ms/ledger = 2% reduction — still sub-Medium. The objective explicitly
rejects Low-severity hypotheses at the hypothesis stage; this proposal
is structurally Low at best and would be rejected by the reviewer.

Additionally, the `collectModifiedClassicEntries` global preload
(`src/transactions/ParallelApplyUtils.cpp:601-644`) following the
dispatch check **must** still run on the fast path because the
parallel workers need the global entry map populated for their footprint
lookups. The proposed short-circuit therefore eliminates only the
dispatch-check probes, not the global preload — bounding the savings
further.

### Lesson Learned

Per-tx in-memory probe loops over O(N_tx × constant) classic snapshot
lookups in serial pre-apply orchestration are below the 1% Low floor on
the current baseline (soroswap median 250 ms, ~200 Soroban txs/ledger,
warm in-memory snapshots). Future hypotheses that target serial setup
work in `preParallelApplyAndCollectModifiedClassicEntries` must
demonstrate that the work being removed is materially larger than this
~1 ms/ledger ceiling. The remaining serial residual under
`applySorobanStages` (~3 ms/ledger) is dominated by the
`collectModifiedClassicEntries` global preload itself, which is
necessary by design and not removable.
