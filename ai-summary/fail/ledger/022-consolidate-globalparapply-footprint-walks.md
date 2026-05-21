# H022: Consolidate redundant footprint walks in `GlobalParallelApplyLedgerState` setup

**Date**: 2026-05-21
**Subsystem**: ledger
**Severity**: Low
**Impact**: per-ledger footprint iteration overhead in parallel-apply state construction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When constructing `GlobalParallelApplyLedgerState` for a ledger's
Soroban-stage apply, the apply thread should walk each transaction's
read-only and read-write footprints once, deriving every needed quantity
in a single pass: estimated map capacity, classic-vs-soroban
classification, `requiresSequentialPreParallelApply` decision data,
modified-classic-key set, and the Soroban-RO preload list with TTL keys.
A single fused pass avoids touching the same footprint vectors and
performing key-type dispatch (`isSorobanEntry`, `isInMemoryType`) more
than once per key.

## Mechanism

The current setup performs four separate iterations over per-transaction
footprints in `src/transactions/ParallelApplyUtils.cpp`:

1. **`mGlobalEntryMap.reserve` estimate** (line 405–417): walks every
   stage / txBundle / footprint to size-estimate the map.
2. **`preParallelApplyAndCollectModifiedClassicEntries`** (line 446–462,
   p26+ branch): walks every stage / txBundle, calls
   `requiresSequentialPreParallelApply` which loads source/fee-source
   from both `current` and `previous` snapshots; then runs
   `readOnlyPreParallelApply` (parallel) and `commitBufferedPreParallelApplyWrites`.
3. **`collectModifiedClassicEntries`** (line 600–644): walks every
   footprint again to build a classic-keys set and call
   `getNewestVersionBelowRoot` per classic key.
4. **`fetchSorobanReadOnlyEntries from footprints`** (line 654–718):
   walks every readOnly footprint a third time to preload Soroban
   entries and their TTL keys.

Each pass is O(total footprint keys). For a soroswap ledger of ~2000 txs
with ~5 footprint keys each (~10000 key-touches), the redundant
iteration plus key-type dispatch contributes some apply-thread serial
overhead that a single fused pass would avoid.

## Trigger

Soroban-only ledger close with non-trivial parallel apply staging
(soroswap workload: 2000 tx/ledger, 8 clusters, ~5 footprint keys/tx).
The setup runs once per ledger inside `applySorobanStages` and is on the
apply-thread serial critical path.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState`
  ctor:380–428 — pre-reserve walk.
- `src/transactions/ParallelApplyUtils.cpp:preParallelApplyAndCollectModifiedClassicEntries:431–523`
  — sequential/parallel split walk.
- `src/transactions/ParallelApplyUtils.cpp:collectModifiedClassicEntries:600–719`
  — classic key set walk + Soroban RO preload walk.

## Evidence

- Tracy reports `getReadWriteKeysForStage` (a similar redundant
  RW-footprint walk used at commit time) at 30.7 ms / 43 stages =
  ~715 µs/stage; this gives an order-of-magnitude calibration for the
  cost of one footprint walk over a ledger's tx set.
- `preParallelApply` zone total = 166 ms / 14036 calls (TransactionFrame),
  with parallel RO preApply taking 130 ms / 14036 = ~9.3 µs/call;
  these aggregate per-tx costs include the footprint dispatch work.

## Anti-Evidence

- The four passes do logically distinct work in distinct phases: pass 2
  needs sequence-number side effects committed to `ltx` before pass 3 can
  read modified classic state; pass 4 must run after pass 3 to avoid
  double-loading classic entries already collected in the global map.
  Reordering would change observable side-effect ordering.
- Each per-key operation (an `unordered_set::emplace`, an
  `isSorobanEntry` enum check, a `getNewestVersionBelowRoot` call) is
  cheap; the total walk time is bounded by the number of footprint keys,
  which is small relative to the host execution work in
  `applySorobanStageClustersInParallel`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not directly covered by existing fail entries
(closest: `002-precompute-parallel-apply-footprint-index` rejected at
final-review for 23.95% soroswap regression from extra index
construction overhead; this hypothesis would be subject to the same
regression risk).

### Why It Failed

Quantified ceiling is below the Medium severity floor. With each
per-key operation in the ~100–500 ns range and ~10000 key-touches per
ledger across all four passes, the total apply-thread serial cost is
~1–5 ms/ledger (≤2% of the 272 ms soroswap apply baseline). Even an
ideal fused single-pass implementation could only reclaim a fraction of
that — the per-key work itself (hash insert, snapshot lookup, type
dispatch) is the dominant cost, not the iteration overhead. The
already-rejected footprint-index precompute hypothesis (fail 002)
demonstrated that adding any auxiliary structure can backfire severely
(soroswap +23.95% regression), so attempting consolidation here carries
high risk for at most Low-tier upside.

### Lesson Learned

For setup phases that combine multiple semantically distinct passes
each with side-effect dependencies (sequence-number commits, modified
classic key collection, Soroban RO preload), the iteration overhead
itself is rarely the bottleneck — per-key hash operations and snapshot
lookups dominate. The footprint-index regression on this branch
(soroswap +23.95% from precompute) confirms that consolidation
schemes carry meaningful regression risk; only pursue if there is a
specific zone with quantified ≥3% apply-thread serial impact, not just
"redundant iteration".
