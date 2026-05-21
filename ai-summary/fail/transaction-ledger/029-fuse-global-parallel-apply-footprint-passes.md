# H029: Fuse `collectModifiedClassicEntries` Footprint Walk With `getReadWriteKeysForStage` And `readOnlyPreParallelApply` Footprint Iterations

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Redundant per-tx footprint iteration on the apply thread during Soroban setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`GlobalParallelApplyLedgerState::ctor` (`src/transactions/ParallelApplyUtils.cpp`)
runs three serial passes over every txbundle's footprint on the apply thread
*before* parallel cluster workers can start:

1. `mGlobalEntryMap.reserve(...)` — sums `fp.readWrite.size() * 2 +
   fp.readOnly.size() * 2 + 1` per tx (one full pass over txs).
2. `preParallelApplyAndCollectModifiedClassicEntries` →
   `requiresSequentialPreParallelApply(...)` — for each tx, iterates source-op
   accountKeys plus the entire footprint and calls `isModifiedClassicKey` per
   key (multiple `LedgerSnapshot::load` calls).
3. `collectModifiedClassicEntries` (line 600) — iterates *every* tx footprint
   again, building a `std::unordered_set<LedgerKey> classicKeys` of all
   non-Soroban keys, then walks `ltx.getNewestVersionBelowRoot` per key.
4. `fetchSorobanReadOnlyEntries from footprints` (line 657) — iterates *every*
   tx footprint a fourth time to load Soroban readonly entries from
   `InMemorySorobanState`.

The expected efficient path would fuse these passes into a single iteration
over the stages, classifying each footprint key once and dispatching to the
appropriate side-buffer. This avoids reprocessing the same footprint vectors
4× on the apply thread before any worker can start.

## Mechanism

For soroswap, each Soroban tx has ~8 footprint keys (RW: 2 SAC balances + 2
TTL + 2 trustlines = 6; RO: contract instance + code + 2 TTL = 4; varies per
tx shape). With ~95 Soroban txs/ledger × 71 ledgers = 6,750 txs and 4 passes
× ~8 keys/tx = ~32 key-visits per tx setup.

The redundant work each pass does:
- Pass 1 (`reserve`): cheap, just `.size()` calls.
- Pass 2 (`requiresSequentialPreParallelApply`): heavyweight per-key
  `LedgerSnapshot::load` calls on `current` and `previous` snapshots.
- Pass 3 (`collectModifiedClassicEntries`): per-classic-key
  `getNewestVersionBelowRoot` walk plus per-key emplace into `mGlobalEntryMap`.
- Pass 4 (`fetchSorobanReadOnlyEntries`): per-Soroban-key
  `InMemorySorobanState::get` plus per-TTL-key resolution.

A fused single-pass implementation would walk each tx's RO and RW vectors
exactly once, dispatching by key type:
  - Soroban key → fetch from `InMemorySorobanState` and stash TTL key for
    pre-load.
  - Classic key → check modification against LCL, stash for ltx-walk.
  - Source-account keys → check modification.

## Trigger

Run the soroswap apply-load benchmark; observe the apply-thread serial setup
phase between `processFeesSeqNums` and `applySorobanStageClustersInParallel`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:432–468` —
  `preParallelApplyAndCollectModifiedClassicEntries` (V_26 path), specifically
  the `requiresSequentialPreParallelApply` per-tx footprint scan.
- `src/transactions/ParallelApplyUtils.cpp:600–710` —
  `collectModifiedClassicEntries` and the trailing
  `fetchSorobanReadOnlyEntries from footprints` zone (a single function with
  two stage iterations).
- `src/transactions/ParallelApplyUtils.cpp:104–132` —
  `getReadWriteKeysForStage` (called separately by each
  `ThreadParallelApplyLedgerState::ctor` later).

## Evidence

- Per the diagnostic Tracy trace, `commitBufferedPreParallelApplyWrites`
  zone is 2,150 ns aggregate (essentially zero) and `preParallelApply` is
  2.3 ms/ledger total. The setup overhead lives in passes 3 and 4 above,
  whose Tracy zones (`fetchSorobanReadOnlyEntries from footprints`) do not
  appear individually in the top self-time list — meaning their per-ledger
  cost is below the threshold for prominent listing.
- For ~6,750 soroswap txs, four iterations cost roughly 27,000 footprint
  visits worth of work on the apply thread serial setup window.

## Anti-Evidence

- **Tracy zones not visible in top self-time**: neither
  `collectModifiedClassicEntries` nor `fetchSorobanReadOnlyEntries from
  footprints` shows up in the soroswap top-50 self-time CSV. Fail meta-pattern
  #6 (Aggregate Worker Time ≠ Critical-Path Time) plus the absence of these
  zones in top self-time strongly suggests the per-ledger setup cost is
  ≪ 1 ms/ledger.
- **The four passes do non-overlapping work**: pass 2 calls
  `LedgerSnapshot::load` on classic keys for change detection; pass 3 calls
  `ltx.getNewestVersionBelowRoot` to populate the global entry map; pass 4
  calls `InMemorySorobanState::get` for Soroban keys. Fusing them does not
  remove any of these calls — it only removes the *iteration* overhead of
  reading the same `xdr::xvector<LedgerKey>` vectors 4× from a hot CPU
  cache. The vectors are cache-resident after pass 1, so pass 2–4 iteration
  costs are dominated by the actual lookup work, not the vector-walk.
- **Fail summary explicitly bounded**: meta-pattern #18 (All Prefetch Phases
  Collectively Bounded Under ~3 ms/Ledger) and the related H003-async-prefetch
  / H008-skip-prefetch-wrappers fails establish that the entire pre-cluster
  setup including prefetches is bounded under ~3 ms/ledger. Setup-pass fusion
  is a strict subset of that already-sub-threshold window.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — distinct from `H002-collapse-duplicate-prefetch-passes`
(targeted `prefetchTxSourceIds`+`prefetchTransactionData`) and
`H019-fuse-global-parallel-apply-state-iterations` (different file/scope —
prior fuse target was the GlobalParallelApplyLedgerState ctor's three
*non-footprint* iterations; this proposal targets the four *per-tx-footprint*
iterations across `preParallelApplyAndCollectModifiedClassicEntries`,
`collectModifiedClassicEntries`, and `fetchSorobanReadOnlyEntries`).

### Why It Failed

The optimization is real (the four serial passes really do walk the same
footprint vectors) but the savings are bounded well below the Medium 3% floor.
Each pass does heavyweight per-key lookup work (snapshot loads,
getNewestVersionBelowRoot walks, InMemorySorobanState gets) that fusion does
not remove — fusion only removes the per-vector iteration overhead, which is
sub-microsecond per pass given the vectors are cache-hot after the first
read.

The aggregate critical-path cost of these four passes is bounded by the
absence of any of them in the soroswap top-50 self-time zones, indicating
each is well under 1 ms/ledger. Even an optimistic 0.5 ms/ledger fusion
saving is ~0.18% of the 272 ms apply window — three orders of magnitude
below Medium severity.

The same conclusion applies under fail meta-pattern #5 (Sub-Threshold Narrow
Fixes): individual narrow fixes in the apply-thread serial setup phase
consistently land at 0.2–2.5%, never reaching Medium individually. A combined
multi-site setup-fusion patch could approach but not clear Medium, and the
review cost of restructuring the three setup functions is disproportionate
to the win.

### Lesson Learned

When multiple serial passes iterate the same in-memory vectors but each
performs different heavyweight work per element, the fusion saving is the
iteration overhead alone — not the per-element work. For txbundle-footprint
iteration in `GlobalParallelApplyLedgerState::ctor`, the iteration overhead
across 4 passes is sub-millisecond per ledger because the footprint vectors
are tiny (~8 keys/tx) and stay in CPU cache after the first read. Future
serial-setup hypotheses must size against the iteration overhead alone, not
the inclusive zone time, before claiming a meaningful saving.
