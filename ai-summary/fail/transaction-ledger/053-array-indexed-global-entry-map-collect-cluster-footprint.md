# H053: Replace `mGlobalEntryMap` unordered_map probes in `collectClusterFootprintEntriesFromGlobal` with array-indexed lookup

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Sub-noise — projected ≤ 0.6% apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The serial pre-launch loop in `applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2545-2554`) constructs one
`ThreadParallelApplyLedgerState` per cluster, each of which runs
`collectClusterFootprintEntriesFromGlobal`
(`src/transactions/ParallelApplyUtils.cpp:925-986`) — a walk over every
transaction's RO+RW footprint that probes `mGlobalEntryMap` (an
`UnorderedMap<LedgerKey, LedgerEntryPtr>`) twice per footprint key (entry +
TTL key) to copy needed entries into the per-thread map. The expected
efficient path would precompute, once per stage at
`GlobalParallelApplyLedgerState` construction time, a dense
`std::vector<LedgerEntryPtr>` indexed by a stage-local footprint-position
identifier (assigned during the existing footprint-collection pass) and have
each cluster's `collectClusterFootprintEntriesFromGlobal` perform array
lookups instead of hash probes.

## Mechanism

Today, for each cluster, `collectClusterFootprintEntriesFromGlobal` walks
~250 txs × ~16 footprint+TTL keys = ~4,000 `mGlobalEntryMap.find(...)` calls
(unordered_map hashing + bucket scan + key compare). Across 8 clusters this
is ~32,000 hash probes per ledger, all serial on the main thread before any
worker can start. Each probe is roughly 50–100 ns (hash + linear-probe +
LedgerKey equality), totaling ~1.6–3.2 ms/ledger of serial pre-launch work.
An array-indexed alternative would replace the hash with an O(1) integer
deref, saving the hashing cost but preserving the LedgerEntryPtr copy and
TTL-key computation (which already dominates this loop per H051/H052
analyses).

## Trigger

Run the current soroswap apply-load benchmark (see
`ai-summary/CURRENT_STATE.md`). Each ledger close enters the pre-launch
loop once, processes 8 clusters × ~250 Soroban txs × ~16 footprint+TTL keys.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:925-986` —
  `collectClusterFootprintEntriesFromGlobal` (hash probes to replace)
- `src/transactions/ParallelApplyUtils.h:128-...` —
  `GlobalParallelApplyLedgerState` (would carry the precomputed flat array
  + key→index map)
- `src/transactions/ParallelApplyUtils.cpp:GlobalParallelApplyLedgerState::ctor`
  — additional one-pass numbering of all footprint keys at stage build
- `src/transactions/ParallelApplyStage.h:TxBundle` — would need to carry a
  pre-resolved `std::vector<uint32_t>` of footprint-key indices per tx

## Evidence

- `collectClusterFootprintEntriesFromGlobal` runs strictly serial on the
  main apply thread before any worker starts, so its cost is fully on the
  critical path.
- Each hash probe pays an `LedgerKey` hash (which traverses an XDR
  discriminated union) plus equality compare on collision.
- The same `mGlobalEntryMap` entries are probed repeatedly across the 8
  cluster ctors (shared RO entries hit every cluster).

## Anti-Evidence

- H051's direct sizing of the per-cluster ctor placed total ctor work at
  well under 1 ms per cluster, including the unordered_map probes. Total
  serial pre-launch is <8 ms/ledger and the hash-only portion is a small
  fraction of that.
- The flat-array variant still must perform the LedgerEntryPtr copy into
  the thread map and the TTL-key computation per-key (H051/H052 show this
  is the dominant per-iteration cost, not the hash).
- Building the per-tx index vector at stage construction adds 2,000-tx ×
  16-key work in `GlobalParallelApplyLedgerState` ctor (~32,000 hash+insert
  into a key→index map) — strictly recovering the same hash cost in a
  different phase rather than removing it.
- The pre-numbering pass itself is serial and adds critical-path work that
  cancels much of the per-cluster gain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H019 (loop fusion of three iterations),
H051 (parallelize ctor into worker), H052 (per-frame TTL-key cache), and
fail/006 (share `RestoredEntries` across clusters). This targets the
hash-probe cost specifically.

### Why It Failed

Below the objective's 3% Medium floor by sizing. Even an optimistic 100%
elimination of the hash cost in `collectClusterFootprintEntriesFromGlobal`
recovers at most the hash-only fraction of the per-cluster ctor work, which
H051 placed at well under 1 ms per cluster total (hash + entry copy + TTL
key + reserve). The aggregate ceiling across 8 serial clusters is well under
2 ms/ledger, ≤0.7% of the 272 ms soroswap baseline — below the 1% noise
floor and well below the 3% Medium threshold. The pre-numbering pass needed
to build the index vector itself adds roughly equivalent hash work in the
`GlobalParallelApplyLedgerState` ctor (a per-key key→index insertion),
shifting cost rather than removing it. Per objective severity rules, Low
projections are not accepted at the hypothesis stage.

### Lesson Learned

Replacing unordered_map probes with array indexing in apply-path code paths
must size the hash cost as a *fraction* of the per-iteration body cost
(which here is dominated by `LedgerEntryPtr` copy + TTL-key construction
per H051/H052), not as the per-iteration body cost itself. For this loop
the hash share is <0.7% of soroswap apply time, and the index-building
prepass shifts rather than removes the work.
