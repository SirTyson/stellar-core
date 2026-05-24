# H003: Fuse Double-Scan of Footprints in `collectModifiedClassicEntries` (Classic-Key Set + Soroban-RO Preload)

**Date**: 2026-05-24
**Subsystem**: soroban (parallel-apply setup)
**Severity**: Low
**Impact**: Apply-time reduction (sub-Medium after sizing)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The setup of `mGlobalEntryMap` performed in
`GlobalParallelApplyLedgerState::collectModifiedClassicEntries` should walk
the per-tx Soroban RW + RO footprints **once** to populate (a) classic-key
pre-loads and (b) Soroban RO pre-loads — not twice. The second loop's
iteration overhead and redundant per-tx `mGlobalEntryMap.find` calls
should be eliminated.

## Mechanism

`collectModifiedClassicEntries` (`ParallelApplyUtils.cpp:600-719`) iterates
all stages × all tx-bundles × all footprint keys twice:

1. Lines 607-628: builds a deduplicated `std::unordered_set<LedgerKey>
   classicKeys` from the RW and RO footprints (skipping Soroban keys).
2. Lines 654-718: a second nested loop over stages × bundles × RO footprint
   that for each RO Soroban key does `mGlobalEntryMap.find(lk)` (continue
   if already loaded), then `mInMemorySorobanState.get(lk)` /
   `mLCLSnapshot.loadLiveEntry(lk)`, and the same for the TTL key.

For soroswap with ~2 000 txs × 6 RO footprint keys = ~12 000 iterations of
the second loop. The `find` dedup is O(1) per call, so first-iteration
cost (per unique key) is the real `get`; the rest are hash+lookup misses.
A fused single pass over the iteration space would avoid the second
traversal and combine the classic-key insert + Soroban-RO `find`+`get`
inline.

The deviation from expected behavior is the second pass over the same
iteration space (stages × bundles × footprint), costing ~12 000 hashed
`find` calls per soroswap ledger.

## Trigger

Modify `collectModifiedClassicEntries` to fuse the two passes — a single
loop over `stages × txBundles × (readWrite ∪ readOnly)` that routes each
key by `isSorobanEntry` to either `classicKeys.emplace` or the Soroban-RO
pre-load path. Then run `scripts/run_apply_load_matrix.py` soroswap and
verify the apply-time delta.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:600-719` — entire body of
  `collectModifiedClassicEntries`.
- `src/transactions/ParallelApplyUtils.h:236-237` — declaration.

## Evidence

- The two loops walk the identical iteration space
  (`stages × txBundles × footprint`).
- Per-tx iteration count for soroswap (≈ 12 000 inner iterations / ledger)
  is meaningful relative to the apply-thread serial work.

## Anti-Evidence

- The first pass does set-insert (classic only); the second pass does
  map-find + conditional map-emplace + per-key `get`. The shapes differ
  enough that fusion saves only iteration overhead and one `isSorobanEntry`
  check per key, not the dominant `get` calls.
- `collectModifiedClassicEntries` is a child of `soroban_setup_glbl`
  (24.24 ms total), which has been the subject of meta-pattern rejections
  (fused-soroban-fee-preapply-state family), so structurally-similar
  hypotheses are at risk of being treated as duplicates.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — `collectModifiedClassicEntries` fusion (this exact path)
not previously investigated; meta-pattern `fused-soroban-fee-preapply-state`
targeted a different surface (`requiresSequentialPreParallelApply` /
read-only pre-apply dispatcher), not the post-preApply classic+RO scan.

### Why It Failed

Sizing kills it. The marginal work of the second loop is:

- ~12 000 iteration overhead (~10-30 ns each): ~0.12-0.36 ms/ledger.
- ~12 000 `mGlobalEntryMap.find` calls (~50-100 ns each):
  ~0.6-1.2 ms/ledger; but most are hits-on-dedup (cheap), and the
  unique-key `get` calls remain even after fusion.
- The dominant cost in the loop is the first-iteration
  `mInMemorySorobanState.get(lk)` per unique RO Soroban key (e.g., shared
  contract code + instance) — bounded by `unique_keys × ~5 µs` ≈ a few
  hundred µs for soroswap. Fusion does not eliminate this term.

Total upper bound for fusion: ≤ ~1.5 ms/ledger = **0.69 %** of the 218 ms
baseline — below the 1 % Low noise floor and far below the 3 % Medium
threshold this objective requires at the hypothesis stage. The
contribution to `soroban_setup_glbl` (24.24 ms) is ≤ 6 %, so even if fully
eliminated the parent phase moves from 11.1 % → 10.5 % of apply — invisible
under benchmark noise.

### Lesson Learned

Loop fusion inside `collectModifiedClassicEntries` cannot clear the
Medium floor; the real cost in the second pass is the first-iteration
`InMemorySorobanState.get` per unique RO Soroban key, which fusion does
not avoid. Any future angle on this function must target the per-unique-
key `get`/copy path (e.g., shared-pointer pass-through), not the
iteration shape — and even then must size against ≤ a few hundred µs of
genuine work per ledger.
