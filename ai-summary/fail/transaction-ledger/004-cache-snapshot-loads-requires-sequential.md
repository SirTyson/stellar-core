# H004: Cache RW/RO key snapshot lookups in requiresSequentialPreParallelApply

**Date**: 2026-05-25
**Subsystem**: transaction-ledger (ParallelApplyUtils)
**Severity**: Low
**Impact**: redundant LedgerSnapshot.load() calls in classic-modification check
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`requiresSequentialPreParallelApply` should answer "did any key this tx touches
get modified by a classic tx earlier in this ledger?" without doing
double-lookups on the same key across the `current` and `previous` snapshots
when the answer is obviously no (the empty-overlay common case). Ideally a
fast path that short-circuits when `current` has no classic writes (which is
the dominant case in pure-Soroban soroswap workloads) would skip per-key
loads entirely.

## Mechanism

`src/transactions/ParallelApplyUtils.cpp:171-208` iterates every footprint key
(RO + RW) of every Soroban tx in the stage, plus source-accounts of every
op, and calls `isModifiedClassicKey` which performs two `LedgerSnapshot.load`
operations per key. For 2000 soroswap txs with ~8 footprint keys each, that's
~32 000 snapshot loads per ledger. Even though each load is a cheap hashmap
probe (overlay is small), the work is structurally redundant when no classic
tx ran in this ledger — and soroswap ledgers in the benchmark contain only
Soroban txs.

## Trigger

Run apply-load with a pure-Soroban ledger (soroswap config); profile
`collectModifiedClassicEntries` self-time.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:171-208` — `requiresSequentialPreParallelApply`
  per-key snapshot loads.
- `src/transactions/ParallelApplyUtils.cpp:151-168` — `isModifiedClassicKey`
  doing dual `current.load()` + `previous.load()`.
- `src/transactions/ParallelApplyUtils.cpp:431-523` — caller
  `preParallelApplyAndCollectModifiedClassicEntries`.

## Evidence

- `collectModifiedClassicEntries` apply-window self-time per Tracy: 0.30 ms /
  ledger. The function does more than just this check, but this is its
  dominant inner loop.
- Per-key dual load on 32K keys/ledger is structurally repeated work.

## Anti-Evidence

- `LedgerSnapshot.load()` is already optimized — the soroban path resolves
  to an in-memory hash-map probe with no disk hit.
- The function correctly short-circuits on the first modified key found per tx.
- The function is essential for correctness: misclassifying as "no sequential
  needed" would race classic writes against Soroban reads.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — fail summary entries #003, #078, #207 cover related
`preParallelApply` work but specifically target the function-level cost or
fusion with other passes, not this per-key snapshot-load redundancy.

### Why It Failed

Per Tracy, `collectModifiedClassicEntries` total self-time is 0.30 ms / ledger
on the soroswap benchmark. Even a 100% elimination of this function would be
0.30 / 207 = 0.14% — well below the 1% noise floor and far below the 3%
Medium threshold. A partial optimization (e.g., fast-path skip when overlay
is empty) would yield only a fraction of that.

### Lesson Learned

When considering optimization of a per-key inner loop, always look up the
*enclosing zone's* total apply-window self-time before proceeding. If the
enclosing zone is sub-millisecond per ledger, no inner-loop tweak — however
clever — can hit the Medium threshold. The right way to attack
`collectModifiedClassicEntries` would be a redesign that eliminates the
entire concept of cross-checking classic-modification (e.g., per-key dirty
flags propagated from `preParallelApplyAndCollectModifiedClassicEntries`),
not micro-optimizing inside it.
