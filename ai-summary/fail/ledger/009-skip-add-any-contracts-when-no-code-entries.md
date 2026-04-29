# H009: Skip addAnyContractsToModuleCache walks when init/live batches contain no CONTRACT_CODE entries

**Date**: 2026-04-30
**Subsystem**: ledger
**Severity**: Low
**Impact**: small constant per-ledger CPU reduction in `finalizeLedgerTxnChanges`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`addAnyContractsToModuleCache` should compile any newly-deployed Wasm
contracts into the Soroban module cache. For workloads that deploy no
contracts (e.g., the soroswap apply-load benchmark, which only invokes
already-deployed contracts), the call should be effectively free — no
per-entry iteration over thousands of unrelated `LedgerEntry`s.

## Mechanism

`LedgerManagerImpl::finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3354-3355`) calls
`addAnyContractsToModuleCache(initEntries)` and
`addAnyContractsToModuleCache(liveEntries)`. The implementation
(`src/ledger/LedgerManagerImpl.cpp:3468-3490`) walks every entry in the
batch and tests `entry.data.type() == CONTRACT_CODE`. For soroswap, neither
batch contains any `CONTRACT_CODE` entry, so the entire scan is wasted
work. Adding an early-exit (e.g., a precomputed flag, or reading the
batch's per-type counts that `addLiveBatch` already produces) skips the
walk entirely.

## Trigger

Profile `finalizeLedgerTxnChanges` on the soroswap workload; the
`addAnyContractsToModuleCache` calls show up as a small but non-zero
constant.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3355` — call sites in
  `finalizeLedgerTxnChanges`.
- `src/ledger/LedgerManagerImpl.cpp:3468-3490` — implementation that
  walks the entry vector unconditionally.

## Evidence

- Soroswap deploys no new contracts during the benchmark window; both
  `initEntries` and `liveEntries` for a typical soroswap ledger contain
  zero `CONTRACT_CODE` entries.
- `finalizeLedgerTxnChanges` is on the in-scope serial path
  (descendant of `applyLedger`); per Tracy, it accounts for ~325 ms /
  3.18% of `applyLedger`. Some fraction of that is these scans.

## Anti-Evidence

- The per-entry test is a single tagged-union check — extremely cheap
  per iteration. With ~5 000 entries per ledger × 2 batches ×
  69 ledgers, the total skip would be ~700 k cheap branches, well below
  1 ms wall-clock.
- The `addLiveBatch` per-type counts are computed *after* this scan in
  the current ordering; getting them earlier would require a small
  refactor for what is essentially negligible CPU savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below this objective's Medium severity threshold (3–10% apply time
reduction). The walk is two passes over the per-ledger entry batches
performing only a tagged-union enum check; back-of-envelope cost is
sub-1% of `applyLedger`, well within benchmark noise. Per the
optimize-soroswap rules, Low (1–3%) hypotheses are rejected at the
hypothesis stage and sub-1% items are excluded outright.

### Lesson Learned

When a candidate hot-path scan is "wasted but cheap" (cheap per-element
predicate over a moderately sized batch), quantify it before drafting
a full hypothesis. Two enum scans over ~5 k entries are nowhere near
the 3% threshold even when fully eliminated. Reserve hypothesis slots
for changes that touch large XDR-allocation paths or O(n) work inside
the dominant 40%-of-trace `applySorobanStageClustersInParallel` zone.
