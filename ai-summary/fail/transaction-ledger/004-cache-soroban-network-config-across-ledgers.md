# H004: Cache `SorobanNetworkConfig` Across Ledgers Instead of Reloading From Ledger Each Close

**Date**: 2026-05-04
**Subsystem**: transaction-ledger (apply finalize / network config)
**Severity**: Low
**Impact**: Sequential close-window setup overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanNetworkConfig::loadFromLedger`
(`src/ledger/NetworkConfig.cpp:1754`) reads ~17 distinct config-setting
ledger entries on every Soroban-active ledger close — once inside
`finalizeLedgerTxnChanges` (`src/ledger/LedgerManagerImpl.cpp:3329`) and
typically again from setup paths in the same close, totaling ~4 invocations
per ledger close in the soroswap diagnostic trace. Since config-setting
upgrades happen at most a few times per protocol upgrade (and never at all
in steady-state soroswap apply-load), the post-apply config could be reused
from the cached LCL config when no `LedgerUpgradeType::LEDGER_UPGRADE_CONFIG`
is in `sv.upgrades`, eliminating the redundant reads.

## Mechanism

`finalizeLedgerTxnChanges` always calls `loadFromLedger(ltx)` to capture any
config upgrade in `sv.upgrades`. In steady state this returns the same
config the LCL already has. Detecting the no-upgrade case and reusing the
cached config would skip ~17 ledger entry loads per close.

## Trigger

Any soroswap or max-sac apply-load run in steady state (no config upgrades).

## Target Code

- `src/ledger/NetworkConfig.cpp:1754-1796` — `SorobanNetworkConfig::loadFromLedger`
- `src/ledger/LedgerManagerImpl.cpp:3326-3330` — call site inside `finalizeLedgerTxnChanges`
- `src/ledger/LedgerManagerImpl.cpp:1716-1740` — upgrades application loop (potential
  trigger for an explicit "config-changed" flag)

## Evidence

- Tracy diagnostic trace (current accepted baseline) shows
  `loadFromLedger` total = 8.3 ms across 287 calls, with each child loader
  (`loadComputeSettings`, `loadCpuCostParams`, etc.) running ~287 times.
  287 / 71 ledgers = ~4 invocations per ledger close, suggesting reuse
  would skip 75% of calls.
- The full set of loader children has measured zone times (e.g.
  `loadMaxContractSize` = 877 µs aggregate, `loadCpuCostParams` = 572 µs
  aggregate), all summing into the single `loadFromLedger` total.

## Anti-Evidence

- Aggregate `loadFromLedger` cost is **8.3 ms across the entire 71-ledger
  trace** = 0.117 ms / ledger sequential = **~0.04% of soroswap apply
  time**. Even eliminating 100% of the calls is two orders of magnitude
  below the Medium 3% floor and below the 1% noise floor.
- The "extra" 3 invocations per ledger close are not all inside the
  measured `applyLedger` window — at least some come from the apply-load
  benchmark setup (`upgradeSorobanConfig`, snapshot-taking code paths).
  Apply-window-only call count is closer to 1 per ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from prior
config-related work which targeted `feeRent1KB` caching at load time
(memory note: `loadFromLedger` eagerly computes `mFeeRent1KB`).

### Why It Failed

Below objective severity threshold by orders of magnitude. The full
`loadFromLedger` aggregate cost of 0.117 ms / ledger is below the 1% noise
floor; even a perfect cache cannot reach Medium. Adds invalidation surface
(detect config upgrades correctly across protocol bumps) for negligible
return.

### Lesson Learned

`SorobanNetworkConfig::loadFromLedger` and its loaders are individually
sub-microsecond per call against in-LedgerTxn cached entries; the
"~17 entry loads per ledger close" framing is misleading because the loads
hit the LedgerTxn cache. Future work targeting per-close setup should
profile against the `applyLedger` parent timestamp window first, and
discard any sub-1-ms-per-ledger sequential targets in this region.
