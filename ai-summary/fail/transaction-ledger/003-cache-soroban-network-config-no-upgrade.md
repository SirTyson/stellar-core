# H003: Cache SorobanNetworkConfig and Reuse Across Pre-Apply / Post-Apply When No Upgrade

**Date**: 2026-05-04
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-time reduction by eliminating redundant network config load
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanNetworkConfig::loadFromLedger(ltx)` reads multiple
`CONFIG_SETTING` ledger entries, deserializes each, and computes derived
values (e.g., `mFeeRent1KB`). For a typical ledger that contains no
config-setting upgrades, the network config at ledger close is byte-for-byte
identical to the network config that existed before apply. Calling
`loadFromLedger` a second time after apply (in `finalizeLedgerTxnChanges`,
LedgerManagerImpl.cpp:3329) reproduces the same object that was already
loaded at the start of `applyTransactions` (line 2862). Ideally, the
post-apply load would be skipped (or replaced with a cheap reuse) when
no `CONFIG_SETTING` keys were modified by any transaction in the
ledger, which is the common case.

## Mechanism

The pre-apply load constructs a complete `SorobanNetworkConfig` object
including a CPU-snapshot of `mFeeRent1KB`. The post-apply load repeats
the same disk reads through the LTX, full XDR deserialization, and
derived-value computation, even when no transaction in the ledger
touched a `CONFIG_SETTING` entry. For a soroswap workload with 2000
swap transactions per ledger and zero config-setting upgrades, this
repeated work is wasted.

## Trigger

Run `apply-load --mode soroswap`. Observe the per-ledger
`SorobanNetworkConfig::loadFromLedger` invocation in Tracy (zone
`loadFromLedger`) and confirm that each ledger triggers two loads
(pre-apply + post-apply). Modify `finalizeLedgerTxnChanges` to detect
the absence of `CONFIG_SETTING` modifications in the LTX and reuse
the pre-apply config object; measure apply-time delta.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2858-2863` — pre-apply load.
- `src/ledger/LedgerManagerImpl.cpp:3326-3330` — post-apply load.
- `src/ledger/NetworkConfig.cpp:1754-1788` — `loadFromLedger`
  implementation; reads ConfigSettingEntry keys and constructs
  derived state.
- `src/ledger/LedgerTxn.h` — `getDeltaForKeyType` / similar APIs to
  detect whether any `CONFIG_SETTING` entry was modified.

## Evidence

- Five `loadFromLedger` callsites exist in
  `src/ledger/LedgerManagerImpl.cpp`; two of them (lines 2862 and 3329)
  fire on every soroswap ledger.
- Tracy: `loadFromLedger` (NetworkConfig.cpp) total wall-time across
  the soroswap trace is small but non-zero — sub-1 ms/ledger across
  the two callsites combined.
- The apply-thread surface area for redundant work is conceptually
  recoverable: detect "no CONFIG_SETTING modifications in this LTX"
  and reuse the pre-apply config object.

## Anti-Evidence

- The post-apply call uses the (possibly upgraded) `lh.ledgerVersion`,
  not the pre-apply version. For an upgrade ledger, the protocol
  version itself can change between pre-apply and post-apply, so the
  cached pre-apply config cannot be reused unconditionally; the
  hypothesis only applies when no upgrade occurred.
- `SorobanNetworkConfig::loadFromLedger` is already lightweight (~28 µs
  per call per Tracy) — the absolute time saved is small.
- Per the meta-pattern documented in
  `ai-summary/fail/transaction-ledger/summary.md`, "small per-callsite
  work" optimizations consistently land below the 1-3% threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone
hypothesis. The fail summary contains no specific entry for caching
`SorobanNetworkConfig` across pre-apply/post-apply, though the broader
meta-pattern about small-per-callsite optimizations applies.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis stage).
Tracy measurement of `loadFromLedger` shows the combined two-call
per-ledger cost is well under 0.5 ms/ledger, putting the maximum
recoverable savings at roughly 0.18% of the 272.9 ms soroswap apply
baseline — an order of magnitude below the Medium 3% floor and inside
the benchmark noise band.

The implementation is also non-trivial: detecting "no CONFIG_SETTING
modifications" requires walking the LTX delta and filtering, which
itself adds work; and the cache must be invalidated correctly for
upgrade ledgers, where the protocol version changes between pre-apply
and post-apply. The complexity-vs-payoff ratio is unfavorable.

### Lesson Learned

`SorobanNetworkConfig::loadFromLedger` is a real but tiny per-ledger
cost; the eager `mFeeRent1KB` cache (per existing memory:
NetworkConfig.cpp:1754-1788, NetworkConfig.cpp:2230-2233) and the
overall `loadFromLedger` runtime keep this callsite well below the
Medium severity floor. Don't propose narrow caching of small
configuration loads; instead look for redesigns that eliminate entire
phases of `closeLedger` or restructure dominant hot paths.
