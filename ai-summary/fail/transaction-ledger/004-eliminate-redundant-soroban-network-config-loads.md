# H004: Eliminate Redundant `SorobanNetworkConfig::loadFromLedger` Calls in Apply Path

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: redundant-config-load
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a single ledger close, `SorobanNetworkConfig` only changes at upgrade
boundaries. The expected design is to load the network config exactly once
per apply (e.g., the pre-apply load at `LedgerManagerImpl.cpp:2862`), reuse
the same instance for the eviction scan, finalize, and module-cache rebuild
phases, and only re-load if a config upgrade was applied during the ledger.
Repeated `loadFromLedger` calls inside one apply window — each performing a
full pass over the config-setting ledger entries — should not be necessary.

## Mechanism

The apply path performs at least three `SorobanNetworkConfig::loadFromLedger`
calls per ledger:
1. `src/ledger/LedgerManagerImpl.cpp:2862` — pre-apply config load for
   parallel Soroban setup.
2. `src/bucket/BucketManager.cpp:1197` — inside
   `resolveBackgroundEvictionScan`, called from `finalizeLedgerTxnChanges`.
3. `src/ledger/LedgerManagerImpl.cpp:3329` — `finalSorobanConfig` load in
   `finalizeLedgerTxnChanges` after upgrades.

Each call iterates all `CONFIG_SETTING` entries and decodes them. The pre-apply
config (#1) is identical to the eviction-scan config (#2) unless an upgrade
ran in between, which it cannot since `applyLedger` does not apply upgrades
between line 2862 and line 1197 — both run before the upgrade-apply phase.
The actual ACTUAL behavior re-decodes the same config-setting entries three
times per ledger, whereas the EXPECTED behavior is one decode that is threaded
through the eviction scan and reused until upgrade-apply mutates the entries.

## Trigger

Every soroswap apply-load ledger close hits all three sites unconditionally
(protocol version is well past `SOROBAN_PROTOCOL_VERSION`). Run
`scripts/run_apply_load_matrix.py --scenario soroswap` and the trace will
show two `loadFromLedger` invocations in the pre-finalize window plus one
in finalize.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2855-2863` — pre-apply config load
- `src/bucket/BucketManager.cpp:1181-1200` — `resolveBackgroundEvictionScan`'s
  internal `loadFromLedger`
- `src/ledger/LedgerManagerImpl.cpp:3217-3330` — `finalizeLedgerTxnChanges`'s
  `resolveBackgroundEvictionScan` call and the post-upgrade `loadFromLedger`
  at line 3329

## Evidence

- Three distinct `loadFromLedger` call sites are reachable in every apply
  pass for ledgers at protocol ≥ V20.
- The previously-rejected H064
  (`004-reuse-finalize-soroban-network-config-in-maybe-rebuild.md`) covered
  reusing `finalSorobanConfig` from finalize in `maybeRebuildModuleCache` —
  a different pair of calls. The eviction-scan-internal `loadFromLedger`
  at `BucketManager.cpp:1197` was not addressed by H064 and is genuinely
  novel as a target.

## Anti-Evidence

- H064 measured `SorobanNetworkConfig::loadFromLedger` at ≤0.5 ms/ledger per
  call and concluded that eliminating one of two calls (~0.25 ms/ledger,
  ~0.1%) is far below Low. With three reachable calls, even fully
  eliminating two of them caps savings at ~1 ms/ledger ≈ 0.45% of the 218 ms
  soroswap median — still below the 1% Low floor and ~6× below the 3%
  Medium floor.
- `loadFromLedger` is already heavily optimized: `mFeeRent1KB` is eagerly
  cached, and the config-setting entry count is small (~30 entries). Per-call
  cost is dominated by a handful of map lookups; further reductions in
  per-call cost have a sub-100 µs/ledger ceiling.
- Threading a shared `SorobanNetworkConfig` reference through
  `BucketManager::resolveBackgroundEvictionScan` requires API and ownership
  changes (BucketManager currently consumes config via a `LedgerSnapshot`
  parameter); the review/PoC burden is disproportionate to the projected
  saving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PARTIAL — the eviction-scan internal `loadFromLedger` call at
`BucketManager.cpp:1197` is a genuinely novel call site not previously
investigated; H064 covered only the maybeRebuildModuleCache reuse angle. The
overall conclusion (sub-Low ceiling) matches H064's sizing.

### Why It Failed

H064 established that `loadFromLedger` is bounded at ≤0.5 ms/ledger per call,
so even eliminating two of the three calls per ledger caps savings at ~1 ms
≈ 0.45% of the soroswap median. This is below the 1% Low floor (which this
objective does not accept anyway) and ~6× below the 3% Medium threshold.
The eviction-scan call site is the truly novel piece of this investigation,
but the sizing ceiling carries over: at sub-Low per-ledger savings, no
combination of these three calls reaches Medium severity.

### Lesson Learned

When extending a prior fail record (here H064) to additional call sites of
the same function, project the per-call ceiling × full call count against
the objective floor before writing a new hypothesis. For
`SorobanNetworkConfig::loadFromLedger`, the per-call cost (~0.5 ms) caps
total savings at sub-Low even if every call site is fused. Future
config-caching hypotheses must identify an uncached expensive load that
dominates apply time, not an already-fast load that recurs.
