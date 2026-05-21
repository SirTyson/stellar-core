# H004: Skip the Redundant Second `SorobanNetworkConfig::loadFromLedger` in `finalizeLedgerTxnChanges`

**Date**: 2026-05-20
**Subsystem**: ledger / sealing
**Severity**: Low
**Impact**: Sub-1% apply-time reduction by avoiding the second per-ledger
`SorobanNetworkConfig::loadFromLedger` call when no Soroban config upgrade is
applied in the current ledger.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanNetworkConfig::loadFromLedger` loads ~17 individual `CONFIG_SETTING`
ledger entries plus protocol-gated extras (parallel compute, ledger-cost-ext,
SCP timing, frozen keys, freeze-bypass txs) via separate `ls.load(key)` calls
and computes `mRentFee1KBSorobanStateSize`. The expected behavior is that the
config is loaded **once per ledger**: either it is computed by `applyTransactions`
(at `LedgerManagerImpl.cpp:2862`) and reused throughout the ledger close, or
the post-upgrade config is computed by `finalizeLedgerTxnChanges` (at
`LedgerManagerImpl.cpp:3329`) only when a Soroban config upgrade actually
changed the relevant settings in this ledger.

## Mechanism

`applyLedger` currently invokes `SorobanNetworkConfig::loadFromLedger(ltx)`
**twice per ledger** for any Soroban-active ledger: once at
`LedgerManagerImpl.cpp:2862` (used as `sorobanConfig` for parallel apply
phase) and again at `LedgerManagerImpl.cpp:3329` (assigned to
`finalSorobanConfig` used by the `inMemoryStateUpdateFuture` and returned to
the caller). The second call is unconditional and unchanged-config aware:
even when no upgrade modified any `CONFIG_SETTING` entries, the function
still rereads all ~17 settings. For ledgers without Soroban config upgrades
(the common case, including every soroswap apply-load ledger), the second
load is redundant: the config produced by the second call is identical to
the first.

## Trigger

Run the soroswap apply-load benchmark and inspect the `loadFromLedger` Tracy
zone count: it reports 287 invocations across 71 closed ledgers (~4 calls
per ledger, including upgrade validation paths in `applySequentialPhase`).
The duplicated finalize-time call is one of those per-ledger invocations and
runs on the synchronous apply critical path between `getAllEntries` and
`addLiveBatch`. Caching the result of the first call and reusing it when no
Soroban config upgrade was applied should eliminate the second call entirely
for the benchmark workload (which applies no upgrades).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2857-2863` — first per-ledger
  `SorobanNetworkConfig::loadFromLedger` in `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:3322-3330` — second per-ledger
  `SorobanNetworkConfig::loadFromLedger` in `finalizeLedgerTxnChanges`.
- `src/ledger/NetworkConfig.cpp:1754-1788` — `loadFromLedger` body with ~17
  per-setting `ls.load(key)` calls.

## Evidence

- The full `loadFromLedger` Tracy zone reports 8.31 ms total across 287
  invocations on the soroswap diagnostic trace, i.e. ~29 µs per call.
- Two `loadFromLedger` invocations per ledger therefore contribute on the
  order of 60 µs of serial apply-thread work per ledger.
- The comment at `LedgerManagerImpl.cpp:3323-3325` acknowledges that the
  second load exists specifically to capture **post-upgrade** state. For
  ledgers without a Soroban config upgrade (i.e., `sv.upgrades` does not
  include any setting that affects Soroban config), the first load's result
  is still authoritative.

## Anti-Evidence

- Per-ledger savings of ~60 µs against a 272 ms soroswap baseline is
  ~0.022% — three orders of magnitude below the 3% Medium threshold and
  well within benchmark noise.
- Even if upgrades did occur, the second call is required only when one of
  the upgrades actually modifies a `CONFIG_SETTING`; without a precise check
  the safety fallback would have to retain the second load, capping savings
  at the (much smaller) "no upgrade" fraction of ledgers.
- Other recently-rejected ledger hypotheses in the same magnitude band
  (`014-defer-bucket-file-write-mergeinmemory.md`,
  `015-skip-prefetch-when-all-buckets-cacheresident.md`,
  `016-eliminate-inner-ltxinner-in-commitchanges.md`) have set a clear
  precedent that sub-1% wins are not accepted, even when the diff is
  clean.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/success/hypothesis file targets the
duplicate `SorobanNetworkConfig::loadFromLedger` in `finalizeLedgerTxnChanges`.

### Why It Failed

The per-ledger cost of the redundant second `loadFromLedger` is on the order
of 30 µs, which is roughly 0.01% of the 272 ms soroswap apply baseline.
Eliminating it entirely cannot move the benchmark needle above noise and is
nowhere near the 3% Medium threshold required by the objective. The
objective explicitly excludes Low (1–3%) and sub-1% findings at the
hypothesis stage.

### Lesson Learned

For per-ledger setup/teardown work, the Medium threshold (~8 ms/ledger on
the 272 ms soroswap baseline) requires the targeted zone to consume at least
that much wall time on the apply critical path. A handful of small
`ls.load(key)` lookups against an in-memory bucket snapshot do not approach
this scale even when invoked redundantly. Future ledger-config hypotheses
should target the unique-keys-loaded count per ledger (low hundreds), not
the loadFromLedger invocation count.
