# H003: Pre-cache TTL Key Alongside ParallelApplyLedgerKey Hash

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-entry SHA256+XDR work on parallel apply hot path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban CONTRACT_DATA / CONTRACT_CODE footprint key processed in
parallel apply, the corresponding `TTL` key (which is just
`SHA256(xdr_to_opaque(lk))` wrapped in a `LedgerKey`) should be computed
**at most once per ledger** and reused across all subsequent uses (RO TTL
read, TTL bump flush, cluster footprint collection, commit). Since
`ParallelApplyLedgerKey` already caches its own hash in a `mutable size_t
mHash{0}` field (TransactionFrameBase.h:47-80), the natural extension is to
also memoize the derived TTL `LedgerKey` next to it (lazy, single-shot).

## Mechanism

Today `getTTLKey(lk)` (LedgerTypeUtils.cpp:31) re-runs
`xdr::xdr_to_opaque(e)` + `sha256(...)` every time. It is called from at
least 7 sites in `ParallelApplyUtils.cpp` (lines 127, 249, 691, 781, 794,
980, 1017), several of which fire per-RW-footprint-entry per-tx inside
`flushRoTTLBumpsInTxWriteFootprint` and `collectClusterFootprintEntriesFromGlobal`.
A previous commit (`f1d4e7a22 perf: cache getTTLKey computation in
ThreadParallelApplyLedgerState`) appears to have been reverted or narrowed
during the subsequent `c99134971 fix: three correctness bugs` work, leaving
the call sites uncached.

## Trigger

Run the soroswap apply-load benchmark; each Soroban tx has 3-5 RW footprint
entries and triggers 2-3 `getTTLKey` calls per entry per tx across the
parallel apply pipeline (collect, flush bumps, commit).

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:980` — `collectClusterFootprintEntriesFromGlobal` calls `getTTLKey(key)` fresh
- `src/transactions/ParallelApplyUtils.cpp:1017` — `flushRoTTLBumpsInTxWriteFootprint` constructs fresh `ttlParallelKey(ttlKey)` per RW entry per tx
- `src/transactions/ParallelApplyUtils.cpp:127,249,691,781,794` — other raw getTTLKey sites
- `src/ledger/LedgerTypeUtils.cpp:31` — `getTTLKey` uncached
- `src/transactions/TransactionFrameBase.h:47-80` — `ParallelApplyLedgerKey` with existing hash cache (natural site to add `mutable std::optional<LedgerKey> mTTLKey`)

## Evidence

- 7 raw `getTTLKey(...)` call sites remain in `ParallelApplyUtils.cpp`.
- Past success #004-parallel-apply-ledgerkey-hash-recompute proved that
  caching the *LedgerKey hash* on the same struct landed ~5ms savings.
- Tracy: `sha256` self = 697ms across the trace; a non-trivial fraction
  originates in getTTLKey-invoked hashes.

## Anti-Evidence

- Soroswap RW footprint per tx is small (≤5 entries), and the parallel apply
  layer divides work across `NUM_CLUSTERS=8` worker threads, so per-ledger
  serial saving is small.
- Prior fail `001-cache-ttl-key-per-footprint-entry` (per fail/summary.md
  meta-pattern #5) already capped SHA256/TTL savings at ≤0.67% apply time.
- The `c99134971` correctness fix may indicate non-trivial subtleties (TTL
  key identity across cluster boundaries) that would re-emerge.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — incremental over success #004 and fail #001 but the
                  *combined* hash+TTL caching on `ParallelApplyLedgerKey`
                  was not separately rejected. Still self-rejected on
                  magnitude grounds.

### Why It Failed

Meta-pattern #5 from `fail/soroban/summary.md` caps the SHA256/TTL
budget for the entire apply path at ~0.67% of soroswap apply time
(roughly 1.5ms against the 230ms median). Even fully eliminating every
remaining `getTTLKey` call would not cross the **Medium ≥ 3%** threshold
the objective requires at the hypothesis stage. The work is bounded by
the same ceiling that defeated `001-cache-ttl-key-per-footprint-entry`.
Adding a second `mutable` field to `ParallelApplyLedgerKey` increases the
hot-struct size and changes copy/move costs on the very same path; the
net would likely be wash-or-worse.

### Lesson Learned

`ParallelApplyLedgerKey` is already at the right size/shape for its role.
Further per-key memoization needs to attack a *new* costly derived value
(not another hash), and any such derived value must independently exceed
the SHA256 budget ceiling to clear the Medium threshold. The
`f1d4e7a22 → c99134971` revert pattern in git history is itself
evidence that adding state to this struct is risky and was previously
required to be unwound.
