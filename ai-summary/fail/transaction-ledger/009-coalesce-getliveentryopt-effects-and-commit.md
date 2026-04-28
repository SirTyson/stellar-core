# H009: Coalesce duplicate getLiveEntryOpt lookups in setEffectsDeltaFromSuccessfulTx + commitChangesFromSuccessfulTx

**Date**: 2026-04-28
**Subsystem**: transactions (parallel apply)
**Severity**: Low
**Impact**: per-tx allocation/lookup overhead in parallel-apply per-thread commit
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each modified entry produced by a successful Soroban tx, the per-thread
state machinery should look up the prior live entry (`prevLe`) at most once
before deciding what to write into `mThreadEntryMap`/`mRoTTLBumps` and what
delta to record into the meta `TxEffects`.

## Mechanism

`ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx` and
`setEffectsDeltaFromSuccessfulTx` both iterate `res.getModifiedEntryMap()`
and both call `getLiveEntryOpt(key)` for the *same* key, returning the same
prior entry. Each `getLiveEntryOpt` call constructs a fresh
`ParallelApplyLedgerKey` (recomputing the key hash because the cached
`mHash` lives on a temporary), performs a hash-table lookup in
`mThreadEntryMap`, and on miss falls through to either `InMemorySorobanState`
or `mLCLSnapshot.loadLiveEntry`. The redundancy is purely duplicated work —
nothing in between the two iterations changes the result.

## Trigger

Any soroswap-like workload: per tx ~2-4 modified RW entries, run in parallel
clusters. Each modified entry triggers two `getLiveEntryOpt` calls that
return the same value.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1084-1121` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt`
- `src/transactions/ParallelApplyUtils.cpp:1164-1196` —
  `commitChangeFromSuccessfulTx` calls `getLiveEntryOpt(key)` to compute
  `oldEntryOpt`, then calls `upsertEntry`/`eraseEntry` which themselves do a
  third `try_emplace` on the same map slot.
- `src/transactions/ParallelApplyUtils.cpp:1198-1238` —
  `setEffectsDeltaFromSuccessfulTx` calls `getLiveEntryOpt(lk)` for the same
  key already touched by `commitChangesFromSuccessfulTx`.
- `src/transactions/TransactionFrameBase.h:47-80` —
  `ParallelApplyLedgerKey` caches its hash but only per-instance; the
  fresh temporary in `getLiveEntryOpt` recomputes the hash every call.

## Evidence

- The two functions are invoked sequentially per tx in the per-thread
  commit pipeline, so the result of the first lookup is trivially
  available to the second.
- `ParallelApplyLedgerKey(LedgerKey)` copies the LedgerKey by value and
  the temporary's hash cache (`mHash{0}`) is recomputed on every
  `find()` invocation.
- A simple refactor would be to (a) iterate `getModifiedEntryMap()` once,
  computing `prevLe` per key, and (b) hand the entry-map iterator (or
  `(key, prevLe)` tuple) to both the commit-side decision and the effects
  delta builder. Alternatively, change `getLiveEntryOpt` to accept
  `ParallelApplyLedgerKey const&` so callers iterating
  `ParallelApplyLedgerKeyMap` reuse the cached hash.

## Anti-Evidence

- Soroswap modifies only ~2-4 entries per tx, so total redundant work is
  bounded. Per-call cost is ~250-400 ns (LedgerKey copy + hash + map
  probe). At 4000 tx/ledger × 65 ledgers × 4 entries × 2 lookups = ~2.1 M
  redundant lookups → ~500-800 ms total CPU, spread across 8 worker
  threads → ~60-100 ms wall.
- 596 ms × 65 ledgers ≈ 38.7 s total benchmark wall → savings ≈ 0.2 %.
- The two functions are also called on different control-flow paths
  outside the parallel commit (e.g. effects collection only when meta is
  enabled in the relevant path); coalescing requires careful refactor of
  the per-thread post-tx pipeline to preserve correctness.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below objective severity threshold. The redundant work is real and the
refactor is structurally clean, but projected wall-time savings are
sub-1 % (≈ 0.2 %), well below the Medium 3 % bar. The footprint of the
change (touching the per-thread commit pipeline, effects delta builder,
and a public helper signature) is non-trivial relative to the win, and
the interaction with `mRoTTLBumps`/`upsertEntry` semantics raises the
review burden further. The benchmark noise floor (~1 %) would likely
swallow the delta entirely.

### Lesson Learned

For per-tx lookups inside `ThreadParallelApplyLedgerState`, the dominant
cost is not the redundant `mThreadEntryMap` probes — most calls hit the
hash table in O(1) on already-loaded clusters, and per-call cost is on
the order of a few hundred nanoseconds. To find a Medium-tier win in
the per-thread commit path, look for changes that eliminate work whose
unit cost is *much* larger (e.g., XDR copies of `LedgerEntry` payloads,
contract-data round-trips through `InMemorySorobanState`) rather than
shaving cached hash-table lookups.
