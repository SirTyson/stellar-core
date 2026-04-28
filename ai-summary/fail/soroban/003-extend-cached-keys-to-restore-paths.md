# H003: Extend Cached `ParallelApplyLedgerKey` Hashes to Restore / Autorestore / TTL-Extension Fallback Paths

**Date**: 2026-04-28
**Subsystem**: soroban (parallel apply lookup paths)
**Severity**: Medium
**Impact**: Apply-time reduction for soroswap parallel Soroban apply; followup to confirmed success #004
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After success `004-parallel-apply-ledgerkey-hash-recompute`, every parallel-apply
map probe over an immutable footprint key should reuse a primed
`ParallelApplyLedgerKey` whose hash was computed once per `TxBundle`. The
remaining `LedgerKey const&` overloads in the parallel-apply ledger-access
helpers were intentionally retained for keys that can be synthesized at
runtime (auto-restore/restore handling, TTL-extension lookups for restored
entries, hot-archive entry restoration). Those code paths still pay full
per-probe `std::hash<LedgerKey>` recomputation on what is, in practice, the
same set of footprint keys already cached on each `TxBundle`.

The expected efficient implementation is to route all parallel-apply lookups
performed on behalf of a tx — including the restore, autorestore, TTL-extension,
and hot-archive paths — through the cached `ParallelApplyLedgerKey` indexed by
footprint position, falling back to the slow `LedgerKey const&` overload only
for keys that are genuinely synthesized (e.g. transient TTL keys for entries
not in the declared footprint).

## Mechanism

Success #004 introduced `CachedTxFootprintKeys` (`ParallelApplyStage.h:18-245`)
that pre-computes `ParallelApplyLedgerKey` for every footprint key plus the
deterministic TTL key for each Soroban entry. Hot paths in stage setup,
read-materialization, host-output writeback, RO TTL flushing, and
successful-tx commit were updated to use the cached overloads.

The completion of that work explicitly called out a follow-up:
> "Investigate whether remaining `LedgerKey const&` fallback calls in
> restore/TTL-extension helpers can be routed through footprint-indexed
> cached keys without adding linear-scan overhead."
(`ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md:107`)

The fallback paths still exist in:

1. **`InvokeHostFunctionApplyHelper::handleArchivedEntry` and related restore
   logic** (`InvokeHostFunctionOpFrame.cpp:411-471`) — for archived entries the
   helper loads the TTL by constructing a fresh `LedgerKey` via `getTTLKey(lk)`
   and calling `getLedgerEntryOpt(ttlKey)` through the slow overload. The TTL
   key for the same footprint entry was already primed by
   `CachedTxFootprintKeys` for the success path; the restore path discards it
   and re-derives + re-hashes.

2. **Autorestore lookup vector** (`InvokeHostFunctionOpFrame.cpp:1283-1297`) —
   constructs auxiliary `LedgerKey` lookups for keys marked for autorestore.
   These keys are a subset of the RW footprint and are already cached on the
   TxBundle.

3. **TTL extension during invoke** — when the host returns RW TTL changes or
   restore actions, the C++ side again synthesizes TTL `LedgerKey`s and
   probes parallel state through the slow overload, even though the TTL keys
   for footprint entries are exactly the cached ones in
   `CachedTxFootprintKeys::ttlKeys`.

For the soroswap workload the hot path is mostly success-case (no archived
entries), so the restore/autorestore branches are cold. **However**, on the
write/TTL-extension side every successful invoke that extends a TTL pays a
fallback hash recomputation, and when soroswap traffic includes long-lived
balances the autorestore lookup vector is constructed for every tx that
declares an autorestore footprint extension. Tracy in the optimized baseline
still attributes 411 ms of self-time to `map lookup`
(`soroban-env-host/src/host/metered_map.rs:173`) and the C++ side shows
~50 ms of self-time spread across `getReadWriteKeysForStage` (2.8 ms) plus
the restore/TTL-extension helpers in `ParallelApplyUtils.cpp`. A meaningful
fraction of that residue is `LedgerKey` hash recomputation that the cached
keys already eliminated for the main success path.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` against the current soroswap
baseline (596.381 ms median in `CURRENT_STATE.md`) with a workload that
exercises non-trivial RW footprints with TTL extensions (the default
`soroswap, TX=4000, T=8` config exercises balance TTL bumps via SAC
`extend_contract_data_ttl` on every transfer). A PoC threading the cached
keys through the autorestore lookup table, restore TTL probes, and post-
invoke TTL-extension fallback paths should reduce per-tx hash recomputation
on the parallel apply path.

## Target Code

- `src/transactions/ParallelApplyStage.h:18-245` — `CachedTxFootprintKeys`
  already exposes `keys` and `ttlKeys` indexed by footprint position; extend
  the public API so `handleArchivedEntry` and the autorestore vector can
  retrieve the cached TTL key for a footprint index without rebuilding it.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:411-471` — restore /
  archive handling rebuilds `getTTLKey(lk)` and probes via the slow
  `LedgerKey const&` overload. Replace with a cached-overload call that
  takes the footprint index `i` already in scope.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1283-1380` —
  `mAutorestoredEntries` initialization synthesizes lookups for RW
  footprint keys that are autorestore candidates. These keys are a subset
  of `CachedTxFootprintKeys::keys` and can be referenced by index instead
  of fresh `ParallelApplyLedgerKey` construction.
- `src/transactions/ParallelApplyUtils.cpp:1084-1457` — TTL-extension and
  RW-writeback paths still have `LedgerKey const&` fallbacks for
  TTL-extension synthesizing; thread the cached overloads through where
  the originating footprint key is known.

## Evidence

- Success #004
  (`ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md`)
  confirms the parallel-apply lookup path benefits measurably from
  pre-cached `ParallelApplyLedgerKey` values: average soroswap improvement
  was 2.66% (3.96% best run) just from the footprint-success path.
- The "Suggested Follow-Up" section of that success file explicitly names
  restore/TTL-extension helpers as the next candidate.
- Optimized-baseline Tracy
  (`CURRENT_STATE.md` Tracy reference) still attributes
  ~50 ms self-time per measured ledger across `ParallelApplyUtils.cpp`
  helpers that do RW-writeback and TTL-bump probing; the dominant
  remaining cost is map probes on synthesized keys.
- The TTL key for a given footprint key is deterministic
  (`getTTLKey(lk)`), so the cached value is bit-identical to what
  `handleArchivedEntry` and the autorestore path recompute.

For an objective Medium-tier win, the increment should add ~3% on top of the
current baseline (≈18 ms / ledger ≈ 1.17 s across the 65-ledger trace
window). Even capturing half of the remaining `ParallelApplyUtils.cpp`
self-time plus a corresponding reduction in `map lookup` self-time inside
the parallel-apply hot path is plausibly enough — the same per-call
mechanism (avoiding `std::hash<LedgerKey>` recomputation on a multi-field
XDR key) that delivered #004's win still applies to these residual paths.

## Anti-Evidence

- The restore/archived path is cold for the steady-state soroswap workload;
  most of the win must come from the autorestore vector and TTL-extension
  paths, which are exercised on every successful invoke.
- `mAutorestoredEntries` is built once per tx in the parallel-apply helper
  constructor, not per-probe; the redundant work it does is per-tx setup,
  not per-lookup. The setup cost is bounded by RW footprint size
  (typically ~5 entries for soroswap), so the savings per tx are small.
  Aggregated across 4000 txs / ledger this could still clear Medium, but
  a PoC must verify with Tracy that the residual `map lookup` /
  `getReadWriteKeysForStage`-adjacent zones actually decrease.
- A naive expansion that adds a footprint-index lookup *before* every
  fallback call could regress wall time if the footprint-index map probe
  is itself expensive. The cached-key API in #004 already exposes per-key
  references via the bundle, so the expansion should be O(1) lookup by
  index, not by key.
- This hypothesis depends on success #004 staying applied. If #004 is
  reverted, this hypothesis becomes part of #004's scope.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — subsumed by `ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md`, with the TTL-key-only portion already rejected in `ai-summary/fail/soroban/summary.md` as `001-cache-ttl-key-per-footprint-entry.md`
**Failed At**: reviewer

### Trace Summary

The specific follow-up cannot be validated as a standalone optimization against the current source: `TxBundle` has no `CachedTxFootprintKeys`, and `ParallelLedgerAccessHelper` exposes only `LedgerKey const&` accessors, so "extend the cached key API to remaining fallbacks" collapses back into the already-confirmed #004 optimization. Tracing the named invoke path also disproves one claimed hot target: `mAutorestoredEntries` construction is just a `std::vector<bool>` indexed by archived-entry positions, not a ledger-key lookup vector. The remaining restore/hot-archive path does synthesize TTL keys, but it only runs for expired/archived entries marked for restore, which the hypothesis itself identifies as cold for steady-state soroswap. The post-invoke TTL/writeback work in the current tree has the broader uncached-key shape already covered by #004; any residual after #004 would be smaller than the Low-severity 2.66% average win #004 achieved and below this objective's Medium floor.

### Code Paths Examined

- `src/transactions/ParallelApplyStage.h:74-114` — current `TxBundle` stores only the transaction, result payload, tx number, and effects; there is no `CachedTxFootprintKeys` member or footprint-indexed cached-key API to extend.
- `src/transactions/TransactionFrameBase.h:47-80` — `ParallelApplyLedgerKey` caches its hash per object, but callers must retain and reuse the object; constructing a temporary from `LedgerKey const&` recomputes the hash once for that temporary.
- `src/transactions/ParallelApplyUtils.h:338-390` and `src/transactions/ParallelApplyUtils.cpp:337-342` — `LedgerAccessHelper`/`ParallelLedgerAccessHelper` only provide `getLedgerEntryOpt(LedgerKey const&)`, which delegates to `TxParallelApplyLedgerState::getLiveEntryOpt`.
- `src/transactions/ParallelApplyUtils.cpp:104-132` — `getReadWriteKeysForStage` still creates `ParallelApplyLedgerKey` objects from RW footprint keys and freshly derived TTL keys; this is part of the broad #004 key-caching scope, not a residual follow-up in the checked-out source.
- `src/transactions/ParallelApplyUtils.cpp:925-985` — thread-state setup fetches footprint and TTL keys from the global map by constructing temporary `ParallelApplyLedgerKey` objects, again matching #004's already-confirmed mechanism.
- `src/transactions/ParallelApplyUtils.cpp:1003-1039` — `flushRoTTLBumpsInTxWriteFootprint` derives `getTTLKey(lk)`, constructs a temporary `ParallelApplyLedgerKey`, then may call `getLiveEntryOpt(ttlKey)` and `upsertEntry(ttlKey, ...)`; this is a real uncached-key path in the current tree but is in the #004 RO-TTL/write-footprint scope.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` and `src/transactions/ParallelApplyUtils.cpp:1294-1314` — thread and tx `getLiveEntryOpt` create temporary `ParallelApplyLedgerKey` objects for map probes when reached through `LedgerKey const&`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:395-535` — `addReads` derives a TTL key for each Soroban footprint key, probes the ledger helper for the TTL entry, and handles live/expired/archive cases before serializing entries for the Rust host.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:654-763` — post-host writeback linearly matches returned modified ledger entries to RW footprint entries, deriving `getTTLKey(rwKeys[j])` during TTL association and deleting associated TTL entries on erase.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1115-1189` — archived-entry restore derives `getTTLKey(lk)` and updates/restores the TTL entry; this path is gated by non-read-only autorestore indices and archived/expired entries, so it is not the default soroswap success path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1270-1304` — `InvokeHostFunctionParallelApplyHelper` initializes `mAutorestoredEntries` by resizing a bool vector and setting indexed bits from `archivedSorobanEntries`; it does not synthesize or probe `LedgerKey`s.
- `ai-summary/success/soroban/004-parallel-apply-ledgerkey-hash-recompute.md:9-17,47-52,87-107` — #004 already documents precomputing footprint and TTL `ParallelApplyLedgerKey` values, adding cached-key overloads, updating invoke-host add-read/writeback/erase/autorestore and TTL flush/commit paths, and leaves only a suggested follow-up for remaining fallbacks.
- `ai-summary/fail/soroban/summary.md:9,36` — the TTL-key-cache-only mechanism was previously rejected as below threshold, with the whole in-apply SHA256 budget capped around 0.67% of apply time.

### Why It Failed

This is not a viable standalone Medium-severity hypothesis. In the current source, the prerequisite cached-key API is absent, so implementing the proposed routing would first require redoing #004 rather than extending it. If evaluated as an extension after #004, the named hot paths do not support the projected impact: `mAutorestoredEntries` does no key lookup work, restore/hot-archive handling is cold for steady-state soroswap, and residual TTL-key derivation/hash recomputation is bounded by prior records below the 3% Medium threshold. The proposal is therefore either duplicate/subsumed by #004 or a small TTL-key-cache residual that the objective explicitly rejects as below threshold.

### Lesson Learned

Do not project Medium-severity follow-ups from a Low-severity hash-caching success without first verifying the residual call sites still exist after that success is applied. For soroswap, footprint-indexed TTL/key caching can be real but is structurally bounded unless it removes work from the dominant per-success path; restore/autorestore residuals and per-footprint `getTTLKey` leftovers are too small for this objective.
