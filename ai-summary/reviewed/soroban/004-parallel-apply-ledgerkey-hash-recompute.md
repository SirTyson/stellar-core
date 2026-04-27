# H004: Parallel-apply maps recompute LedgerKey hashes for every per-footprint-key access; precompute and cache hashed footprint keys on TxBundle

**Date**: 2026-04-28
**Subsystem**: soroban (parallel apply)
**Severity**: Medium (potentially High)
**Impact**: Apply-time reduction; soroswap (CONTRACT_DATA-heavy footprints) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Within a single transaction's apply, the set of `LedgerKey`s used to probe
the parallel-apply maps (`mTxEntryMap`, `mThreadEntryMap`, `mRoTTLBumps`)
is fixed by the transaction's declared footprint at envelope construction
time. The *hash* of each footprint `LedgerKey` is a pure function of
immutable bytes (the XDR representation of the key plus the SCVal in
`CONTRACT_DATA` keys) and is identical across every probe of every map
for the duration of that transaction's lifetime. The expected efficient
implementation is to compute each footprint key's hash exactly once and
reuse it for every probe — analogous to how `ParallelApplyLedgerKey`
*already* memoizes its `mHash`, but for the *map-stored* key, not for
the lookup key.

## Mechanism

`ThreadParallelApplyLedgerState::getLiveEntryOpt` (ParallelApplyUtils.cpp:1085),
`upsertEntry` (1124), `eraseEntry` (1147), `commitChangeFromSuccessfulTx`
(1165), `flushRoTTLBumpsInTxWriteFootprint` (1010), and
`TxParallelApplyLedgerState::getLiveEntryOpt` / `upsertEntry` /
`eraseEntryIfExists` (1295/1316/1335) all do the same thing:

```cpp
ParallelApplyLedgerKey parallelKey(key);   // mHash = 0
auto it = mSomeMap.find(parallelKey);      // computes hash once for this stack-local instance, then discards it
```

Because the `ParallelApplyLedgerKey` is constructed fresh on the stack
on every call, the cached `mHash` slot is reset to 0 and the hash is
recomputed from scratch on every map probe. For `CONTRACT_DATA` keys
(which dominate soroswap footprints), `std::hash<LedgerKey>` performs
`shortHash::xdrComputeHash(lk.contractData().key)`, i.e. it serializes
the SCVal to a temporary byte buffer via `xdr_to_opaque` and then runs
SipHash over those bytes — hundreds of nanoseconds per call, with
allocation churn. The `mHash` cache on the *stored* keys (the ones
inside the map) saves only equality comparisons during probing, not the
lookup-side hash work, and is wasted entirely for the (very common)
miss case in `mRoTTLBumps`.

For a soroswap measured ledger (4000 swaps × ~10 footprint keys each ×
multiple accesses per key per tx — read during op setup, read during
host invocation, write/upsert, then again during `commitChangesFromSuccessfulTx`
-> `getLiveEntryOpt` and `mThreadEntryMap.try_emplace`), hash
recomputation runs into the 100k+ range per measured ledger. At ~500
ns/hash this is on the order of 50–100 ms per ledger — 8–16% of the
620 ms median.

The fix: precompute a `ParallelApplyLedgerKey` (with primed `mHash`)
for every key in `sorobanData.resources.footprint.{readOnly,readWrite}`
and the corresponding TTL keys exactly once — at `TxBundle` construction
or lazily on first apply-path access — then thread those cached
instances through `getLiveEntryOpt`/`upsertEntry`/`eraseEntry`/
`flushRoTTLBumps...`/`commitChangeFromSuccessfulTx` instead of fresh
`ParallelApplyLedgerKey(key)` constructions. Since every map key in
the parallel-apply data structures is one of those footprint or
TTL-derived keys, every probe becomes free of XDR-serialization work.

## Trigger

Run the soroswap apply-load benchmark (4000 swaps / ledger × 8 clusters).
In a Tracy zone hierarchy under `applyLedger` -> `applyParallelPhase` ->
`applyThread`, time spent in `std::hash<LedgerKey>` and
`shortHash::xdrComputeHash` will be observable on every map probe inside
the inner loop.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1085-1092` —
  `ThreadParallelApplyLedgerState::getLiveEntryOpt`: fresh
  `ParallelApplyLedgerKey(key)` -> `mThreadEntryMap.find(parallelKey)`.
- `src/transactions/ParallelApplyUtils.cpp:1124-1145` — `upsertEntry`:
  fresh `ParallelApplyLedgerKey(key)` -> `mThreadEntryMap.try_emplace`.
- `src/transactions/ParallelApplyUtils.cpp:1147-1162` — `eraseEntry`:
  same pattern.
- `src/transactions/ParallelApplyUtils.cpp:1003-1039` —
  `flushRoTTLBumpsInTxWriteFootprint`: per RW footprint key, builds a
  TTL key via `getTTLKey(lk)`, then constructs a fresh
  `ParallelApplyLedgerKey(ttlKey)` -> `mRoTTLBumps.find(...)`. The TTL
  key is also derivable once per footprint and cacheable.
- `src/transactions/ParallelApplyUtils.cpp:1295-1314, 1316-1352` —
  `TxParallelApplyLedgerState::getLiveEntryOpt`/`upsertEntry`/
  `eraseEntryIfExists`: same pattern on `mTxEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:1241-1252` —
  `commitChangesFromSuccessfulTx`: per modified entry, calls
  `getLiveEntryOpt(key)` (hash) and `commitChangeFromSuccessfulTx`
  (which probes again).
- `src/transactions/ParallelApplyUtils.cpp:239-252` — `buildRoTTLSet`:
  built per tx; could share precomputed TTL `ParallelApplyLedgerKey`s
  with `flushRoTTLBumpsInTxWriteFootprint`.
- `src/transactions/TransactionFrameBase.h:47-91` —
  `ParallelApplyLedgerKey` definition; already memoizes `mHash`. The
  hypothesis is that the codebase intends for this cache to be
  effective, but the stack-local construction pattern defeats it.
- `src/ledger/LedgerHashUtils.h:178-185` — the expensive
  `xdr::shortHash::xdrComputeHash(lk.contractData().key)` path that the
  cache should sidestep.

## Evidence

- `ParallelApplyLedgerKey::hash()` (TransactionFrameBase.h:66-75)
  explicitly memoizes `mHash` — the codebase already recognizes that
  this hash is expensive, but the memoization slot is unused on every
  lookup-side construction.
- All map-probe sites in `ParallelApplyUtils.cpp` follow the
  `ParallelApplyLedgerKey parallelKey(key); mMap.find(parallelKey);`
  pattern (8+ sites) — proves the pattern is systemic, not isolated.
- For CONTRACT_DATA keys (soroswap's case), each hash recomputation
  walks the SCVal via `xdr_to_opaque`, allocates a temporary byte
  buffer, then runs SipHash. Token-balance SCVals are non-trivial
  structures (typically a `Vec` of `Symbol("Balance"), Address`).
- `flushRoTTLBumpsInTxWriteFootprint` runs per tx for every RW
  footprint key, and `mRoTTLBumps` is largely empty for soroswap (no
  cross-tx RO TTL extension) — so the hash work is *pure overhead* in
  the common-case miss.
- The H001 (bucket scan polymorphic wrapper) and H003 (footprint dedup)
  hypotheses establish that `xdr::shortHash::xdrComputeHash(SCVal)` is
  a measurably hot operation in this benchmark — the same root cause
  appears here in a third independent code path.
- TxBundle is constructed once per tx and lives for the entire apply
  phase, so adding a small `vector<ParallelApplyLedgerKey>` of cached
  footprint/TTL keys is a clean place to memoize.

## Anti-Evidence

- Some lookup keys are *not* in the declared footprint — e.g.
  `eraseEntryIfExists` may be called on synthesized keys, and host-side
  storage operations may construct keys at runtime. Cached lookups only
  help when the lookup key matches a precomputed footprint entry; the
  fallback path must remain. However, for CONTRACT_DATA accesses the
  Soroban host's storage layer requires every accessed key to be in
  the footprint (enforcing mode), so the fast path covers the dominant
  case.
- Threading the cached key down through call sites is API-invasive: it
  may require new overloads on `getLiveEntryOpt`/`upsertEntry`/etc. that
  accept `ParallelApplyLedgerKey const&` instead of `LedgerKey const&`.
  This is mechanical and low-risk but touches many files.
- The `mHash` cache is `mutable` and computed lazily — it is *thread
  local* in the sense that two threads racing to compute it would both
  write the same value, but writing twice to the same `size_t` is a
  technical data race per the C++ memory model. If the cached
  `ParallelApplyLedgerKey` instances are shared across threads (e.g.
  stored on `TxBundle` accessed by the apply thread and by tx-set
  construction simultaneously), `mHash` must be primed on the
  construction thread before any concurrent reader accesses it.
  Priming during `TxBundle` construction (single-threaded) before
  `applySorobanStageClustersInParallel` launches the apply threads
  satisfies this.
- An alternative simpler fix is to upgrade the map's `Hash` policy to
  use `LedgerKey::hash()` *cached on the stored key only* (already the
  case) and rely on a different pattern — but that does not solve the
  lookup-side recomputation, which is the bulk of the work for
  reads/lookups.
- Determinism is preserved: hashes are deterministic by construction,
  and caching does not change observed values, only avoids recomputation.
- Concurrency: no change to thread count, no new locks; cached keys are
  read-only after priming.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed lookup-side recomputation exists: parallel apply repeatedly constructs fresh `ParallelApplyLedgerKey` objects from immutable footprint keys before probing `mTxEntryMap`, `mThreadEntryMap`, `mGlobalEntryMap`, `mRoTTLBumps`, and per-transaction read/write TTL sets. The existing `ParallelApplyLedgerKey::mHash` cache is effective only within each temporary object or stored key; it does not carry across repeated lookups that start from `LedgerKey const&`. The soroswap benchmark exercises this path for every transaction during stage setup, footprint loading, host-output writeback, metadata/invariant delta construction, and per-transaction commit, with footprints containing six `CONTRACT_DATA` keys plus two `CONTRACT_CODE` keys. The exact original wording overstates `shortHash::xdrComputeHash` by saying it allocates, but the repeated SipHash/XDR walk is real, and nearby TTL derivation via `getTTLKey` does allocate and SHA256 the XDR key repeatedly.

### Code Paths Examined

- `src/transactions/TransactionFrameBase.h:47-79,385-392` — `ParallelApplyLedgerKey` stores a mutable lazy `mHash`, and `std::hash<ParallelApplyLedgerKey>` delegates to `key.hash()`.
- `src/ledger/LedgerHashUtils.h:178-184` — `std::hash<LedgerKey>` for `CONTRACT_DATA` mixes the contract address, `shortHash::xdrComputeHash(lk.contractData().key)`, and durability.
- `src/crypto/ShortHash.h:35-55` — `xdrComputeHash` archives directly into SipHash without a temporary opaque buffer; this corrects part of the hypothesis but does not remove the repeated hashing cost.
- `src/ledger/LedgerTypeUtils.cpp:31-37` — `getTTLKey` derives TTL keys with `sha256(xdr::xdr_to_opaque(e))`, making repeated TTL-key construction an adjacent and cacheable cost.
- `src/transactions/ParallelApplyUtils.cpp:104-132,238-252` — `getReadWriteKeysForStage` and `buildRoTTLSet` rebuild `ParallelApplyLedgerKeySet`s from footprint keys and derived TTL keys.
- `src/transactions/ParallelApplyUtils.cpp:952-982` — `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` constructs one temporary `ParallelApplyLedgerKey` per footprint/TTL key to probe both thread and global maps during cluster setup.
- `src/transactions/ParallelApplyUtils.cpp:1003-1038` — `flushRoTTLBumpsInTxWriteFootprint` recomputes TTL keys and probes `mRoTTLBumps` for every RW Soroban key before every transaction.
- `src/transactions/ParallelApplyUtils.cpp:1084-1162` — thread-level `getLiveEntryOpt`, `upsertEntry`, and `eraseEntry` recreate lookup keys for `mThreadEntryMap`.
- `src/transactions/ParallelApplyUtils.cpp:1165-1195,1235-1251` — committing successful transaction changes re-enters thread-level lookup/upsert/erase paths even though the modified-entry map iterator already has cached `ParallelApplyLedgerKey` keys.
- `src/transactions/ParallelApplyUtils.cpp:1294-1350` — transaction-level `getLiveEntryOpt`, `upsertEntry`, and `eraseEntryIfExists` recreate lookup keys for `mTxEntryMap`; misses then call the thread-level lookup, causing another fresh key/hash.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-553,640-720` — `addFootprint` and `recordStorageChanges` are the dominant invoke-host-function C++ bridge paths that call `getLedgerEntryOpt`/`upsertLedgerEntry` over declared footprint keys and returned modified entries.
- `src/ledger/LedgerManagerImpl.cpp:2484-2511` — each Soroban apply worker flushes RO TTL bumps, runs `parallelApply`, and commits changes for every transaction in the cluster.
- `src/simulation/ApplyLoad.cpp:3447-3475` — each soroswap tx declares five RO keys and five RW keys, including six `CONTRACT_DATA` keys and two `CONTRACT_CODE` keys that also have TTL keys.

### Findings

The inefficiency is real and in the objective hot path. With 4000 soroswap swaps per measured ledger, the code performs repeated per-transaction map lookups over immutable footprint keys in `applyThread` and repeated per-stage setup lookups before launching cluster workers. For live Soroban entries, `TxParallelApplyLedgerState::getLiveEntryOpt` commonly hashes the same `CONTRACT_DATA` key once for the empty/mostly-empty transaction map and again after falling through to `ThreadParallelApplyLedgerState::getLiveEntryOpt`; writeback and commit add more lookups over the same keys.

Existing mitigations do not cover this issue. The maps reserve capacity to reduce rehashing, `ParallelApplyLedgerKey` caches only the hash of each object instance, and recent read-only preloading reduces fallthrough to `InMemorySorobanState`, but none of these reuse the lookup-side hash when each access starts by constructing a new `ParallelApplyLedgerKey`. `recordStorageChanges` already uses a linear scan over the small RW footprint to avoid an extra hash set, which is a useful pattern for the PoC: locating cached footprint entries by known footprint position or by the existing scan result is preferable to adding another unordered lookup that would itself rehash the key.

The proposed fix is correctness-preserving if implemented carefully. Footprint keys are immutable for the transaction, TTL keys are deterministic derivatives of those keys, and cached `ParallelApplyLedgerKey` values can be treated as read-only after construction. Because `mHash` is mutable and not atomic, the PoC should prime cached hashes before worker threads can read them, or keep cached objects strictly thread-local; it must also preserve fallback overloads for synthesized/non-footprint keys and any error paths.

The expected impact is Medium rather than High. The hypothesis's 50-100 ms estimate is plausible only if the PoC also removes repeated `getTTLKey` derivations and threads cached `ParallelApplyLedgerKey const&` values through the high-volume C++ bridge/read/writeback paths, not if it only changes one or two map probes. The direct repeated `CONTRACT_DATA` map hashes plus repeated TTL derivations are frequent enough to plausibly exceed the 3% objective threshold on soroswap, but this is not a dominant redesign of close-ledger apply.

### PoC Guidance

- **Target code**: add cached footprint-key and TTL-key storage to `TxBundle` (`src/transactions/ParallelApplyStage.h`) or an equivalent per-apply transaction context; add overloads in `src/transactions/ParallelApplyUtils.h/.cpp` for `TxParallelApplyLedgerState` and `ThreadParallelApplyLedgerState` methods that accept `ParallelApplyLedgerKey const&`; route cached keys through `InvokeHostFunctionOpFrame.cpp` add-footprint and writeback paths, `flushRoTTLBumpsInTxWriteFootprint`, `buildRoTTLSet`, and successful-tx commit.
- **Change description**: precompute `ParallelApplyLedgerKey` for every RO/RW footprint key and for every corresponding TTL key once per `TxBundle`, prime `hash()` on those objects before `applySorobanStageClustersInParallel` launches workers, and use those cached objects for map probes. Avoid building an unordered `LedgerKey -> cached-key` lookup unless it can be proven not to reintroduce the same hash cost; prefer footprint-index-based access and the existing small-footprint linear scans where possible.
- **Correctness check**: preserve existing `LedgerKey const&` fallbacks for non-footprint/synthesized keys, ensure `LedgerKey` equality and observable ledger/meta ordering are unchanged, and verify protocol-26 parallel apply, invoke-host-function, restore-footprint, TTL bump, and invariant-delta paths still use the same ledger entries and result codes.
- **Benchmark focus**: run the soroswap apply-load matrix with the default 4000 swaps / 8 clusters and compare top-line `ledger.close` apply time across repeated runs. Secondary phase timers to inspect are `build_tx_bundles`, cluster setup/thread-state construction, `transaction.apply`, and any Tracy zones around `getTTLKey`, `std::hash<LedgerKey>`, `TxParallelApplyLedgerState::getLiveEntryOpt`, and `ThreadParallelApplyLedgerState::getLiveEntryOpt`; the expected improvement target is 3-10% if both cached hashes and cached TTL keys are threaded through the hot paths.
