# H002: `addReads` performs two map lookups per soroban footprint key (TTL + data) where one combined lookup suffices, since `InMemorySorobanState` already stores TTL inline with the contract data entry

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (`InvokeHostFunctionOpFrame::addReads` ↔ parallel-apply ledger access ↔ `InMemorySorobanState`)
**Severity**: Medium
**Impact**: Apply-time reduction; soroswap (CONTRACT_DATA-heavy footprints) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Loading a soroban footprint entry should require **one** lookup through the
ledger access layers, not two. `InMemorySorobanState` explicitly stores
`TTLData` inline with the `ContractDataMapEntryT`/`ContractCodeMapEntryT`
"to avoid an additional lookup and save memory"
(`InMemorySorobanState.h:46-48`). The expected efficient implementation is
to expose a "fetch entry + TTL together" API at every layer
(`InMemorySorobanState`, `Global`/`Thread`/`TxParallelApplyLedgerState`,
`ParallelLedgerAccessHelper`) and have `addReads` consume it, so that a
single key→entry probe yields both the data and its TTL. The TTL key
should be derived only when it must be inserted into a map (e.g. for
modification) — not for read-only liveness checks against in-memory
soroban state.

## Mechanism

`InvokeHostFunctionApplyHelper::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:404-498`) currently
performs *two* separate `getLedgerEntryOpt` calls per soroban footprint
key:

```cpp
if (isSorobanEntry(lk))
{
    auto ttlKey = getTTLKey(lk);                  // hash-of-XDR derivation
    auto ttlEntryOpt = getLedgerEntryOpt(ttlKey); // LOOKUP #1 (TTL)
    ...
    sorobanEntryLive = true;
    ttlEntry = ttlEntryOpt->data.ttl();
    ...
}
if (!isSorobanEntry(lk) || sorobanEntryLive)
{
    auto entryOpt = getLedgerEntryOpt(lk);        // LOOKUP #2 (data)
    ...
}
```

`getLedgerEntryOpt` for the parallel-apply path
(`ParallelLedgerAccessHelper::getLedgerEntryOpt`,
`src/transactions/ParallelApplyUtils.cpp:336-342`) descends through
`mTxState.getLiveEntryOpt(key)`:

- `TxParallelApplyLedgerState::getLiveEntryOpt`
  (`ParallelApplyUtils.cpp:1294-1314`) constructs a
  `ParallelApplyLedgerKey(key)`, hashes it, probes `mTxEntryMap` (miss),
- falls through to `ThreadParallelApplyLedgerState::getLiveEntryOpt`
  (`ParallelApplyUtils.cpp:1084-1092`) which constructs another fresh
  `ParallelApplyLedgerKey`, hashes again, probes `mThreadEntryMap`,
- falls through to the global map / `mInMemorySorobanState.get(...)` for
  the read-only preloaded TTL/data set.

For TTL keys, `InMemorySorobanState::get(TTL)` ultimately resolves via
`getTTL` → `mTtlNonceToContractDataKeyHash` → `mContractDataEntries.find`
on the *same* `ContractDataMapEntryT` whose `ledgerEntry` field will be
returned in the second lookup for `lk`. The TTL data is sitting in the
struct *next to* the entry that the second lookup will return — yet the
two are accessed via two completely separate hash probes through three
map layers each.

Because `ContractDataMapEntryT::ttlData` is stored inline
(`InMemorySorobanState.h:50-64`) and `ContractCodeMapEntryT::ttlData` is
stored inline too (`:67-86`), a `getDataAndTTL(LedgerKey)` API on
`InMemorySorobanState` can return both with **one** lookup and **zero**
TTL-key derivation. Threading that combined-fetch API through the
parallel-apply layers (with a single combined probe at each layer) cuts
in-memory-soroban footprint reads from 2 lookups to 1.

For a soroswap measured ledger (4000 swaps × ~10 footprint keys, all
soroban): ~40 000 redundant lookups eliminated. Each lookup costs
~500–1000 ns through the layered probes (CONTRACT_DATA hash via
`shortHash::xdrComputeHash(SCVal)` + 3 hash-table probes, plus TTL key
derivation via `sha256(xdr_to_opaque(LedgerKey))` which itself is
~200–400 ns), so ~20–40 ms saved per measured ledger ≈ **3.2 – 6.5 %**
of the 620 ms median apply time. The win compounds with H004 (cached
`ParallelApplyLedgerKey`s) — H004 makes each remaining lookup cheaper,
this hypothesis halves the *number* of lookups; the two are
complementary, not overlapping.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py` with `model_tx="soroswap"`,
4000 swaps / ledger × 8 clusters). In a Tracy zone hierarchy under
`applyLedger` → `applyParallelPhase` → `applyThread` → `addReads`,
half of the footprint-load `getLedgerEntryOpt` time will collapse, as
will all `getTTLKey(lk)` derivations on the load-side path.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:404-498` — `addReads`
  performs the two separate lookups and immediately reads
  `ttlEntryOpt->data.ttl()`. Refactor to a single
  `getEntryWithTTL(lk)` call that returns
  `std::optional<std::pair<LedgerEntry, TTLData>>`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:411` —
  `auto ttlEntryOpt = getLedgerEntryOpt(ttlKey);` — the lookup to
  eliminate.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:476` —
  `auto entryOpt = getLedgerEntryOpt(lk);` — the lookup to expand into
  a combined-fetch site.
- `src/ledger/LedgerTypeUtils.cpp:31-38` — `getTTLKey` is the per-call
  SHA256+XDR derivation that the combined-fetch path can skip entirely
  on the load side (it's still needed on the write side when committing
  a TTL bump back into the map).
- `src/ledger/InMemorySorobanState.cpp:206-238` — `get(LedgerKey)`:
  add a sibling `getEntryWithTTL(LedgerKey)` that returns the cached
  `LedgerEntry` *and* the inline `TTLData`/derived TTLEntry without a
  second hash probe.
- `src/ledger/InMemorySorobanState.h:46-86` — `ContractDataMapEntryT`
  and `ContractCodeMapEntryT` already hold both fields inline; the
  combined accessor is a one-liner per type.
- `src/transactions/ParallelApplyUtils.cpp:336-342` —
  `ParallelLedgerAccessHelper::getLedgerEntryOpt` is the single bridge
  between `addReads` and the parallel-apply maps; add a sibling
  `getLedgerEntryOptWithTTL` that descends through the same layered
  fall-through but returns both pieces together.
- `src/transactions/ParallelApplyUtils.cpp:1294-1314, 1084-1092,
  952-982` — `TxParallelApplyLedgerState::getLiveEntryOpt`,
  `ThreadParallelApplyLedgerState::getLiveEntryOpt`, and the
  cluster-setup global probes; thread the combined-fetch through these
  layers (a per-tx data write modifies the data entry but not its TTL,
  and a per-tx TTL bump modifies the TTL but not the data, so the
  combined fetch still has to consult both maps but can do so with one
  lookup keyed on `lk` and an explicit TTL-bump check rather than two
  generic lookups).

## Evidence

- The InMemorySorobanState design comment is unambiguous:
  "ContractDataMapEntryT stores a ContractData LedgerEntry and its
  TTL. TTL is stored directly with the data to avoid an additional
  lookup and save memory" (`InMemorySorobanState.h:46-48`). The
  current `addReads` undermines the very optimization the storage
  layer was designed for.
- `ttlEntryOpt->data.ttl()` (line 436) is the *only* use of the TTL
  lookup result in the live-entry branch; `addReads` doesn't need the
  full TTL `LedgerEntry`, only the `TTLData`/`liveUntilLedgerSeq`
  field. A combined fetch returning `(LedgerEntry, TTLData)` is
  strictly sufficient, not a forced redesign.
- Each `getTTLKey(lk)` call walks `xdr::xdr_to_opaque(lk)` (allocates a
  vector) and runs SHA256 over the bytes
  (`src/ledger/LedgerTypeUtils.cpp:31-38`). For 40 000 calls per
  measured ledger this is on its own ~10–20 ms; combined fetch makes
  the load-side derivations vanish (TTL key derivation is still
  required on the write side, but at half the call count).
- The layered probe overhead is real: H004 (reviewed) measured the
  per-probe `ParallelApplyLedgerKey` hash recomputation as a 3-10%
  apply-time cost. Each eliminated lookup is one fewer trip through
  exactly that layered cost.
- The fall-through to `mInMemorySorobanState.get(...)` is the common
  case for soroswap RO footprints (preloaded once per stage into
  `mGlobalEntryMap` via the read-only preload phase, then read by
  every cluster's first access for that key). Eliminating one of the
  two lookups directly halves the cost of that pathway.
- Soroswap-specific: per `src/simulation/ApplyLoad.cpp:3447-3475`
  each soroswap tx footprint has 5 RO + 5 RW soroban keys
  (CONTRACT_DATA + CONTRACT_CODE). Every one currently incurs the
  double lookup; none are classic.

## Anti-Evidence

- Within a single tx, an earlier op may have bumped the TTL of a
  footprint key (TTL bump appears in `mTxEntryMap`/`mThreadEntryMap`
  even though the data hasn't changed). The combined fetch must still
  consult the per-tx/thread maps for the TTL key — but it can do so
  using the *cached* TTL key (this is exactly the H004 cache, so the
  two hypotheses compose cleanly), and only one map probe per layer
  for the combined fetch instead of two. Net: still a 50 % reduction
  in lookup count, not an elimination.
- For classic entries (accounts, trustlines), there is no TTL and the
  combined-fetch API simply returns `(LedgerEntry, std::nullopt)`. No
  regression.
- Some non-`addReads` callers of `getLedgerEntryOpt` will not benefit
  (e.g. `recordStorageChanges` doesn't fetch TTLs). The combined API
  is opt-in: existing single-fetch sites keep using
  `getLedgerEntryOpt` unchanged.
- `handleArchivedEntry` (`InvokeHostFunctionOpFrame.cpp:421-...`) does
  a separate `getLedgerEntryOpt(lk)` for the archived path. That path
  is rare in soroswap (entries don't expire mid-benchmark) so leaving
  it as-is is acceptable.
- API churn touches several layers
  (`InMemorySorobanState`, `LedgerAccessHelper` hierarchy,
  `Global`/`Thread`/`TxParallelApplyLedgerState`). The diff is
  mechanical (parallel sibling methods to existing ones) but
  non-trivial in line count. The hypothesis remains Medium because
  the lookup-count halving is a structural win rather than a
  micro-optimization.
- Determinism is preserved: combined fetch returns the same data and
  TTL the two separate fetches would return today, drawn from the
  same maps in the same priority order.
- Concurrency is preserved: combined fetch reads the same per-thread
  / global / in-memory state with the same locking discipline as the
  current two-call version. No new shared state.
