# H005: Eliminate polymorphic dispatch + per-lookup heap alloc in `InMemorySorobanState::get`

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (ledger / InMemorySorobanState)
**Severity**: Low (sub-threshold)
**Impact**: apply-time reduction (per-lookup overhead on Soroban entry probes)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InMemorySorobanState::get(LedgerKey const& key)` should be the fast path for
all in-memory Soroban entry probes from the apply thread / cluster workers.
For `CONTRACT_DATA`, the expected cost should be a single hash lookup
keyed by an already-computed TTL-key SHA256 (or equivalent stable key), with
no per-lookup heap allocation, no virtual dispatch, and no SHA256 recomputed
over a stored entry to satisfy bucket equality semantics. The
`mContractDataEntries` index already has the same access pattern as the
non-polymorphic `mContractCodeEntries` (a plain `unordered_map<uint256, ...>`)
and should perform identically.

## Mechanism

`InternalContractDataMapEntry` (`src/ledger/InMemorySorobanState.h:107-284`)
wraps two heap-allocated subclasses (`QueryKey`, `ValueEntry`) behind
`std::unique_ptr<AbstractEntry>`. A `get()` lookup constructs a
`QueryKey(key)` on the stack but then heap-allocates the `AbstractEntry`
inside `mContractDataEntries.find(InternalContractDataMapEntry(key))` (see
the wrapper constructor in the header). The bucket-equality probe between
the temporary `QueryKey` and the stored `ValueEntry` calls
`ValueEntry::copyKey()`, which recomputes
`getTTLKey(LedgerEntryKey(*entry.ledgerEntry))` — a fresh SHA256 over the
stored entry's contract-data key — on every collision check. Two virtual
calls, one heap allocation, and (worst-case) one redundant SHA256 per
probe replace what could be a single `uint256` hash and one map lookup.

## Trigger

Run the soroswap apply-load benchmark. Profile `InMemorySorobanState::get`
self-time and call count. The pre-load loop in
`ParallelApplyUtils.cpp:fetchSorobanReadOnlyEntries` (lines 640-718) and
the worker-fallback path in
`ThreadParallelApplyLedgerState::getLiveEntryOpt`
(`src/transactions/ParallelApplyUtils.cpp:1085-1121`, line 1113) plus the
sequential-apply fallback at `LedgerTxn.cpp:3680-3729` all funnel through
`InMemorySorobanState::get`.

## Target Code

- `src/ledger/InMemorySorobanState.h:107-284` — polymorphic
  `InternalContractDataMapEntry` design with `unique_ptr<AbstractEntry>`,
  `QueryKey`, `ValueEntry::copyKey()` (SHA256 recompute).
- `src/ledger/InMemorySorobanState.cpp:206-238` — `get()` implementation
  that constructs the wrapper and probes `mContractDataEntries`.
- `src/transactions/ParallelApplyUtils.cpp:1113` — worker fallback
  callsite.
- `src/transactions/ParallelApplyUtils.cpp:743` — code comment
  explicitly acknowledges "InMemorySorobanState.get() does SHA256 per
  CONTRACT_DATA key", motivating the `mIsNew` flag that already
  shields the commit path.

## Evidence

- The companion `mContractCodeEntries` field on the same class uses a
  plain `unordered_map<uint256, ...>` keyed by the contract-code hash and
  exhibits none of this overhead — the design difference is a vestige of
  CONTRACT_DATA's TTL-key indirection, not a hard constraint.
- The existing `mIsNew` workaround in `commitChangesToLedgerTxn` was
  specifically introduced to avoid these probes on the bulk commit path,
  showing that maintainers already considered the per-key cost worth
  engineering around.

## Anti-Evidence

- Soroswap's hot read-only Soroban entries (router instance, pair
  instance, both Wasms) are bulk-preloaded into
  `GlobalParallelApplyLedgerState::mGlobalEntryMap` via
  `collectClusterFootprintEntriesFromGlobal`, so per-tx worker calls to
  `getLiveEntryOpt` find them in `mThreadEntryMap` first and never reach
  the `InMemorySorobanState::get` fallback.
- Per-tx RW entries (token balance pairs, reserves) hit the global
  preload exactly once per cluster — first-touch only — then live in
  `mThreadEntryMap` for the remainder of the cluster.
- Sequential-apply path at `LedgerTxn.cpp:3680-3729` is not exercised
  for parallel-eligible Soroban txs in soroswap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — neither the polymorphism removal nor the TTL-key
SHA256 caching variant appears in any prior fail/hypothesis/reviewed/poc
record (greps for `InternalContractDataMapEntry`, `polymorphic`,
`copyKey`, `QueryKey` over `ai-summary/`).

### Why It Failed

Sizing per cluster per ledger (cluster=8, ~2000 Soroban txs/ledger):
- Pre-load loop (`fetchSorobanReadOnlyEntries`): ~5 unique RO keys/tx
  × 250 txs/cluster = ~1250 RO probes, but dedup via `mGlobalEntryMap`
  reduces unique misses to ~50/cluster = 400/ledger.
- Worker first-touch RW fallback: ~5 unique RW keys × 8 clusters = 40
  fallback probes/ledger.
- Sequential-apply path: 0 calls in soroswap (Soroban txs are all
  parallel-eligible).

Total ≈ 440 `InMemorySorobanState::get(CONTRACT_DATA)` calls per ledger.
At ~300–500 ns per probe of overhead removable by depolymorphization
(2 virtual calls + 1 unique_ptr alloc/free + 1 stored-entry SHA256),
upper bound ≈ 440 × 500 ns = **0.22 ms/ledger**, ≈ **0.1% of the 211 ms
soroswap baseline** — two orders of magnitude below the Medium (3%) and
Low (1%) floors, and well below the 1% benchmark-noise threshold.

The aggregate-vs-critical-path distinction does not help here: even if
every probe were on the critical path of a different cluster (impossible
— pre-load is serial), the bound stays at 0.22 ms.

### Lesson Learned

When estimating a per-call overhead removal, always start with the
call-count after **dedup** by the calling stack's caches
(`mGlobalEntryMap`, `mThreadEntryMap`). The InMemorySorobanState
fallback path is heavily shielded by upstream caches; targeting its
per-probe cost has been a recurring temptation but is structurally
sub-Medium. Future hypotheses on this class should instead consider
whether the *whole-class* representation could be changed to make
`updateState` (the apply-path async writer) materially cheaper, since
that path iterates ALL modified entries per ledger and has no upstream
dedup.
