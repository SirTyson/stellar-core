# H017: Plumb Cached `ParallelApplyLedgerKey` Through Writeback and Meta-Build Paths

**Date**: 2026-04-30
**Subsystem**: soroban / parallel apply
**Severity**: Low
**Impact**: SHA256 ledger-key hashing on writeback and meta-build paths
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The cached `ParallelApplyLedgerKey` (with primed `getLedgerKeyHash` SHA256
and TTL key) that success #4 added to `TxBundle::CachedTxFootprintKeys`
should be reused everywhere a tx interacts with `mThreadEntryMap`, not
just in the read path. Specifically:

- `ThreadParallelApplyLedgerState::upsertEntry(LedgerKey const&, ...)`
  (`src/transactions/ParallelApplyUtils.cpp:1124`) should accept (or
  internally retrieve) the cached `ParallelApplyLedgerKey` for the
  current tx's footprint instead of constructing a fresh one (which
  re-runs `xdrComputeHash` over the full XDR-encoded `LedgerKey`,
  including walking the SCVal CONTRACT_DATA key tree).
- `ThreadParallelApplyLedgerState::eraseEntry(LedgerKey const&, ...)`
  (`:1147`) — same.
- `ThreadParallelApplyLedgerState::getLiveEntryOpt(LedgerKey const&)`
  (`:1085`) — same; called from
  `OperationMetaBuilder::setLedgerChangesFromSuccessfulOp`
  (`src/transactions/TransactionMeta.cpp:401`) for every modified entry
  during meta build in worker threads.

Once that wiring exists, `ParallelApplyLedgerKey(key)` (which calls
`getLedgerKeyHash(key)` → `xdrComputeHash` → SHA256) should not be
re-executed on the tx writeback or meta-build hot path.

## Mechanism

`recordStorageChanges` calls `mTxState.upsertEntry(lk, ...)` and
`mTxState.upsertEntry(ttlKey, ...)` for every modified entry of every
soroban tx (~5–10 calls per tx). Each `upsertEntry` constructs
`ParallelApplyLedgerKey parallelKey(key)` which re-hashes the
XDR-encoded key. The same redundancy exists in
`setLedgerChangesFromSuccessfulOp`'s `getLiveEntryOpt(lk)` calls (one
per modified entry per tx) and in
`InvokeHostFunctionParallelApplyHelper::handleArchivedEntry` for
auto-restore writes. These callsites all have the cached
`ParallelApplyLedgerKey` available on `TxBundle::CachedTxFootprintKeys`
but discard it.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`).
Per ledger ~70 txs × ~10 footprint entries = ~700 redundant SHA256
computations of CONTRACT_DATA / TTL keys.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1124-1145` — `upsertEntry(LedgerKey)`
- `src/transactions/ParallelApplyUtils.cpp:1147-1162` — `eraseEntry(LedgerKey)`
- `src/transactions/ParallelApplyUtils.cpp:1084-1092` — `getLiveEntryOpt(LedgerKey)`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1163-1179` — write loop in `ApplyHelper`
- `src/transactions/TransactionMeta.cpp:398-442` — `setLedgerChangesFromSuccessfulOp` modified-entry loop
- `src/transactions/TxBundle.{h,cpp}` — `CachedTxFootprintKeys` (already exists)

## Evidence

- Success #4 implemented per-TxBundle cached `ParallelApplyLedgerKey`
  with primed hash + TTL key, but only routed it through
  `addReads` / `mTxState.getLiveEntryOpt(ParallelApplyLedgerKey)`.
- `xdrComputeHash` for CONTRACT_DATA keys with non-trivial SCVal keys
  (e.g., soroswap pool keys: Vec of token addresses + symbol) walks
  the full XDR tree before SHA256 — measured as a meaningful slice of
  the per-tx setup cost in success #4 evidence.

## Anti-Evidence

Quantification under benchmark conditions:

- ~5093 txs/run × ~10 hashes/tx = ~50k redundant SHA256s/run.
- CONTRACT_DATA-key SHA256 cost ~5 µs/call (XDR walk + hash).
- Total worker CPU savings: ~250 ms/run.
- Wall-clock savings under NUM_CLUSTERS=8 parallelism:
  ~250 ms / 8 / 70 ledgers ≈ 0.45 ms/ledger.
- Apply-time impact: 0.45 ms / 278 ms ≈ **0.16 % per ledger**.

This is well below the 3 % Medium threshold and below benchmark noise
(see fail-summary meta-pattern #5: "SHA256 budget ceiling ~0.67 %").
The diff is small and clean but the win is sub-noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — success #4 only addressed the read path; writeback /
meta-build paths are unaddressed but the residual cost is too small
to clear the Medium severity floor.

### Why It Failed

The total redundant `xdrComputeHash` work outside the already-cached
read path is bounded by the per-tx footprint write count (~5 entries
+ ~5 TTLs) times tx count. Even with optimistic 5 µs/hash, total
worker CPU savings (~250 ms/run) divides by NUM_CLUSTERS=8 into well
below 1 ms/ledger — under the Low threshold (1–3 %) and far under the
Medium threshold (3 %). Same sub-threshold pattern as fail #006
(InMemory bucket scan polymorphic wrapper hash recompute) and fail
summary meta-pattern #5 (SHA256 budget ceiling).

### Lesson Learned

When extending an already-landed cache (success #N) to additional
callsites, quantify the residual unhashed-call count *before* writing
a hypothesis. The dominant term in success #4 was per-key admission
hashing during `addReads` (which runs on every footprint entry of
every tx); writeback is bounded by *modified* entries, which is
typically half the footprint or smaller, so the residual is roughly
half of what success #4 captured — and success #4 itself was already
near the Medium floor.
