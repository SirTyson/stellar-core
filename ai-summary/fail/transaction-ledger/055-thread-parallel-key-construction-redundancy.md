# H055: Thread `ParallelApplyLedgerKey` (with cached hash) through commit and read paths to skip per-step LedgerKey copy and hash recomputation

**Date**: 2026-05-22
**Subsystem**: transaction-ledger
**Severity**: Low (below objective threshold)
**Impact**: Worker per-modified-entry hot path during `commitChangesFromSuccessfulTx` and `setLedgerChangesFromSuccessfulOp`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx`
(`src/transactions/ParallelApplyUtils.cpp:1241-1252`) and its callee
`commitChangeFromSuccessfulTx` (lines 1164-1196), the iteration over
`res.getModifiedEntryMap()` yields `[ParallelApplyLedgerKey key, ...]` pairs
where `key` already carries a memoized `mHash` (computed once when the key
was inserted into the tx-scoped modified-entry map during host apply).
Downstream calls `getLiveEntryOpt(key)` and the subsequent
`upsertEntry`/`eraseEntry` should re-use that cached hash and the underlying
`LedgerKey` reference without copying or recomputing.

## Mechanism

Today, the downstream functions all take `LedgerKey const&` (line 1085, 1124,
1147) rather than `ParallelApplyLedgerKey const&`. They reconstruct a fresh
`ParallelApplyLedgerKey parallelKey(key)` inside each function (lines 1087,
1138, 1156). The `ParallelApplyLedgerKey(LedgerKey const&)` constructor
(`src/transactions/TransactionFrameBase.h:51`) copies the underlying
`LedgerKey` into `mLedgerKey` (deep-copy of `SCVal` for `CONTRACT_DATA`) and
resets `mHash` to 0; the hash is then recomputed on first lookup. The cached
hash on the key passed in by the caller is discarded.

Additionally, `OperationMetaBuilder::setLedgerChangesFromSuccessfulOp`
(`src/transactions/TransactionMeta.cpp:398-401`) iterates the same modified
entry map and calls `threadState.getLiveEntryOpt(lk)` again, paying the same
key copy + hash recomputation.

Threading `ParallelApplyLedgerKey const&` through the read and commit paths
would skip the per-step `LedgerKey` deep-copy and the per-step
`std::hash<LedgerKey>` recomputation.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:1085-1121` — `getLiveEntryOpt(LedgerKey)`
- `src/transactions/ParallelApplyUtils.cpp:1123-1162` — `upsertEntry`/`eraseEntry`
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — `commitChangeFromSuccessfulTx` / `commitChangesFromSuccessfulTx`
- `src/transactions/ParallelApplyUtils.cpp:1199-1238` — `setEffectsDeltaFromSuccessfulTx`
- `src/transactions/TransactionMeta.cpp:385-452` — `setLedgerChangesFromSuccessfulOp`
- `src/transactions/TransactionFrameBase.h:47-80` — `ParallelApplyLedgerKey`

## Evidence

- Code inspection confirms a fresh `ParallelApplyLedgerKey parallelKey(key)`
  is constructed inside `getLiveEntryOpt`, `upsertEntry`, and `eraseEntry`
  on every call.
- For each modified entry of a successful Soroban tx, the per-tx commit
  pipeline performs at minimum 2-3 hash recomputations and 2-3 deep copies
  of the `LedgerKey` (CONTRACT_DATA keys carry a full `SCVal`).
- Per `std::hash<LedgerKey>` definition in
  `src/ledger/LedgerHashUtils.h:178-184`, CONTRACT_DATA hashing involves
  `shortHash::xdrComputeHash(lk.contractData().key)` which serializes and
  hashes the `SCVal` key per call.

## Anti-Evidence

- The previously rejected H009
  (`ai-summary/fail/transaction-ledger/summary.md` row 009
  "coalesce-getliveentryopt-effects-and-commit") already enumerated the
  per-tx `getLiveEntryOpt` redundancy and projected ~0.2% wall-clock
  savings. The key-construction redundancy targeted here is a strict
  sub-component of the same code path.
- Sizing: soroswap has ~200 successful Soroban txs/ledger × ~10 modified
  entries/tx = ~2,000 modified-entry commit operations per ledger per
  worker. Even at a generous ~1µs per redundant hash + copy and ~3
  redundancies per entry, the per-worker savings are ~6ms/ledger.
  Divided by 8 clusters for critical-path normalization: ~0.75ms/ledger
  ≈ 0.27% of the 272ms soroswap median. This is well below the Low
  threshold (1%) and into benchmark noise.
- The required diff also has to update `ParallelApplyEntryMap`'s
  hash/equality predicates and audit all callers of the affected
  signatures, increasing review burden disproportionate to the win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — H009 covered lookup coalescing, not key-construction
hash/copy reuse; this is a related but distinct angle.

### Why It Failed

Critical-path savings after cluster normalization are ~0.27% of soroswap
apply time, below the 1% Low floor and well below the 3% Medium floor
required by the optimize-soroswap objective. The meta-pattern is the same
as H009 — per-tx parallel-apply commit-path micro-optimizations are
structurally bounded by aggregate worker cost / cluster count.

### Lesson Learned

`ParallelApplyLedgerKey` already memoizes its hash, but the cache is only
useful if callees take `ParallelApplyLedgerKey const&` rather than
`LedgerKey const&`. Threading the typed key through downstream signatures
would be a clarity improvement, but the apply-time impact does not justify
the review burden. Future per-tx commit-path micro-optimizations on the
parallel-apply hot path should be combined with a broader structural
change to the worker commit pipeline, not pursued in isolation.
