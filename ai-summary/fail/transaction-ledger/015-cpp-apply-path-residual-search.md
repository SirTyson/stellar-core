# H015: Residual C++ apply-path search after Soroban-host hypotheses are reviewed

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (apply path: InvokeHostFunctionOpFrame, ParallelApplyUtils, LedgerManagerImpl, TransactionMeta)
**Severity**: Low
**Impact**: residual per-tx C++ overhead in `applyLedger` outside the Soroban host
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After accepting the five Soroban-host hypotheses currently in
`ai-summary/reviewed/transaction-ledger/` (ValSer charge batching, bulk
storage-map build, typed SAC balance fast path, batch host-object visit, fused
SAC auth+balance), the remaining C++-side apply-path code should still contain
at least one Medium-tier (3–10% apply-time) optimization opportunity. A fresh
sweep of `parallelApply`, the per-thread commit pipeline, `addReads`,
`recordStorageChanges`, and the meta-builder gating should turn up at least
one candidate that survives quantitative sizing against the soroswap baseline
(~314 ms per ledger).

## Mechanism

Re-reading the apply-path code with the latest Tracy trace
(`/mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-02-soroswap-tx-2000-t-8.tracy`,
self-time export) shows that the remaining non-host C++ work fits well below
the Medium floor. The host (`invoke_host_function`, ~9.78 s of self-time) is
the only material residual in `parallelApply`; everything else
(`addReads` ≈ 85 ms self / 6066 calls, `recordStorageChanges` ≈ 26 ms /
2994 calls, `commitChangesFromSuccessfulTx` block ≈ 43 ms across all threads,
`addLiveBatch` ≈ 278 ms across the run, `loadFromLedger` for
SorobanNetworkConfig ≈ 30 µs/ledger) is each below 1% of per-ledger apply
time, so even an aggressive rewrite cannot produce a Medium-tier win on its
own. The deviation from the expected behavior is that the search yields no
viable Medium hypothesis — only sub-noise Low candidates that have already
been rejected.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap scenario at HEAD with
`disable_metrics=True`, 2000 tx/ledger, 8 worker threads, the matching
checkpoint-style benchmark cfg (`docs/apply-load-benchmark-token.cfg` etc.)
that sets `DISABLE_TX_META_FOR_TESTING=true`. Profile with Tracy and read
self-time CSV: filter to descendants of `applyLedger` and check whether any
non-host zone exceeds ~9 ms/ledger (~3% of the soroswap median).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads`:
  per-RO/RW-key TTL+entry load + `toCxxBuf` serialization + `xdr_size(lk)`
  per key. Tracy: ~85 ms self over 6066 calls (~14 µs each, ~28 µs/ledger).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-760` —
  `recordStorageChanges`: deserialize each modified entry, `LedgerEntryKey`,
  linear scan over RW footprint, `xdr_size(lk)` per write. Tracy: ~26 ms /
  2994 calls (~9 µs each, ~9 µs/ledger).
- `src/transactions/ParallelApplyUtils.cpp:1085-1121` — `getLiveEntryOpt`:
  triple lookup chain (mThreadEntryMap → InMemorySorobanState →
  mLCLSnapshot.loadLiveEntry). Already covered by H009.
- `src/transactions/ParallelApplyUtils.cpp:1241-1252` —
  `commitChangesFromSuccessfulTx`: per modified entry calls
  `getLiveEntryOpt`, `scopeAdoptEntryOptFrom`, `commitChangeFromSuccessfulTx`
  (which calls `getLiveEntryOpt` again).
- `src/transactions/ParallelApplyUtils.cpp:1199-1238` —
  `setEffectsDeltaFromSuccessfulTx`: now gated behind
  `!config.INVARIANT_CHECKS.empty()` (see
  `src/transactions/TransactionFrame.cpp:2438-2445`), so meta-disabled
  benchmark runs already short-circuit it. The "skip when meta disabled"
  angle considered in earlier rounds is therefore moot.
- `src/transactions/TransactionMeta.cpp:385-452` —
  `OperationMetaBuilder::setLedgerChangesFromSuccessfulOp`: already returns
  early when `!mEnabled`. Same with `setSorobanReturnValue`,
  `setOperationEvents`, etc. — meta-disabled is already free.
- `src/ledger/LedgerManagerImpl.cpp:2839-2850` — `enableTxMeta` plumbing
  is already correct: `enableTxMeta = ledgerCloseMeta != nullptr`, so when
  `DISABLE_TX_META_FOR_TESTING=true` and no meta streams, the per-tx
  TransactionMetaBuilder is constructed with `mEnabled=false`.
- `src/ledger/NetworkConfig.cpp:1754-1788, 2230-2233, 2887-2900` —
  `loadFromLedger` and `feeRent1KB()` already cache; total cost
  ~30 µs/ledger.
- `src/bucket/BucketListSnapshot.cpp:60-115, 171-201, 313-346` — total
  Tracy time looks large but the meta-pattern in
  `ai-summary/fail/transaction-ledger/summary.md` confirms most
  load/getBucketEntry/scan time is contamination from the pre-timing
  `warmAccountCache` window in `src/simulation/ApplyLoad.cpp:2074-2086`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` — wasmi
  `instantiate_wasmi`: ~596 ms self / 9035 calls (~66 µs each, ~200 µs
  per ledger). InstancePre is per-store and not reusable as a cached
  artifact; this is already in the fail set.

## Evidence

This round considered the following candidate optimizations and sized each
against the soroswap baseline. None reached the 3% Medium floor; all are
documented here to prevent re-investigation:

1. **Pre-load classic footprint entries into
   `GlobalParallelApplyLedgerState::mGlobalEntryMap`** so per-tx classic
   reads in `getLiveEntryOpt` skip `mLCLSnapshot.loadLiveEntry`. Soroswap
   uses very few classic footprint reads per Soroban tx (source/fee account
   are pre-processed in fee+seq, RW footprint is dominated by Soroban
   types). Estimated upper bound: a few µs per tx, well under 1%.

2. **Skip `setEffectsDeltaFromSuccessfulTx` when meta disabled.** Already
   gated behind `!config.INVARIANT_CHECKS.empty()`
   (`src/transactions/TransactionFrame.cpp:2438-2445`). The benchmark runs
   with no invariants, so this work is already free. No-op.

3. **Skip TransactionMetaBuilder per-op work when disabled.** Already
   short-circuits via `mEnabled` checks in every public mutator. No-op.

4. **Cache shared ContractCode XDR / pre-serialize host-handed buffers.**
   Modified-entry XDR comes back from the host as opaque buffers; the
   apply-path deserializes them once via `xdr_from_opaque` to compute
   `LedgerEntryKey` and to upsert. Total deserialize time across all
   modified entries per ledger ≈ a few ms. Below 1%.

5. **Hoist `xdr::xdr_size(lk)` out of `addReads` and
   `recordStorageChanges`.** ~12000 calls/ledger × ~50 ns = ~600 µs/ledger.
   Below noise.

6. **Combine `commitChangesFromSuccessfulTx` and
   `setEffectsDeltaFromSuccessfulTx` into a single iteration.** Already
   covered by H009 (rejected as Low, ~Low-end of <3%).

7. **Coalesce `getLiveEntryOpt(key)` inside `commitChangeFromSuccessfulTx`
   with the `try_emplace` in `upsertEntry`.** Same family as H009. The
   determining `isNew` flag cannot be reused from the per-tx
   `mRwKeyExisted` bitmap because thread-state existence differs from
   tx-local existence (an earlier tx in the same thread may have written
   the entry).

8. **Pre-compute per-thread `mPointTimers` map copies / cache the
   BucketListSnapshot per-thread.** Apply-load disables Soroban metrics
   (`DISABLE_SOROBAN_METRICS_FOR_TESTING=true`) and metric updates already
   short-circuit; mPointTimers map churn is not visible in the trace.

9. **Pre-load the SorobanNetworkConfig once per ledger** outside the apply
   loop. Already cached: `loadFromLedger` runs once per ledger with total
   cost ~30 µs.

The unifying observation: **the soroswap apply path's residual time is now
overwhelmingly inside the Soroban host** (`invoke_host_function`,
`Vm::instantiate_wasmi`, host-object/storage/SAC machinery). The C++ side
of the parallel-apply pipeline has been thoroughly sanded down. The five
host-side hypotheses already in `reviewed/` cover the remaining Medium-tier
opportunities; no fresh non-host C++ angle in this sweep clears the floor.

## Anti-Evidence

- Every C++ candidate listed sizes below 1% of per-ledger apply time when
  totaled across all ledgers in the trace.
- The meta-disabled and invariant-disabled gates are already in place,
  removing the largest plausible "skip work in benchmark mode" wins.
- The fail-summary meta-pattern explicitly warns that `BucketListSnapshot`
  totals are contaminated by the pre-timing `warmAccountCache` window;
  per-apply blocking work is small.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — this is a meta-record of a fresh sweep, not a
duplicate of a single prior fail entry. Each individual sub-candidate is
either explicitly rejected here or documented in earlier fail files
(H009 covers candidate 6/7, H012/H013/H014 cover unrelated
parallelization angles, H011/H010 cover signature/validation caching).

### Why It Failed

After the five reviewed Soroban-host hypotheses, the remaining
non-host C++ apply-path zones are individually below the 3% Medium
floor. The meta-disabled and invariant-disabled gates already exist,
the bucket totals are contamination, and the per-tx parallel-apply
state machinery has small absolute self-time. There is no single C++
change that moves the soroswap apply-time needle by Medium without
regressing correctness or determinism.

### Lesson Learned

For this objective, future hypothesis rounds targeting soroswap should
either: (a) propose Soroban-host changes (where the dominant time
lives), (b) propose structural redesigns of the parallel-apply pipeline
(e.g., reshaping clusters or eliminating the global → thread → tx state
hierarchy) that change a dominant phase rather than a single zone, or
(c) target the wasmi instantiation cache at a higher level than
`InstancePre` (a known dead-end). One-zone-at-a-time micro-optimization
of the C++ apply path has reached diminishing returns and should not
generate Medium-tier hypotheses without a structural angle.
