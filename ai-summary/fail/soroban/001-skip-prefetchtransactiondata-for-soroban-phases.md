# H001: Skip per-tx iteration in prefetchTransactionData for Soroban phases

**Date**: 2026-04-28
**Subsystem**: ledger / apply path
**Severity**: Medium
**Impact**: Hot-path serial overhead inside applyLedger; reduces wall time by ~4 ms/ledger ≈ 6% on the soroswap benchmark.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::prefetchTransactionData` should issue prefetches only for keys that the bucket-list snapshot actually needs to load. For a Soroban-only tx phase (the soroswap benchmark), every Soroban op's `insertLedgerKeysToPrefetch` is a no-op (`InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` at `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` does nothing), and the source-account key is already prefetched by the immediately-prior `prefetchTxSourceIds` call. Therefore prefetchTransactionData should perform zero useful work for a Soroban-only phase and should skip iteration of that phase entirely.

## Mechanism

`LedgerManagerImpl::prefetchTransactionData` (`src/ledger/LedgerManagerImpl.cpp:2464-2481`) currently iterates every tx in every phase, invokes `tx->insertKeysForTxApply(keys)` (a virtual call that itself iterates every op and makes a second virtual call to `op->insertLedgerKeysToPrefetch`), then calls `ltx.prefetch(keys)`. For a soroswap ledger of ~4000 Soroban txs whose op-source equals tx-source, this loop contributes effectively nothing to the keys set and then calls `prefetch` with an essentially empty set — yet still incurs ~4 ms/ledger of serial overhead before parallelApply begins. The deviation from expected behavior is that the function pays the iteration cost in spite of provably producing zero meaningful prefetch keys for Soroban phases. Eliminating the per-tx iteration on Soroban phases (e.g., by checking `phase.isParallel()` / phase type and skipping, or by merging this work into the existing `prefetchTxSourceIds` pass which already iterates every tx) should remove that ~4 ms from the apply critical path.

## Trigger

Run the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py` with the soroswap scenario, 4000 txs/ledger). Observe Tracy zone `prefetchTransactionData` consuming ~268 ms across 65 captured ledgers (~4 ms/ledger), serially executed inside `applyLedger` before `parallelApply` starts.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2464-2481` — `prefetchTransactionData`: iterates every phase/tx, calls `insertKeysForTxApply`.
- `src/ledger/LedgerManagerImpl.cpp:2444-2461` — `prefetchTxSourceIds`: already iterates every tx; could absorb the work or short-circuit Soroban phases together.
- `src/ledger/LedgerManagerImpl.cpp:2823` — call site of `prefetchTransactionData` inside `applyLedger`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1424` — empty `insertLedgerKeysToPrefetch` proves Soroban ops contribute no keys.
- `src/transactions/TransactionFrame.cpp:2032-2043` — `insertKeysForTxApply`: only adds op-source if it differs from tx-source, plus delegates to `op->insertLedgerKeysToPrefetch`.

## Evidence

- Tracy (soroswap trace `02-soroswap-tx-4000-t-8.tracy`):
  - `prefetchTransactionData` self-time: 268 ms across 65 calls = 4.06 ms/call (ledger).
  - `prefetchTxSourceIds` self-time: 88 ms across 65 calls = 1.35 ms/call.
  - Both zones are direct descendants of `applyLedger` (verified in csvexport `-e` output).
- Code analysis shows `InvokeHostFunctionOpFrame::insertLedgerKeysToPrefetch` is a no-op, and Soroban tx envelopes typically use op-source == tx-source, so the only key inserted per Soroban tx by `insertKeysForTxApply` is the source-account — already added by `prefetchTxSourceIds` (`TransactionFrame::insertKeysForFeeProcessing` adds `accountKey(getSourceID())`).
- The resulting `prefetch(keys)` call eventually reaches `LedgerStateSnapshot::loadLiveKeys` with a (near-)empty set; the per-call overhead of constructing the snapshot/iterating the empty set adds further fixed cost beyond the tx-iteration.
- Per-ledger projected savings ≥ 3–4 ms on a ~67 ms apply, i.e., ~5–6% — within Medium severity (3–10%).

## Anti-Evidence

- For mixed (classic + Soroban) ledgers, classic txs DO add real keys via `insertLedgerKeysToPrefetch` (offer/trustline/etc.), so the optimization must preserve the existing behavior for classic phases. Conditioning the skip on phase type (Soroban vs classic) addresses this.
- For Soroban txs whose op-source differs from tx-source, the `accountKey(op->getSourceID())` insertion is real but small. A correct implementation should still capture op-source keys when they differ — likely fast since duplicate op-source==tx-source can be filtered without virtual dispatch into `insertLedgerKeysToPrefetch`.
- Determinism: this is purely a cache-warming optimization that does not alter ledger output, so removing it cannot break determinism.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prefetch redundancy was summarized previously, but this exact empty Soroban transaction-data pass was not present in current fail/success records
**Failed At**: reviewer

### Trace Summary

`applyLedger` first calls `prefetchTxSourceIds`, then processes fees, then `applyTransactions` calls `prefetchTransactionData` before dispatching phases. The claimed empty-work path is real for the soroswap shape: generated swaps are single `InvokeHostFunctionOp` transactions with no explicit operation source, and all Soroban operation prefetch hooks inspected (`InvokeHostFunction`, `ExtendFootprintTTL`, and `RestoreFootprint`) are empty. However, the measured savings ceiling is the whole `prefetchTransactionData` zone, about 4.06 ms per ledger, which is below the objective's Medium threshold when compared to the current accepted `run_apply_load_matrix.py` headline soroswap median of 596.381 ms.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1655-1688` — `applyLedger` prefetches source accounts via `prefetchTxSourceIds`, then runs `processFeesSeqNums`, then calls `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2443-2480` — `prefetchTxSourceIds` inserts fee/source-account keys, while `prefetchTransactionData` separately iterates every phase and transaction and calls `insertKeysForTxApply`.
- `src/ledger/LedgerManagerImpl.cpp:2784-2884` — `applyTransactions` calls `prefetchTransactionData` before sorting phases in apply order and dispatching parallel Soroban phases.
- `src/transactions/TransactionFrame.cpp:2025-2043` — `insertKeysForFeeProcessing` adds the transaction source account; `insertKeysForTxApply` only adds an operation source account when it differs from the transaction source, then delegates to the operation prefetch hook.
- `src/transactions/OperationFrame.cpp:263-268` — absent an explicit operation source, `OperationFrame::getSourceID()` resolves to the parent transaction source, so the soroswap operation-source check does not add a new key.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1420-1429`, `src/transactions/ExtendFootprintTTLOpFrame.cpp:365-374`, and `src/transactions/RestoreFootprintOpFrame.cpp:454-463` — Soroban operation prefetch hooks are empty and `isSoroban()` returns true.
- `src/herder/TxSetFrame.h:322-325` and `src/herder/TxSetFrame.cpp:2216-2229,2277-2292` — parallel phases are Soroban phases, and validation enforces Soroban-vs-classic phase transaction type.
- `src/ledger/LedgerTxn.cpp:3101-3155` — `LedgerTxnRoot::Impl::prefetch` rejects Soroban/TTL keys, filters loaded keys, then calls `loadLiveKeys`; an empty key set provides no useful cache warming.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap generation creates one unique source account per swap and constructs a single invoke-host-function operation without setting an explicit operation source.
- `scripts/run_apply_load_matrix.py:120-124,417-424` and `ai-summary/CURRENT_STATE.md:16-28` — the active benchmark scenario is soroswap TX=4000, T=8, and the accepted headline median apply time is 596.381 ms.

### Why It Failed

The inefficiency exists, but it is below the objective severity threshold. Even assuming a perfect implementation eliminates the entire cited `prefetchTransactionData` cost of 4.06 ms per soroswap ledger, that is only about 0.68% of the current 596.381 ms headline apply-load median, below the 1% noise floor and far below the 3% Medium acceptance floor. The hypothesis's 5-6% projection is based on comparing against a narrower Tracy `applyLedger` subtotal rather than the objective's top-line apply time as reported by `scripts/run_apply_load_matrix.py`.

There is also a correctness-shaping caveat for any future lower-priority cleanup: blindly skipping every Soroban/parallel phase would drop cache warming for explicit Soroban operation-source accounts, because `insertKeysForTxApply` still adds `accountKey(op->getSourceID())` when the operation source differs from the transaction source. This would not change consensus results because prefetch is advisory, but a production-quality cleanup should preserve those op-source keys or explicitly accept the cache-warming tradeoff.

### Lesson Learned

Empty prefetch passes in Soroban-only benchmark shapes can be real, but they must be sized against the apply-load headline metric, not only against a narrow Tracy subtree. For this objective, a serial helper must save roughly 18 ms per 596 ms soroswap ledger to clear Medium; a 4 ms helper is not enough even if it can be removed completely.
