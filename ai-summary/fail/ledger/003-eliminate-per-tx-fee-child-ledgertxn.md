# H003: Eliminate per-tx child LedgerTxn allocation in `processFeesSeqNums` by capturing fee meta inline

**Date**: 2026-04-29
**Subsystem**: ledger / fee processing
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by removing per-tx child `LedgerTxn` create/seal/commit overhead in the meta-emitting fee processing loop
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a meta-emitting soroswap ledger close, `processFeesSeqNums` should charge the source-account fee, increment the sequence number where applicable, and emit a per-tx `LedgerEntryChanges` pair (state + updated) into `LedgerCloseMeta`. The cost should scale linearly in the number of transactions, but the constant factor should not include allocation, sealing, and commit of an entire nested `LedgerTxn::Impl` per transaction when the only modification is a single source-account entry.

## Mechanism

Today `processFeesSeqNums` constructs a fresh child `LedgerTxn ltxTx(ltx)` for **every** transaction whenever `ledgerCloseMeta` is enabled (`src/ledger/LedgerManagerImpl.cpp:2386-2394`). For 2000 txs/ledger across 69 measured ledgers this allocates ~138k child `LedgerTxn::Impl` instances. Each child instantiates an `EntryMap` (UnorderedMap), an `ActiveMap`, an empty `MultiOrderBook`, header copy, `WorstBestOffer` map, and a `RestoredEntries` struct; on `processFeeSeqNum` it loads the source account (registers in `mActive` and `mEntry`), mutates balance/seqnum, then on `getChanges()` walks `mEntry` calling `mParent.getNewestVersion(key)` to fetch the previous state, then on `commit()` merges the single delta back into the parent and re-invalidates parent caches. None of this nesting is required for Soroban-only fee processing where the only mutation is the source account: a previous-state snapshot can be captured inline against the parent `LedgerTxn` (one `getNewestVersion` lookup before mutation), the parent can be mutated directly, and the per-tx `LedgerEntryChanges` (`LEDGER_ENTRY_STATE` + `LEDGER_ENTRY_UPDATED`) can be pushed to meta with no child allocation.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with default meta emission enabled. With 2000 txs per ledger, `processFeesSeqNums` invokes the child-LTX branch (`ledgerCloseMeta != nullptr`) once per tx, exactly matching the 2000-tx/ledger × 69-ledger workload that produced the cited Tracy zone counts.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2386-2400` — current per-tx `LedgerTxn ltxTx(ltx); processOneTxFee(ltxTx); ledgerCloseMeta->pushTxFeeProcessing(ltxTx.getChanges()); ltxTx.commit();` pattern.
- `src/ledger/LedgerManagerImpl.cpp:2347-2384` — `processOneTxFee` lambda — must be reworked to either accept an explicit "before-state" capture or to operate directly on the parent ltx.
- `src/transactions/TransactionFrame.cpp:1776-1817` — `TransactionFrame::processFeeSeqNum` only loads and mutates the source account; nothing else changes for Soroban txs.
- `src/ledger/LedgerTxn.cpp:1422-1468` — `LedgerTxn::Impl::getChanges` currently re-queries `mParent.getNewestVersion(key)` to populate `LEDGER_ENTRY_STATE`; the same value can be captured once before mutation.
- `src/ledger/LedgerCloseMetaFrame.cpp:71` — `pushTxFeeProcessing` accepts any `LedgerEntryChanges` vector; no API change needed on the meta side.

## Evidence

In the headline soroswap Tracy trace (`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/...-soroswap-tx-2000-t-8.tracy`):
- `applyLedger` total = `5,774,332,215 ns` across 69 closes.
- `processFeesSeqNums` (`ledger/LedgerManagerImpl.cpp:2308`) total = `142,360,408 ns` / 69 calls = **2.46% of applyLedger** with average 2.06 ms per ledger.
- Inside it, `processFeeSeqNum` (`transactions/TransactionFrame.cpp:1780`) self = `59,985,042 ns` / 28,945 calls = ~2 µs per tx (the actual per-tx fee work). The remaining `~82 ms` per ledger of `processFeesSeqNums` self-time (after subtracting `processFeeSeqNum` and `processSeqNum`) is dominated by per-tx child `LedgerTxn` allocation, sealing, `getChanges` traversal, and commit-merge work — work that scales with the per-tx loop and is invariant of the underlying account mutation.
- `getNewestVersion` (`ledger/LedgerTxn.cpp:3672`) total = `134,414,315 ns` / 220,980 calls; a non-trivial share comes from `getChanges()` re-queries that the inline pattern would eliminate.
- The pattern is on the apply critical path: the entire `processFeesSeqNums` runs synchronously inside `applyLedger` before parallel apply begins.

Combined, removing the per-tx child-LTX overhead targets ~80 ms per ledger of `processFeesSeqNums` work plus the second-order allocation/cache effects on subsequent parallel apply (138k fewer per-ledger heap allocations means less allocator contention and less L1/L2 cache eviction during the immediately following stage-cluster setup). A reproducible 3-5% apply-time reduction is plausible.

## Anti-Evidence

- Some classic-tx code paths (pre-V19, ACCOUNT_MERGE handling) currently rely on per-tx isolation in `accToMaxSeq` and `mergeSeen` tracking. The optimization must keep that branch intact (Soroban txs explicitly skip merge-tracking — see comment at lines 2364-2368).
- `getChanges()` for a child LTX currently captures the *post-stamp* `lastModifiedLedgerSeq` because `maybeUpdateLastModifiedThenInvokeThenSeal` runs first. Inline capture must replicate that stamping order: snapshot previous state, mutate + stamp `lastModifiedLedgerSeq` in the parent, then emit `LEDGER_ENTRY_STATE` (previous) + `LEDGER_ENTRY_UPDATED` (post-stamp current). Any miscompiled stamping order changes meta hashes and breaks cross-node determinism.
- Direct mutation on the parent `ltx` will include fee changes in the parent's `EntryMap` immediately rather than after a child commit. The downstream `applyTransactions`/`applyParallelPhase` logic must remain correct; it already sees committed fee changes today (the parent ltx is the same one used after the fee-processing loop), so this should be transparent — but the PoC must verify with the existing `[tx]` and `[fees]` tests.
- The `BUILD_TESTS` block at lines 2350-2362 (replay-result assignment) assumes the `processOneTxFee` path is uniform; the inline replacement must keep replay assignment in sync.
- Some part of the `processFeesSeqNums` self-time may be `loadHeader().current()` per-tx or `loadSourceAccount` cost; only the LTX-nesting share is removable. The PoC must measure the real share with targeted Tracy zones before claiming a Medium win, and the projected savings depend on the second-order allocator/cache effects materializing in the benchmark.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The claimed per-transaction child `LedgerTxn` overhead exists only on the metadata-enabled path: `applyLedger` creates `ledgerCloseMeta` when a metadata stream/debug stream is active, or in test builds unless `DISABLE_TX_META_FOR_TESTING` is set, and `processFeesSeqNums` then creates `LedgerTxn ltxTx(ltx)` for each transaction before calling `getChanges()` and `commit()`. However the optimize-soroswap benchmark path in `scripts/run_apply_load_matrix.py` uses `docs/apply-load-benchmark-sac.cfg`, which sets `METADATA_OUTPUT_STREAM = ""` and `DISABLE_TX_META_FOR_TESTING = true`; the script overrides model, tx count, thread count, metrics, ledger count, and log file only, not those metadata settings. On that measured path, `ledgerCloseMeta` remains null and `processFeesSeqNums` already uses the direct-parent branch, so the targeted child allocation/seal/commit work is absent from the objective's apply-time metric.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:17-24, 333-429` — the authoritative objective benchmark uses `docs/apply-load-benchmark-sac.cfg` as the default template and does not override metadata settings.
- `docs/apply-load-benchmark-sac.cfg:19-24` — benchmark config disables forced test metadata collection and disables metadata output/debug streams.
- `src/ledger/LedgerManagerImpl.cpp:1600-1631` — `ledgerCloseMeta` is allocated only for metadata streams/debug streams or, in `BUILD_TESTS`, when `DISABLE_TX_META_FOR_TESTING` is false.
- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — `applyLedger` calls `processFeesSeqNums` before `applyTransactions`, so this code is in the apply path, but only the branch selected by `ledgerCloseMeta` matters.
- `src/ledger/LedgerManagerImpl.cpp:2303-2400` — with metadata enabled the code creates a per-tx child `LedgerTxn`, pushes `ltxTx.getChanges()`, and commits; with metadata disabled it already calls `processOneTxFee(ltx)` directly on the parent.
- `src/transactions/TransactionFrame.cpp:1776-1817` — `processFeeSeqNum` mutates the source account balance and fee pool, and pre-v10 sequence number, through the supplied `AbstractLedgerTxn`.
- `src/ledger/LedgerTxn.cpp:443-454, 570-578, 1422-1468, 2388-2406` — constructing a child copies the parent header and registers as the active child; `getChanges()` seals/stamps and re-queries parent previous state; `commit()` seals and merges the child entry map into the parent.
- `src/ledger/LedgerCloseMetaFrame.cpp:70-91` — `pushTxFeeProcessing` just stores the supplied `LedgerEntryChanges`, so a metadata-only optimization could be architecturally possible but would not affect the objective benchmark.

### Why It Failed

The trigger premise is wrong for the optimize-soroswap objective: `run_apply_load_matrix.py` does not run with default metadata emission enabled. The benchmark explicitly disables transaction metadata, which means the code already takes the no-meta direct-parent path and avoids per-transaction child `LedgerTxn` construction. Optimizing the metadata-enabled path could help a different meta-ingestion benchmark, but it cannot produce the required Medium 3-10% reduction in the soroswap apply time reported by the objective benchmark because the targeted work is not executed there.

### Lesson Learned

Fee-processing hypotheses must distinguish production/meta-enabled close paths from the benchmark harness. In `BUILD_TESTS`, Stellar Core normally forces `LedgerCloseMeta` allocation, but the apply-load benchmark template deliberately suppresses that behavior with `DISABLE_TX_META_FOR_TESTING = true`, so metadata-specific overhead is out of scope unless the objective explicitly uses the meta benchmark config.
