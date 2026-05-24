# H001: Eliminate per-tx child `LedgerTxn` in serial meta-capture sections (`processFeesSeqNums` + `processPostTxSetApply`)

**Date**: 2026-05-24
**Subsystem**: soroban (ledger / apply orchestration — meta capture on the apply critical path)
**Severity**: Medium
**Impact**: per-tx serial `LedgerTxn` construct/commit/destruct cycle on the apply critical path; affects every Soroban tx in soroswap (~197/ledger) twice (fee phase + refund phase)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Capturing per-tx `LedgerEntryChanges` for `LedgerCloseMeta` should require
only a tiny per-tx allocation: the *changes* themselves (typically 1–2
entry deltas — a `SourceAccount` balance bump and a possible `MAX_SEQ_NUM_TO_APPLY`
write for fee processing; a single `SourceAccount` refund delta for
post-apply). Constructing a fresh child `LedgerTxn` (with its full `mEntry`,
`mActive`, `mMultiOrderBook`, `LedgerTxnHeader` copy, etc.) **per
transaction** purely to harvest `getChanges()` is far heavier machinery
than the work product warrants. A correct, efficient implementation would
record the per-tx delta directly on the parent `LedgerTxn` — e.g.,
snapshot the parent's dirty-entry-map size before/after each
`processFeeSeqNum` / `processPostTxSetApply` call and emit
`LedgerEntryChanges` from the newly added/modified entries — without
spinning up a fresh child `AbstractLedgerTxn` per tx.

## Mechanism

`processFeesSeqNums` (`src/ledger/LedgerManagerImpl.cpp:2386–2400`) wraps
every tx in `LedgerTxn ltxTx(ltx); processOneTxFee(ltxTx);
ledgerCloseMeta->pushTxFeeProcessing(ltxTx.getChanges()); ltxTx.commit();`
when `ledgerCloseMeta` is non-null. The same pattern repeats in
`processPostTxSetApply` (`LedgerManagerImpl.cpp:3109–3123`) for the
post-worker refund step. Each per-tx child `LedgerTxn`:

1. Allocates a fresh `LedgerTxn::Impl` (multiple `UnorderedMap`s,
   `LedgerTxnHeader` copy, BestOffers cache, MultiOrderBook scaffolding).
2. Runs the per-tx fee or refund work, populating its tiny entry/active
   maps with 1–2 entries.
3. Calls `getChanges()` to materialize `LedgerEntryChanges` (walks the
   small map, builds XDR `LedgerEntryChange` vector).
4. Calls `commit()` which merges those 1–2 entries back into the parent
   `ltx` — a redundant entry-map merge operation.
5. Destructs.

For soroswap (~197 Soroban txs/ledger), that is ~394 per-tx child-LTX
cycles **per ledger** sitting on the serial apply thread (one cycle in
the pre-worker fee phase, one in the post-worker refund phase). The
deviation from expected behavior is that we pay the cost of a full
`AbstractLedgerTxn` for an output that is structurally identical to a
trivial `vector<LedgerEntryChange>` accumulator. This serial-critical-path
overhead is, by Tracy structural attribution (see Evidence), in the
single-digit-millisecond-per-ledger range — measurable Medium-tier under
the objective's apply-time benchmark.

## Trigger

`scripts/run_apply_load_matrix.py` against the soroswap workload (the
existing baseline configuration:
`62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8` matrix entry).
Compare median apply time before and after replacing the per-tx child
`LedgerTxn` constructions in `processFeesSeqNums` and
`processPostTxSetApply` with a parent-LTX delta-snapshot approach that
still preserves `LedgerEntryChanges` semantics byte-for-byte.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2386–2400` — per-tx
  `LedgerTxn ltxTx(ltx)` in `processFeesSeqNums`'s `processOneTxFee` /
  `ledgerCloseMeta` branch.
- `src/ledger/LedgerManagerImpl.cpp:3109–3123` — per-tx
  `LedgerTxn ltxInner(ltx)` in `processPostTxSetApply`'s parallel-phase
  loop (refund + `setPostTxApplyFeeProcessing`).
- `src/ledger/LedgerTxn.cpp` — `LedgerTxn::LedgerTxn`, `getChanges`,
  `commit` (machinery being amortized away).
- `src/ledger/LedgerCloseMetaFrame.cpp:71` (`pushTxFeeProcessing`) and
  `:126` (`setPostTxApplyFeeProcessing`) — sinks for the changes; must
  receive byte-identical `LedgerEntryChanges` to preserve observable
  meta-stream output.

## Evidence

- **Tracy structural attribution.** From the accepted trace at
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/...02-soroswap-tx-2000-t-8.tracy`,
  `processFeesSeqNums` accounts for **3.6% of `applyLedger`** (~7.85 ms
  per real-time ledger at the 218 ms/ledger baseline). Of that,
  `processFeeSeqNum` (inner per-tx work) self-time totals only ~330 µs/ledger
  — the **residual ~7.5 ms/ledger** sits in the per-tx child-LTX
  construct/`getChanges`/`commit`/destruct chain plus outer loop control.
  Even attributing half of that to genuine fee work leaves ~3 ms/ledger
  (~1.4% apply) just for the meta-capture child-LTX overhead in this one
  call site.
- **Second site duplicates the cost.** `processPostTxSetApply`
  (`LedgerManagerImpl.cpp:3094`) iterates the same ~197 Soroban txs
  serially post-worker-join with exactly the same per-tx
  `LedgerTxn ltxInner(ltx)` / `getChanges` / `commit` pattern, doubling
  the structural cost (~6 ms/ledger combined ≈ 2.8% apply,
  Medium-tier).
- **Apply-load defaults engage this path.** `runApplyLoad`
  (`src/main/CommandLine.cpp:1832`) does not set
  `DISABLE_TX_META_FOR_TESTING`, so `LedgerManagerImpl.cpp:1625`
  constructs `ledgerCloseMeta` and the per-tx child-LTX branches are
  taken on every Soroban tx in the benchmark.
- **Per-tx delta is tiny.** `processFeeSeqNum` modifies only the
  source account (and possibly creates one `MAX_SEQ_NUM_TO_APPLY`
  entry for classic v19+ same-source merges — but Soroban txs are
  short-circuited at `LedgerManagerImpl.cpp:2369–2383`). `processRefund`
  (`TransactionFrame.cpp:2793–2816`) only touches the fee source
  account. A `vector<LedgerEntryChange>` populated by snapshotting
  the parent LTX dirty-entry map before/after the call delivers
  byte-identical XDR with no fresh `LedgerTxn::Impl` allocation.
- **No correctness blocker.** The child LTX exists *only* for change
  isolation: its `commit()` already merges back into the parent
  immediately. There is no transactional rollback semantic relied
  upon — the per-tx call never throws under successful fee/refund
  processing (failures throw out of the outer try-catch and abort the
  whole ledger).

## Anti-Evidence

- **Meta byte-exactness is a hard constraint.** Any replacement must
  emit `LedgerEntryChanges` in the exact same order and with the exact
  same `LedgerEntryChange` variant (`CREATED` / `UPDATED` / `REMOVED` /
  `STATE`) sequence as the current child-LTX path produces. The
  current path emits a `STATE` entry (the pre-modification value)
  followed by an `UPDATED` entry — built by
  `LedgerTxn::getChanges()` walking the child's `mEntry`. A
  parent-LTX-delta implementation must reproduce that
  `(STATE, UPDATED)` pairing exactly. Verifiable by
  `LedgerCloseMeta` hash diffing in `BUILD_TESTS` (which already
  retains meta via `mLastLedgerTxMeta`).
- **`MAX_SEQ_NUM_TO_APPLY` create still happens on parent.** The
  separate `accToMaxSeq` post-loop at
  `LedgerManagerImpl.cpp:2404–2428` writes to the outer `ltx`, not
  the per-tx child. That path is unaffected and need not be touched.
- **Cost may concentrate in `getChanges()`, not LTX construction.**
  If profiling shows the dominant per-tx cost is the XDR
  `LedgerEntryChanges` materialization itself (not the `LedgerTxn::Impl`
  allocation), the savings shrink and the fix shifts to the
  `LedgerEntryChanges` builder — still actionable but the structural
  win is smaller. PoC must instrument both paths separately.
- **Meta-pattern #14** (sub-millisecond apply-thread serial paths
  exhausted, combined <2%) applies to *known* serial-path
  fails, not specifically this child-LTX pattern. The
  `processFeesSeqNums + processPostTxSetApply` combined budget
  (~6 ms/ledger ≈ 2.8% apply) sits at the Low/Medium boundary; if
  PoC measurement lands below 3%, the hypothesis falls back to
  Low and must go to fail/.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The claimed extra per-transaction child `LedgerTxn` constructions are present in both meta-enabled paths: one around each fee/sequence-number charge in `processFeesSeqNums`, and one around each post-parallel refund in `processPostTxSetApply`. These children are only taken when `ledgerCloseMeta` exists, and apply-load builds meta by default in `BUILD_TESTS` because `DISABLE_TX_META_FOR_TESTING` defaults false. However, the post-apply path still creates another nested child inside `TransactionFrame::refundSorobanFee`, and the removable outer-child work is only a subset of the already sub-Medium post-worker serial window. The proposed parent dirty-map snapshot also does not reproduce child-`LedgerTxn::getChanges()` semantics for accounts already dirty in the parent from earlier transactions.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1600-1631` — `ledgerCloseMeta` is constructed for meta streams and, in tests/apply-load, whenever `DISABLE_TX_META_FOR_TESTING` is false.
- `src/main/CommandLine.cpp:1832-1854` and `src/main/Config.cpp:184` — `runApplyLoad` does not disable tx meta; the default config leaves `DISABLE_TX_META_FOR_TESTING` false.
- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` opens one outer ledger txn for the phase, then opens a per-tx child `LedgerTxn ltxTx(ltx)` solely when meta is enabled so `ltxTx.getChanges()` can feed `pushTxFeeProcessing` before commit.
- `src/transactions/TransactionFrame.cpp:1777-1817` and `src/transactions/FeeBumpTransactionFrame.cpp:765-795` — fee processing mutates the source/fee-source account and ledger header fee pool; Soroban transactions skip the `accToMaxSeq` merge tracking.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — `processPostTxSetApply` opens a per-tx `LedgerTxn ltxInner(ltx)` only for meta capture, passes its changes to `setPostTxApplyFeeProcessing`, then commits.
- `src/transactions/TransactionFrame.cpp:1045-1082`, `src/transactions/TransactionFrame.cpp:2782-2816`, and `src/transactions/FeeBumpTransactionFrame.cpp:255-262` — refund processing touches the fee source and header fee pool, but `refundSorobanFee` itself creates and commits another nested `LedgerTxn`.
- `src/ledger/LedgerTxn.cpp:429-454`, `src/ledger/LedgerTxn.cpp:563-578`, `src/ledger/LedgerTxn.cpp:604-626`, and `src/ledger/LedgerTxn.cpp:1416-1467` — child construction copies the parent header and registers as the active child; commit merges child entries to the parent; `getChanges()` walks child `mEntry` and emits `STATE` plus `UPDATED`/`REMOVED` relative to the parent view.
- `src/ledger/LedgerCloseMetaFrame.cpp:70-91` and `src/ledger/LedgerCloseMetaFrame.cpp:125-132` — meta sinks store the exact `LedgerEntryChanges` vector produced by the child transaction.

### Why It Failed

The inefficiency is real, but it does not clear the optimize-soroswap Medium threshold. The hypothesis itself sizes the removable child-LTX meta-capture component at about 3 ms/ledger for `processFeesSeqNums` plus a combined two-site estimate around 6 ms/ledger, approximately 2.8% of the cited 218 ms apply baseline. That is below the objective's 3% Medium floor, and it is optimistic because `processPostTxSetApply`'s removable outer meta child excludes the still-present nested `LedgerTxn` inside `refundSorobanFee` and excludes unavoidable XDR `LedgerEntryChanges` materialization. Prior review of the same post-join refund/meta window (`010-parallel-per-stage-process-post-tx-set-apply.md`) also sized the total refund+result/meta work at only 3-4 ms/ledger, so the outer-child-only slice cannot independently provide a Medium-tier win.

The proposed implementation shape is also not correctness-ready: snapshotting the parent's dirty-entry-map size or newly inserted entries misses transactions that update a key already dirty in the parent, such as repeated source/fee-source accounts across ledger-order fee processing or across later Soroban stages. The current child `getChanges()` records the parent-current state immediately before that transaction, then the transaction's updated state; a direct parent implementation would need an explicit per-tx before/after capture for the touched keys and exact child `mEntry` iteration semantics, not just a map-size delta.

### Lesson Learned

Per-tx `LedgerTxn` meta-capture overhead is a valid micro-inefficiency, but meta-only child removal must be sized against only the removable child construction/commit layer, not the entire fee/refund/meta serial window. For future variants, first isolate the outer-child-only cost with instrumentation and design an exact touched-key delta API that handles parent-dirty repeated keys; without both, this remains below the objective's review threshold.
