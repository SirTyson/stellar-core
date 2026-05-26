# H078: Coalesce duplicate LedgerSnapshot loads in requiresSequentialPreParallelApply

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: apply-time reduction in the apply-thread serial classification pass that decides between sequential and parallel pre-apply for each Soroban tx
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`requiresSequentialPreParallelApply` (`ParallelApplyUtils.cpp:170`) is called
once per tx on the apply thread to decide whether the tx must be routed
through the sequential `preParallelApply` path (fee-bump or any classic
modification observed) or can be sharded across worker threads via
`readOnlyPreParallelApply`. For each tx it calls `isModifiedClassicKey` on
(a) the source account, (b) the fee-source account if different, (c) every
op-source AccountID, and (d) every footprint key (readWrite + readOnly).
Each `isModifiedClassicKey` invocation performs **two** `LedgerSnapshot::load`
calls (one on `current`, one on `previous`) and compares the resulting
`LedgerEntryWrapper`s for entry equality. Expected: classify each tx in O(K)
*unique* loads rather than O(2K) — keys shared across source/fee-source/
op-source/footprint should be loaded only once per snapshot, and the
`previous` snapshot load can be skipped entirely when the `current` load
returns `nullopt` and the previous returns the same.

## Mechanism

For a typical soroswap tx the loop iterates over: 1 source account + 0–1
fee-source + 1 op-source + ~8 footprint keys ≈ 11 unique keys × 2 snapshot
loads = 22 `LedgerSnapshot::load` calls per tx. Across 28 txs/ledger × 71
ledgers this is ~43k loads. Each `LedgerSnapshot::load` walks the LedgerTxn
parent chain (or the live-BL snapshot) and builds a `LedgerEntryWrapper`. A
coalesced version that (1) loads each unique key at most once per snapshot
and (2) short-circuits once any key is found modified would shave most of
this scan time. Additionally, for soroswap-style txs (no fee-bump, source ≡
fee-source ≡ op-source) the source/fee-source/op-source iteration loads the
same account 3 times against each snapshot today.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap workload. Measure
`requiresSequentialPreParallelApply` self-time and total apply time before
and after the coalescing change.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:170 requiresSequentialPreParallelApply`
  — outer loop; calls `isModifiedClassicKey` per key/account.
- `src/transactions/ParallelApplyUtils.cpp` (above #170): `isModifiedClassicKey`
  — two `ls.load(key)` calls per invocation.
- `src/transactions/ParallelApplyUtils.cpp:432 preParallelApplyAndCollectModifiedClassicEntries`
  — call site that drives the classification pass.

## Evidence

- Source-account, fee-source-account, and op-source-account keys are highly
  likely to alias for benchmark txs (no fee-bump, single Soroban op), so
  3 of the loads per snapshot are pure duplicates.
- Footprint keys are de-duplicated within a single tx by the validator at
  `checkValid`, but RO and RW are passed to two separate iterations of
  `isModifiedClassicKey` calls. While they cannot overlap by spec, every
  key still gets the 2-snapshot load.
- Fail #207 (003-skip-fee-bump-false-positive-in-requires-sequential-preparallelapply.md)
  already established the sequential preParallelApply path is bounded at
  ≤2.4ms/ledger total once false-positives are skipped. The
  classification pass itself (without the sequential preParallelApply
  invocation) is a fraction of that.

## Anti-Evidence

- Fail #207 caps the entire serial preParallelApply zone (which includes
  both this classification loop AND the actual sequential apply work it
  routes to) at 2.4ms/ledger ≈ **1.16%** of 207ms. The classification pass
  itself is a strict subset of that — likely <0.5ms/ledger ≈ <0.25%.
- `LedgerSnapshot::load` is already O(1)-ish for the hot in-memory case
  (live-BL snapshot pointer chase + map lookup); the savings per eliminated
  duplicate are sub-microsecond.
- Coalescing accounts requires building an UnorderedSet<AccountID> per tx,
  which itself allocates and hashes; the constant-factor win may be largely
  offset by the de-duplication overhead.
- Per meta-pattern #5, individual C++ apply-path micro-optimizations of this
  scale are consistently sub-threshold; fail #196, #199, and #207 all hit
  the same wall on this exact code region.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — duplicate-load coalescing in `requiresSequentialPreParallelApply`
has not been previously proposed (fail #207 targeted the false-positive
routing logic, not the load redundancy).

### Why It Failed

Below the objective severity threshold. The enclosing serial zone is bounded
at 1.16% by fail #207; coalescing duplicate loads can only save a fraction
of that fraction, well below the 1% noise floor and far below the 3% Medium
floor. The cost is dominated by the `LedgerEntryWrapper` construction and
parent-chain walking inside `LedgerSnapshot::load`, not by call count.

### Lesson Learned

Optimizations targeting the apply-thread serial classification/routing
phases (`requiresSequentialPreParallelApply`, `collectModifiedClassicEntries`,
`commitBufferedPreParallelApplyWrites`) are capped collectively at ~3ms/ledger
by the existing Tracy evidence. Future hypotheses must either (a) move the
work off-thread entirely (subject to the determinism constraint) or
(b) target the *callees* (`LedgerSnapshot::load`, `LedgerTxn` parent chain)
rather than the call sites. Per-call-site coalescing in this region cannot
clear the Medium threshold.
