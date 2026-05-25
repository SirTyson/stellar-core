# H204: Skip per-tx LedgerTxn child in preParallelApplyWrite when meta is disabled

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-tx allocator/commit overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `DISABLE_TX_META_FOR_TESTING=true`, `meta.pushTxChangesBefore(ltxTx)` is a
no-op and the per-tx child `LedgerTxn ltxTx(ltx)` opened at
`TransactionFrame.cpp:2323` exists only to scope changes for a meta capture
that never runs. The expected correct-and-minimal behavior is to call
`processSeqNum(ltx)` and `removeOneTimeSignerFromAllSourceAccounts(ltx)`
directly on the parent (mirroring the short-circuit already applied to
`processFeesSeqNums` in the meta-disabled benchmark path) — avoiding the
construction of a child `LedgerTxn::Impl`, its `EntryMap`/`MultiOrderBook`
allocations, and the subsequent `commit()` walk.

## Mechanism

`preParallelApplyWrite` allocates a fresh per-Soroban-tx child `LedgerTxn`,
performs at most a single account `load`+`update` (in `processSeqNum`), and
then commits the child back into the parent. With meta disabled the child's
sole purpose — providing a delta for `pushTxChangesBefore` — is dead work.
The allocator churn and the commit walk are real per-tx wall-clock cost on
the apply thread that could be removed.

## Trigger

Any Soroban-only ledger under the benchmark config. `applyLedger` runs
`preParallelApply` for every Soroban tx serially before parallel cluster
scheduling, so the per-tx child-ltx cost lives on the critical path.

## Target Code

- `src/transactions/TransactionFrame.cpp:2314-2349` —
  `preParallelApplyWrite` always opens `LedgerTxn ltxTx(ltx)` and commits.
- `src/ledger/LedgerManagerImpl.cpp:2303-2400` — analogous
  meta-disabled short-circuit already applied to `processFeesSeqNums`.

## Evidence

- The tracy trace shows `processSeqNum` at 26.4ms / 34,110 calls ≈ 776ns each,
  which is the *only* meaningful work inside the child ltx for the benchmark
  (one-time signers are not present on benchmark Soroban accounts).
- The processFees path already short-circuits the analogous per-tx child ltx
  when meta is disabled (verified in summary `<technical_details>`).

## Anti-Evidence

- Per-tx Soroban count in the soroswap benchmark is ~98 tx/ledger
  (7k Soroban tx / 71 ledgers).
- Child `LedgerTxn` open + commit with a single entry is ~1–2 µs at most,
  so per-ledger savings are ~0.1–0.2 ms.
- Against the 207 ms soroswap median this is ~0.05–0.10% — well below the 1%
  benchmark-noise floor and far below the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (no existing fail entry
targets `preParallelApplyWrite` per-tx child ltx; closest neighbors are
fail #012 fuse-per-tx-modifiedentrymap-walks which addresses the
*post*-apply commit walk, and fail #001/#203 which addresses
`removeOneTimeSigner`/seqNum short-circuits inside `processFeesSeqNums`,
not `preParallelApplyWrite`).

### Why It Failed

Even in the best case (zero child-ltx machinery) the savings amount to
~0.05–0.10% of soroswap apply time, which is below benchmark noise (1%) and
an order of magnitude below the Medium threshold (3%). The objective
explicitly rejects sub-Low changes (`SEVERITY_SCALE` Low requires 1–3% and
the optimize-soroswap stage threshold is Medium). Meta-Pattern #14 confirms
this: any zone needs ≥3.5 s aggregate self-time inside `applyLedger` to
clear Medium, and the child-ltx open/commit for ~98 tx × 71 ledgers
accumulates well under 100 ms aggregate.

### Lesson Learned

The `preParallelApply{ReadOnly,Write}` split is structured around meta
boundaries; eliminating one half's child ltx is structurally clean but
yields impact strictly proportional to per-Soroban-tx count, which is bounded
in the soroswap workload. Any per-Soroban-tx micro-opt with single-µs
per-tx savings cannot clear Medium severity on this benchmark — it must
target either a heavier per-tx cost or amplify across the much larger
per-host-call surface. Future hypotheses in this area should compute the
`(per-tx-µs * Soroban-tx/ledger) / 207ms` envelope before drafting.
