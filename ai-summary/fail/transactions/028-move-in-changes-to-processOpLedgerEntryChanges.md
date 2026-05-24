# H028: Avoid Deep Copy of LedgerEntryChanges in processOpLedgerEntryChanges

**Date**: 2026-05-24
**Subsystem**: transactions (parallel worker per-op meta finalization)
**Severity**: Low
**Impact**: soroswap worker-path LedgerEntry copy elimination
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`OperationMetaBuilder::setLedgerChangesFromSuccessfulOp` constructs a fresh
`LedgerEntryChanges changes` vector for the modified entries of one Soroban
op, then immediately hands ownership to
`processOpLedgerEntryChanges(... LedgerEntryChanges const& initialChanges, ...)`.
The post-process function then performs `auto changes = initialChanges;` — a
full deep copy of the entry change vector — before walking it to merge
restore-protocol semantics. Since the caller never re-uses its local
`changes` after the call, the correct/efficient behavior is to *move* it
into the helper, not copy it.

Expected: the per-op meta path should perform exactly one deep allocation of
the `LedgerEntryChanges` vector per successful Soroban op (the one needed to
build it in the first place). The copy inside `processOpLedgerEntryChanges`
is mechanically redundant when the function may safely consume its argument.

## Mechanism

`src/transactions/TransactionMeta.cpp:41-48` declares
`LedgerEntryChanges const& initialChanges` and then writes
`auto changes = initialChanges;`. That deep-copies every `LedgerEntryChange`
union element including the embedded `LedgerEntry` payloads. For protocol
≥ V_23 (`AUTO_RESTORE_PROTOCOL_VERSION`), `needToProcess` is `true` for
INVOKE_HOST_FUNCTION ops, so the function does not short-circuit and the
copy is always paid even when `hotArchiveRestores` and `liveRestores` are
both empty (the typical soroswap case). Converting the parameter to
`LedgerEntryChanges initialChanges` taken by value and moving at the
callsite would eliminate the deep copy without changing any observable
output.

## Trigger

Run the soroswap apply-load benchmark (protocol 27, TX=2000, T=8). Every
successful `InvokeHostFunctionOpFrame::doParallelApply` reaches
`OperationMetaBuilder::setLedgerChangesFromSuccessfulOp` →
`processOpLedgerEntryChanges`, which deep-copies the per-op
`LedgerEntryChanges` vector once per successful tx.

## Target Code

- `src/transactions/TransactionMeta.cpp:41-59` — `processOpLedgerEntryChanges`
  signature and `auto changes = initialChanges;` deep copy + early-return
  guard.
- `src/transactions/TransactionMeta.cpp:384-450` —
  `OperationMetaBuilder::setLedgerChangesFromSuccessfulOp` builds local
  `changes` then passes it by const reference into
  `processOpLedgerEntryChanges`.
- `src/transactions/TransactionMeta.cpp:355-381` —
  `setLedgerChangesFromOnlyLtxDelta` (pre-V_23 path) is structurally
  similar but reads `opLtx.getChanges()` (by value) so the copy is mostly
  unavoidable there.

## Evidence

For soroswap each successful Soroban tx produces roughly 4-6 modified
entries → 8-12 `LedgerEntryChange` records, each containing an embedded
`LedgerEntry` (contract-data payloads averaging a few hundred bytes). With
~2000 txs/ledger × 70 ledgers / 8 workers ≈ 17,500 calls per worker, the
redundant deep copy is on the worker critical path. The fix is a pure
parameter-passing refactor and produces identical output for soroswap
(empty restore sets), so behavior is preserved.

## Anti-Evidence

Magnitude check shows the savings are well below the objective's severity
floor:

- Per-tx payload ≈ 5 KB of `LedgerEntry` bytes copied.
- Per worker: 5 KB × 17,500 ≈ 87 MB total memcpy across the benchmark.
- At ~10 GB/s memcpy throughput, that is ≈ 8.5 ms aggregate per worker.
- Against the soroswap `applyLedger` total of ~5,774 ms over 69 ledgers,
  that is **≈ 0.15 % of apply time** — below the 1 % benchmark-noise floor
  and far below the 3 % Medium threshold.

Meta-Pattern 15 documents that all per-tx, per-key worker-path
micro-optimizations have been exhaustively surveyed and each individual
one is sub-noise; this fits that pattern.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — the specific `auto changes = initialChanges;` copy in
`processOpLedgerEntryChanges` has not been previously investigated.

### Why It Failed

Below objective severity threshold. Critical-path savings of ~8.5 ms /
worker ≈ 0.15 % of `applyLedger` is well below the 1 % noise floor; even
fully eliminating the redundant copy cannot move the soroswap benchmark
beyond run-to-run variance. The proposed fix is structurally clean and
mechanically novel, but the absolute cost is too small for the objective
(Medium-only) gate.

### Lesson Learned

The per-op LedgerEntryChanges deep copy in `processOpLedgerEntryChanges`
is a real avoidable cost but lands in the same regime as Meta-Pattern 15
(per-tx worker micro-costs). For soroswap, individual `LedgerEntry`-copy
amortized work is bounded near 0.1 % of apply; future similar candidates
should be sized against per-worker memcpy budget × T-division before
proposal. Defer to a combined refactor across the meta path if multiple
similar copies are bundled later.
