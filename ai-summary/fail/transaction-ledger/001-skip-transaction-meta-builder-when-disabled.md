# H001: Skip TransactionMetaBuilder construction when meta is disabled

**Date**: 2026-04-28
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: Per-tx allocation reduction in classic + Soroban apply paths
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the apply path knows it will not emit transaction meta (production
nodes with `LedgerCloseMeta` not requested, or benchmark/test runs with
`DISABLE_TX_META_FOR_TESTING=true`), per-tx meta construction should be a
no-op: a single small placeholder object, no XDR variant materialization,
no per-operation `OperationMetaBuilder` allocation, no resized
`xvector<OperationMetaV2>`. The only side effects required of the meta
machinery in that mode are (a) collecting `LedgerEntryChanges` for the
classic operations whose `doApply` consumes a builder reference, and (b)
satisfying the `getTxEventManager()` / `getOperationMetaBuilderAt()` APIs
that callers reach through unconditionally.

## Mechanism

`TransactionMetaBuilder::TransactionMetaBuilder`
(src/transactions/TransactionMeta.cpp:924-973) does the same work
regardless of `metaEnabled`:

1. Constructs the `TransactionMetaWrapper`, which calls
   `TransactionMeta::v(version)` — for protocol-23+ this materializes a
   `TransactionMetaV4` XDR object (with nested vectors `txChangesBefore`,
   `txChangesAfter`, `operations`, `events`, `diagnosticEvents`, plus a
   `SorobanTransactionMetaExt`).
2. `mOperationMetas.emplace<xdr::xvector<OperationMetaV2>>().resize(numOps)`
   — N default-constructed `OperationMetaV2` records (each with its own
   `LedgerEntryChanges` vector, `events` vector, etc.).
3. A `vector<OperationMetaBuilder>` is reserved and N
   `OperationMetaBuilder` objects are emplaced (each constructs its own
   `OperationMetaWrapper` XDR variant).

For the soroswap benchmark with `DISABLE_TX_META_FOR_TESTING=true`,
`enableTxMeta` is `false`
(`src/ledger/LedgerManagerImpl.cpp:2839,2843-2846`), but every TX still
pays for these allocations. Per ledger this is ~568 classic txs +
~123 Soroban txs × per-op builders, dominated by allocator calls and XDR
default constructors. Sequentially on the classic path each `tm`
construction sits inside the synchronous per-tx loop; on the Soroban path
each builder sits in the per-cluster apply path.

Skipping the heavy construction (returning empty XDR variants and
no-op'ing `pushTxChangesBefore/After`, `setOperationMetas`, event
emission) when `mEnabled==false` removes per-tx allocation churn from a
loop that currently allocates regardless. The diff is mechanical: a
disabled-mode constructor branch and conditional bodies in the per-op
push helpers.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the soroswap scenario at
T=8 / TX=4000. Compare median apply time before vs after gating
`TransactionMetaBuilder` allocation on `metaEnabled`. The same diff
benefits production nodes that don't request `LedgerCloseMeta` (e.g.
validators that don't expose meta).

## Target Code

- `src/transactions/TransactionMeta.cpp:924-973` —
  `TransactionMetaBuilder` constructor: unconditional XDR variant +
  per-op builder construction.
- `src/transactions/TransactionMeta.cpp:524-547` —
  `TransactionMetaWrapper` ctor switches on protocol and instantiates
  V2/V3/V4 XDR objects.
- `src/transactions/TransactionMeta.cpp:566-720` (approx) —
  `TransactionMetaWrapper` setters/getters that touch the inner XDR
  variant; need disabled-mode no-op paths.
- `src/transactions/TransactionMeta.h:139-175` — class layout to
  understand which members are skippable when disabled.
- `src/ledger/LedgerManagerImpl.cpp:3050-3052` — sequential classic
  per-tx construction site.
- `src/ledger/LedgerManagerImpl.cpp:2960-3020` — Soroban tx-bundle
  builder construction site.

## Evidence

- Tracy zone counts: applyTransaction 36909 calls / 65 ledgers = 568/ledger
  classic. Each builds a `TransactionMetaBuilder`. Soroban adds another
  ~123/ledger via `applySorobanStages`.
- Constructor unconditionally constructs the XDR variant and N
  `OperationMetaBuilder` records regardless of `metaEnabled`
  (TransactionMeta.cpp:937-973).
- The XDR `TransactionMetaV4` and `OperationMetaV2` default constructors
  zero-initialize multiple nested vectors — measurable allocator pressure
  per construction.
- Comparable gate already exists for medida `TimeScope` in the parallel
  Soroban path (LedgerManagerImpl.cpp:2493-2498), establishing a pattern
  of skipping diagnostic infrastructure when disabled.

## Anti-Evidence

- Some op apply paths (notably classic offer ops and Soroban host
  callbacks) reach into the builder unconditionally to push events or
  changes; the disabled-mode paths must short-circuit those without
  changing observable behavior. A naïve change could drop
  `LedgerEntryChanges` collection that the apply loop relies on for
  finalization — but those changes are already gated downstream in
  benchmark mode (LedgerManagerImpl.cpp:2843).
- Magnitude is uncertain. If per-tx meta construction is ~5–15 µs, savings
  scale to 3–10 ms/ledger (~0.5–1.7% of the 596 ms baseline). To clear
  the Medium 3% threshold this needs the heavier Soroban OperationMetaV2
  case to dominate, where per-op builders may run 30–50 µs each due to
  SorobanTransactionMetaExt allocation. Benchmark will arbitrate.
- Production nodes commonly request `LedgerCloseMeta`, so the optimization
  is benchmark-relevant but won't help meta-emitting deployments.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The claimed inefficiency exists: `enableTxMeta` becomes false when no ledger-close meta is being emitted, or in benchmark/test mode when `DISABLE_TX_META_FOR_TESTING=true`, but both the sequential and parallel apply paths still construct a `TransactionMetaBuilder` for every transaction. That constructor always materializes the protocol-specific `TransactionMeta` variant, allocates/resizes the per-operation meta vector, and constructs an `OperationMetaBuilder` per operation even though the event managers and change-recording methods become no-ops when disabled. The proposed optimization is correctness-feasible only with a disabled-mode placeholder that still satisfies the unconditional builder APIs, but the recoverable work is a small allocation/default-construction tax per tx rather than a dominant close-ledger phase. The hypothesis's own realistic estimate is 0.5-1.7% of the soroswap baseline, and source tracing does not reveal enough hidden disabled-mode work to plausibly reach the objective's 3% Medium floor.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2835-2846` — `enableTxMeta` is false when `ledgerCloseMeta == nullptr`, except tests force it back on unless `DISABLE_TX_META_FOR_TESTING` is set.
- `src/ledger/LedgerManagerImpl.cpp:3044-3087` — every sequential-phase tx constructs `TransactionMetaBuilder tm(enableTxMeta, ...)`, emits a fee event through it, applies the tx, then only finalizes meta when `processResultAndMeta` has a ledger-close meta target or test meta collection is enabled.
- `src/ledger/LedgerManagerImpl.cpp:2982-3016` and `src/transactions/ParallelApplyStage.h:19-84` — every parallel Soroban tx is wrapped in a `TxBundle`; `TxEffects` eagerly owns and constructs a `TransactionMetaBuilder` even when `enableTxMeta` is false.
- `src/transactions/TransactionMeta.cpp:524-547` — `TransactionMetaWrapper` always chooses and activates meta version 2, 3, or 4 in the underlying XDR object before knowing whether any meta will be emitted.
- `src/transactions/TransactionMeta.cpp:924-973` — `TransactionMetaBuilder` unconditionally reserves `mOperationMetaBuilders`, allocates/resizes the `OperationMeta` or `OperationMetaV2` vector, and constructs an `OperationMetaBuilder` for each operation.
- `src/transactions/TransactionMeta.cpp:346-352`, `385-393`, and `1111-1120` — ledger-change recording already returns immediately when `mEnabled` is false, so disabled mode is not spending the heavier `getChanges()` / `processOpLedgerEntryChanges()` work.
- `src/transactions/EventManager.cpp:138-145`, `236-245`, `596-612` — diagnostic, operation, and transaction event managers are disabled by `metaEnabled=false`, and their event-emission methods short-circuit before constructing event payloads.
- `src/transactions/TransactionMeta.cpp:1035-1108` and `src/ledger/LedgerManagerImpl.cpp:2759-2781` — finalization asserts meta is enabled and is only called on the paths that will store or emit meta, so disabled builders are generally discarded without final XDR assembly.
- `src/transactions/TransactionFrame.cpp:2520-2588` and `2360-2448` — operation application and parallel application unconditionally ask for operation meta builders, but the expensive ledger-change setters short-circuit when disabled.

### Why It Failed

This is a real but sub-threshold optimization for the optimize-soroswap objective. The disabled path still pays for a small number of per-transaction allocations/default constructions, but the heavy meta work has already been gated: ledger changes are not collected, operation/tx/diagnostic events are no-ops, Soroban fee meta setters are disabled, and disabled builders are not finalized into emitted XDR. For the stated workload (~568 classic txs plus ~123 Soroban txs per ledger), the hypothesis's plausible 5-15 us per-builder estimate gives only ~3-10 ms/ledger, or ~0.5-1.7% of the cited 596 ms apply baseline. Even the more optimistic "heavy Soroban builder" path is limited by only ~123 Soroban txs per ledger and by the fact that `OperationMetaV2` nested vectors are default-empty until populated. Under the objective-specific rules, Low-tier and sub-1%/noise-level findings must be rejected rather than downgraded and accepted.

### Lesson Learned

When meta is disabled, `TransactionMetaBuilder` still has a measurable eager construction cost, but most downstream meta work is already guarded by `mEnabled` or by `processResultAndMeta` finalization gates. Future hypotheses in this area need direct benchmark or allocation-profile evidence that the constructor itself exceeds the 3% apply-time floor; otherwise meta-builder placeholder work is best treated as a small cleanup or combined with broader disabled-infrastructure reductions, not as a standalone Medium soroswap optimization.
