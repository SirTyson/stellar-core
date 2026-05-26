# H003: Skip `xdr_from_opaque(success.returnValue)` decode in `InvokeHostFunctionOpFrame::finalizeSuccess` when meta disabled

**Date**: 2026-05-26
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-tx XDR decode (sub-noise)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `InvokeHostFunctionOpFrame::finalizeSuccess` (`src/transactions/InvokeHostFunctionOpFrame.cpp:878`), the host returns a host-side `result_value.data` byte vector for the contract invocation. The code currently calls `xdr::xdr_from_opaque(out.result_value.data, success.returnValue)` to deserialize the bytes into an `SCVal`, then passes `success.returnValue` to `opMeta.getEventManager().setSorobanReturnValue(returnValue)` and to `consumeRefundableSorobanResources` for byte-size accounting.

When the benchmark config disables transaction meta (`DISABLE_TX_META_FOR_TESTING=true`), `setSorobanReturnValue` is a no-op (the variant store is uninitialized — see `TransactionMeta.cpp:455`). The only consumer of the decoded SCVal is meta. Refundable-fee accounting only needs `result_value.data.size()`, not a decoded SCVal. Therefore, the `xdr_from_opaque` call is pure dead work in the benchmark configuration. The expected behavior under an optimization is to skip the decode when meta is disabled (or to defer it under `if (metaBuilder.maybeEnableSorobanReturnValue())`).

## Mechanism

`xdr_from_opaque` on a typical soroswap return value (a small `SCVal::Vec`/`Map`) walks the XDR variant tree and allocates the discriminant container plus any nested vectors. The cost is small per call (likely 1-5µs) but it runs on every successful Soroban tx in the cluster's critical path. With ~2000 swap txs/ledger and T=8 clusters → ~250 per critical-path thread → at 1-5µs each → 0.25-1.25ms saved per ledger. Against a 207ms soroswap baseline that is **0.12-0.6%** — well below the 3% Medium floor and within benchmark noise.

## Trigger

Apply soroswap workload with `DISABLE_TX_META_FOR_TESTING=true`. Add a Tracy zone around the `xdr_from_opaque` call and measure aggregate self-time across the soroswap trace; expected total <10ms across 71 ledgers.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:finalizeSuccess:878-895` — the `xdr::xdr_from_opaque(out.result_value.data, success.returnValue)` decode and subsequent `setSorobanReturnValue` chain
- `src/transactions/TransactionMeta.cpp:setSorobanReturnValue:455` — confirmed no-op when meta disabled
- `src/transactions/InvokeHostFunctionOpFrame.cpp:invokeHostFunction:557` — `consumeRefundableSorobanResources` only needs `.size()`, not decoded SCVal

## Evidence

- Benchmark config confirms `DISABLE_TX_META_FOR_TESTING=true` → `TransactionMetaBuilder` is constructed with `enableTxMeta=false`, making `setSorobanReturnValue` a no-op.
- `xdr_from_opaque` is the standard XDR decoder; for a non-trivial SCVal it allocates `xdr::pointer`s for the discriminated union storage.
- Code path is in the per-tx worker hot path (every successful InvokeHostFunction op).

## Anti-Evidence

- Soroban Meta-Pattern #4 in `ai-summary/fail/soroban/summary.md` caps **all bridge XDR encode/decode optimizations at ~2.5% combined**; isolated decode-skip optimizations have failed repeatedly (fail records 029, 031 in soroban bucket).
- Transactions Meta-Pattern #15: "Per-Tx Micro-Costs Exhaustively Sub-Threshold" — any optimization in the per-tx serial critical path that nets <2% has consistently failed Medium threshold.
- A typical soroswap return value is small (an `SCVal::Bool` for "swap-ok" or a `Vec` of 1-2 amounts); the decode is genuinely cheap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — finalizeSuccess return-value decode is not the specific target of any existing fail record (existing fail 029 in soroban targets per-event decode in `collectEvents`, not the singular return-value decode in `finalizeSuccess`).

### Why It Failed

Projected impact (0.12-0.6% of soroswap apply time) is below this objective's 3% Medium threshold and within the 1% benchmark-noise floor. The optimization is a strict subset of the broader "skip per-tx XDR decoding when meta is disabled" angle, which is bounded by soroban Meta-Pattern #4 to ~2.5% even when *all* such decodes are eliminated together. Singling out the return-value decode in isolation cannot exceed that cap and falls well below it.

### Lesson Learned

When a benchmark disables meta, individual `xdr_from_opaque`/`xdr_to_opaque` call sites on per-tx paths look like easy wins but consistently aggregate to <3%. To clear the Medium threshold here, an optimization must eliminate the *entire* meta-construction infrastructure cost (TransactionMetaBuilder + OperationMetaBuilder + EventManager) as a single coordinated change — and that broader pattern is itself capped by soroban Meta-Pattern #4. Per-call-site skips inside the meta-disabled path are not a viable Medium-tier angle for this subsystem.
