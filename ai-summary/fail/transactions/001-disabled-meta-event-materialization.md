# H001: Skip Disabled-Meta Soroban Event Materialization

**Date**: 2026-04-28
**Subsystem**: transactions
**Severity**: Low
**Impact**: avoid unnecessary C++ event/return-value XDR materialization when transaction meta recording is disabled
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When transaction meta is disabled, successful Soroban apply should still compute the exact result hash, enforce event-size and return-value-size limits, consume refundable resources, and produce identical transaction results and ledger changes. It should not spend measurable apply time decoding event XDR solely for metadata structures that will be dropped by disabled meta builders.

## Mechanism

`InvokeHostFunctionApplyHelper::collectEvents` decodes each Rust-produced event buffer into a `ContractEvent`, and `finalizeSuccess` decodes the return value before calling `setEvents` and `setSorobanReturnValue`. Since `TransactionMetaBuilder` and `OperationMetaBuilder` have disabled-meta paths, this looked like a potential avoidable decode path for the benchmark configs that disable transaction meta. The actual behavior is below the objective threshold: the current trace reports only 7.127 ms total for `collectEvents`, and the return-value decode is intertwined with consensus-visible result construction rather than a clean removable meta-only path.

## Trigger

Run the current soroswap benchmark shape (`soroswap`, 4000 tx, 8 clusters) with transaction meta disabled and inspect the apply-only Tracy trace. The investigated path triggers on successful Soroban invocations that return contract events or a return value.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` — `collectEvents` reserves, decodes, and stores contract events while enforcing event-size limits.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:878-927` — `finalizeSuccess` decodes the return value, streams the result-hash preimage from already-encoded bytes, then forwards events and return value to metadata builders.
- `src/transactions/TransactionMeta.cpp` — metadata builders contain disabled-meta behavior that originally made this path look removable.

## Evidence

The code does materialize C++ `ContractEvent` and `SCVal` objects even though the benchmark disables transaction meta, and the result hash is already streamed from encoded `out.result_value.data` and `out.contract_events` bytes. This suggested a possible disabled-meta fast path that would keep limit checks and result hashing in encoded form while avoiding meta-only XDR objects.

## Anti-Evidence

The current trace shows `collectEvents` at only 7.127 ms total across the entire run, far below the 3% Medium threshold after parallel-worker normalization. The return-value decode is also used to populate the success preimage object and metadata handoff, so avoiding it safely would require more invasive API changes for a sub-threshold gain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated for the transactions queue

### Why It Failed

The removable disabled-meta event materialization is too small in the current soroswap apply trace to meet the optimize-soroswap objective's Medium severity floor.

### Lesson Learned

Encoded result-hash streaming already removed the expensive part of successful invoke result handling; remaining disabled-meta event decoding is not a priority unless future traces show a much higher event count or event size.
