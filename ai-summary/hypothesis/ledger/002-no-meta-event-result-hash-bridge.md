# H002: No-meta host result hash bridge for contract events

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding event/result buffer transfer and C++ XDR decode when transaction meta is disabled
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When transaction metadata and Soroban diagnostics are disabled, Core should still set the exact same `InvokeHostFunctionResult` success hash, enforce the same contract-event/return-value size limits, charge the same refundable resources, and apply the same ledger changes. It should not decode contract events or the return `SCVal` into C++ XDR objects that are immediately dropped by disabled `OperationMetaBuilder` and `OpEventManager` paths.

## Mechanism

Rust returns `result_value` and every encoded contract event to C++, then `InvokeHostFunctionOpFrame::collectEvents` decodes each event into `ContractEvent` and `finalizeSuccess` decodes the return value before computing the success hash from the original encoded bytes. In apply-load, `DISABLE_TX_META_FOR_TESTING` disables operation event and return-value metadata, so `OpEventManager::setEvents` and `OperationMetaBuilder::setSorobanReturnValue` are no-ops; the only consensus-relevant value is the SHA256 hash over canonical return/event XDR plus byte counts for resource accounting. A no-meta bridge variant can compute and return the success hash and event/return byte totals directly from Rust while omitting `result_value` and `contract_events` buffers unless meta or diagnostics require them.

## Trigger

Run the current soroswap benchmark with the standard apply-load config (`DISABLE_TX_META_FOR_TESTING = true`, Soroban diagnostics off). Successful router/pool/SAC invocations emit contract events, Rust returns those encoded event buffers, C++ decodes them in `collectEvents`, and `setEvents` later drops them because the operation event manager is disabled.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:InvokeHostFunctionResult:49-67` — result currently always carries encoded return value and encoded contract events on success.
- `src/rust/src/bridge.rs:InvokeHostFunctionOutput:30-55` — CXX bridge always exposes `result_value` and `contract_events`.
- `src/rust/src/soroban_proto_any.rs:invoke_host_function_or_maybe_panic:478-506` — converts Rust result/event buffers into bridge output unconditionally.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:collectEvents:769-817` — decodes each event only to populate success preimage/event metadata.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:finalizeSuccess:879-927` — decodes return value, then hashes the already-encoded bytes.
- `src/transactions/EventManager.cpp:OpEventManager::setEvents:504-512` and `src/transactions/TransactionMeta.cpp:OperationMetaBuilder::setSorobanReturnValue:455-463` — both drop the decoded objects when metadata is disabled.

## Evidence

The code path is inside `applyLedger`: `InvokeHostFunctionOpFrame doParallelApply` is called from `TransactionFrame::parallelApply` in Soroban worker clusters, and prior current-trace records show router/pool/SAC host invocation zones are measured `applyLedger` descendants rather than TX-set construction. The source structurally proves redundant work in the benchmark configuration: `collectEvents` decodes `out.contract_events` into `success.events`, but `OpEventManager::setEvents` returns immediately when `metaEnabled` is false; `finalizeSuccess` decodes `out.result_value.data` into `success.returnValue`, but `setSorobanReturnValue` also returns immediately when disabled. Soroswap emits multiple contract events per swap, so avoiding cross-language event buffer transfer plus C++ XDR decode has a plausible Medium ceiling.

## Anti-Evidence

The optimization must be gated strictly to no-meta/no-diagnostics apply; Horizon/meta streaming still needs full decoded events and return values. Rust still has to produce canonical event and return XDR, or an equivalent streaming hash, because the operation result hash is consensus-critical. If event encoding itself dominates and C++ transfer/decode is small, the measured gain could fall below the 3% Medium threshold.
