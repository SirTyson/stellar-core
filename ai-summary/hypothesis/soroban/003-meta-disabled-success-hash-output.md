# H003: Meta-disabled Soroban apply can return success hash and event sizes without event/result XDR buffers

**Date**: 2026-04-29
**Subsystem**: soroban / rust bridge / transactions
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in Soroban host-output and C++ success finalization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When transaction meta is disabled, a successful Soroban invocation should still produce the same transaction result hash, resource accounting, refundable-fee inputs, modified ledger entries, rent fee, and ledger state. It should not allocate and return every encoded contract-event buffer to C++ or decode those buffers back into `ContractEvent` objects when the only measured apply-path consumers are the success hash and total event-byte count. In the meta-disabled apply-load path, Rust can return a precomputed `InvokeHostFunctionSuccessPreImage` hash plus the event/result byte totals, while C++ keeps the existing event-vector path when meta is enabled.

## Mechanism

The current bridge always encodes contract events into `InvokeHostFunctionOutput::contract_events` in Rust, then C++ `collectEvents` decodes every event into `success.events`, and `finalizeSuccess` re-hashes the already-encoded result and event buffers. In the optimize-soroswap benchmark, `DISABLE_TX_META_FOR_TESTING` makes `enableTxMeta` false (`LedgerManagerImpl.cpp:2835-2847`), so `OperationMetaBuilder::setSorobanReturnValue` and `OpEventManager::setEvents` are disabled no-ops, but C++ still decodes result/event XDR solely to populate a disabled meta builder. A core-only output mode can stream the exact XDR bytes into a SHA-256 hasher and byte counter on the Rust side, return the final 32-byte success hash and event-byte total, and skip returning/decoding event/result buffers unless meta is enabled.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the benchmark's default disabled transaction meta. A PoC should add a meta-disabled bridge flag or output variant, compute the success preimage hash from `encoded_invoke_result` and encoded contract events in Rust, return `emit_event_byte`/max-event information needed for C++ resource checks, and have C++ bypass `collectEvents` event decoding plus `xdr_from_opaque(out.result_value.data, success.returnValue)` when no meta will be emitted.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2835-2847` — benchmark apply path sets `enableTxMeta` false when no ledger-close meta is emitted and `DISABLE_TX_META_FOR_TESTING` is true.
- `src/transactions/ParallelApplyStage.h:19-84` — `TxEffects` still constructs a disabled `TransactionMetaBuilder`, making the meta-disabled state available per transaction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:489-509` — successful Rust invocation encodes the result value, computes ledger changes, and always calls `encode_contract_events`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:875-889` — `encode_contract_events` serializes every non-diagnostic successful event into an owned `Vec<Vec<u8>>`.
- `src/rust/src/soroban_proto_any.rs:478-506` — bridge wraps the encoded result value and every encoded event into `InvokeHostFunctionOutput`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` — C++ counts event bytes but also decodes every event into `success.events`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:878-927` — C++ decodes the return value for meta, hashes the success preimage from returned bytes, and calls disabled meta setters in benchmark mode.
- `src/transactions/TransactionMeta.cpp:455-463` and `src/transactions/EventManager.cpp:504-512` — return-value and event storage immediately no-op when meta is disabled.

## Evidence

The current soroswap diagnostic trace is grounded in `applyLedger`: timestamp containment showed `write xdr` at **1,071.529 ms** across **132,907** apply-contained calls, `readOne` at **139.575 ms** across **358,335** apply-contained calls, and `collectEvents` at **14.002 ms** across **3,335** calls. `SAC transfer` is also fully apply-contained at **2,406.469 ms** across **6,656** calls, and SAC transfers emit contract events on the hot path, so event encoding is not a setup artifact.

This hypothesis is distinct from the rejected old-entry output-buffer PoC in `ai-summary/fail/soroban/002-skip-redundant-host-output-xdr.md`. That PoC targeted ledger-change old-entry materialization and ultimately preserved exact XDR traversal for metering, leaving no top-line gain. This proposal targets a different consumer: when meta is disabled, C++ does not need decoded `ContractEvent` objects or a decoded return `SCVal` at all; it needs only the success hash, event-byte totals, and existing modified ledger-entry buffers.

## Anti-Evidence

Event XDR bytes are semantically required when transaction meta is enabled, and the success hash must remain byte-for-byte identical. A PoC must therefore keep the existing output path for meta-enabled production/meta-streaming runs, or return enough structured event data to populate meta. The Rust-side streaming hasher must preserve the exact XDR preimage used by `InvokeHostFunctionSuccessPreImage`, including the event vector length prefix and event order. This may reduce only allocation, bridge transfer, C++ decode, and C++ hashing overhead; it does not remove event construction in the Soroban host, so repeated non-Tracy benchmark runs must prove the top-line win clears the 3% Medium threshold.
