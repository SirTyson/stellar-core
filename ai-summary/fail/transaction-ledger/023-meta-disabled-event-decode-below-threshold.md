# H023: Skip C++ contract-event decode when transaction meta is disabled

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban event and meta processing
**Severity**: Low
**Impact**: Potentially reduce soroswap apply overhead in benchmark configurations that disable transaction meta
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban transactions must always hash the exact return value and contract-event XDR bytes into the `InvokeHostFunctionResult`, enforce event-size limits, and charge refundable event fees. When transaction meta is disabled, stellar-core should avoid building decoded `ContractEvent` meta payloads that will not be emitted, while still preserving the result hash, fee/resource accounting, diagnostics behavior, and any required reconciliation events.

## Mechanism

`InvokeHostFunctionApplyHelper::collectEvents` iterates Rust-returned event XDR buffers, updates event metrics and size limits, decodes each buffer with `xdr::xdr_from_opaque`, and pushes decoded events into `InvokeHostFunctionSuccessPreImage::events`. `finalizeSuccess` later hashes the original XDR bytes directly and calls `setEvents(success)`, while `OperationMetaBuilder` can be disabled by the apply-load benchmark. A meta-disabled fast path could skip the C++ event decode and `success.events` construction when there are no reconciliation events and meta is disabled, using the original event bytes for hashing and byte accounting only.

## Trigger

Run the current soroswap apply-load benchmark with transaction meta disabled. Each successful `InvokeHostFunction` returns contract-event XDR bytes from Rust, and C++ decodes them in `collectEvents` even though the benchmark does not emit full transaction meta.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` — `collectEvents` updates event metrics and decodes every `out.contract_events` buffer into `success.events`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:878-928` — `finalizeSuccess` hashes `out.result_value` and raw event bytes, then stores decoded events and return value in operation meta.
- `src/transactions/TransactionMeta.h:43-57` and `src/transactions/TransactionMeta.h:95-135` — operation and transaction meta builders can be disabled for benchmark apply.

## Evidence

- The code has a structural split: the consensus hash already uses raw event XDR bytes (`hasher.add(buf.data)`), while decoded `ContractEvent` objects are needed for meta output and reconciliation handling.
- The current trace confirms this is in the apply path: `collectEvents,transactions/InvokeHostFunctionOpFrame.cpp:773` appears under the same `InvokeHostFunctionOpFrame doApply` path used by parallel Soroban apply.
- A meta-disabled branch would be deterministic and would not change ledger effects, event hash bytes, or refundable fee inputs if it only skipped decoded-event storage.

## Anti-Evidence

- Tracy shows `collectEvents` costs only **27,127,442 ns self/total** over **6,776** calls in the current soroswap trace. Even deleting it completely saves about 0.38 ms per ledger before considering parallelism, far below the 3% Medium floor.
- Rust-side `encode_contract_events` and event construction must still happen because the result hash and event-size accounting require the exact event bytes. This C++ branch cannot remove those costs.
- `finalizeSuccess` still needs to decode the return value for result/meta handling, so the optimization only covers contract-event decode, not the whole success-finalization path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — not previously recorded as a meta-disabled event-decode fast path

### Why It Failed

The target is real but too small for the optimize-soroswap objective. `collectEvents` is a tiny C++ post-host step compared with the VM/host execution and storage paths, and the raw event XDR bytes still have to be produced, sized, and hashed even when transaction meta is disabled. The best-case saving is well below Low and cannot plausibly reach the required Medium threshold.

### Lesson Learned

Meta-disabled fast paths must be sized against the exact disabled work, not the broader event construction/serialization category. For soroswap, C++ event decode is already far below benchmark noise; future event hypotheses need to remove Rust event construction or metered event serialization safely, not only skip the disabled-meta decode.
