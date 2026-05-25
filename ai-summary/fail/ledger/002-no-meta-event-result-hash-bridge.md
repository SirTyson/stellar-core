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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; closest related success is `ai-summary/success/ledger/001-sparse-no-meta-ledger-changes.md`, which removed no-meta ledger-change output but explicitly left result/event output intact
**Failed At**: reviewer

### Trace Summary

The no-meta apply-load precondition is real: `DISABLE_TX_META_FOR_TESTING = true` prevents test-forced transaction meta, `enableTxMeta` remains false, and `OperationMetaBuilder`/`OpEventManager` are disabled. Successful Soroban transactions still return `result_value` and `contract_events` from Rust, C++ still decodes every event in `collectEvents`, and `finalizeSuccess` still decodes the return value before dropping it through disabled meta. However, the only measured event-decode zone is far below this objective's 3% Medium floor, and the proposed bridge cannot remove the required Rust-side canonical XDR encoding, event/return byte accounting, or consensus hash work.

### Code Paths Examined

- `docs/apply-load-benchmark-sac.cfg:18-24` and `scripts/run_apply_load_matrix.py:417-425` — apply-load disables Soroban metrics and transaction metadata, and the matrix overrides keep diagnostics off.
- `src/ledger/LedgerManagerImpl.cpp:1622-1631, 2835-2847` — in `BUILD_TESTS`, `DISABLE_TX_META_FOR_TESTING` suppresses forced `LedgerCloseMeta` allocation and leaves `enableTxMeta` false.
- `src/transactions/TransactionFrame.cpp:2386-2448` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — Soroban transactions enter `InvokeHostFunctionOpFrame doParallelApply` inside the parallel apply worker path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:560-584, 954-969` — Rust still serializes the return value and each non-diagnostic successful contract event to canonical XDR.
- `src/rust/src/bridge.rs:34-55` and `src/rust/src/soroban_proto_any.rs:478-506` — the CXX bridge unconditionally exposes success `result_value` and `contract_events`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` — `collectEvents` counts event bytes, enforces the event/return size limit, and decodes every event into `success.events`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:879-927` — `finalizeSuccess` decodes the return `SCVal`, computes the result hash from the encoded return/event bytes, then calls disabled meta setters.
- `src/transactions/EventManager.cpp:236-246, 504-512` and `src/transactions/TransactionMeta.cpp:455-463, 924-937` — disabled metadata makes `setEvents` and `setSorobanReturnValue` no-ops.

### Why It Failed

The inefficiency exists, but it is below the optimize-soroswap review threshold. In the current diagnostic soroswap trace `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`, Tracy reports `collectEvents` at 33,962,305 ns over 8,705 calls, only 0.33% of trace time and less than 1% of the captured `applyLedger` aggregate even before normalizing worker-thread time by the 8 configured clusters. That zone includes the event byte accounting and every C++ `ContractEvent` decode that this hypothesis targets.

The remaining unzoned `finalizeSuccess` work does include a redundant return-value decode, but it handles one small return `SCVal` per transaction and the SHA256 over return/event bytes is not removable: a no-meta bridge would have to compute the same consensus hash from the same canonical bytes in Rust. The claimed "event/result buffer transfer" also overstates the removable work because the bridge owns Rust `Vec<u8>` buffers rather than reserializing them in C++; Rust must still encode or stream equivalent canonical bytes for limits, refundable fees, and the result hash. Even adding the return decode to the measured event-decode cost leaves a Low/sub-1% to low-single-digit ceiling, below the objective's required 3-10% Medium impact.

### Lesson Learned

No-meta metadata drops are worth checking, but the hot cost must be the specific decoded object path, not the enclosing host invocation. For event/result bridge ideas, measure `collectEvents` or an equivalent dedicated span first; Rust-side event serialization and consensus hashing remain mandatory, so C++ metadata-decode removal alone does not clear the soroswap Medium floor.
