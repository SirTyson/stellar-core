# H002: Apply-Mode Event Success-Hash Bridge

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / Soroban event and result apply bridge
**Severity**: Medium
**Impact**: soroswap apply-time reduction by avoiding duplicate event/result materialization on the no-meta apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For successful Soroban transactions, stellar-core must hash `InvokeHostFunctionSuccessPreImage { returnValue, events }`, enforce the configured event-size limits, charge refundable fees using the same event byte count, and publish identical events when transaction metadata is enabled. When metadata is disabled, the apply path should not need to decode every event into C++ `ContractEvent` objects solely to re-hash bytes that Rust already encoded.

The efficient no-meta apply path should stream the return-value bytes and encoded event bytes into the success hash and event-byte counters once, while preserving the existing C++ event vector only for metadata-enabled callers.

## Mechanism

Rust `Host::try_finish` externalizes internal events into `Events`, `encode_contract_events` serializes those events to XDR byte buffers, the bridge moves those buffers into C++, and C++ `collectEvents` decodes them back to `ContractEvent` objects before `finalizeSuccess` hashes the original bytes. With metadata disabled, `setEvents` feeds a disabled meta builder, but the decode/materialization path still runs before the success hash is finalized.

An apply-mode bridge extension can return a precomputed success hash (or a hash-ready preimage byte stream plus event byte totals) along with event XDR buffers only when metadata is enabled. Rust already owns the encoded return value and event bytes in `invoke_host_function_internal`; it can compute the success preimage hash and event-byte totals in the same pass used to encode events. C++ would verify limits from byte counts, set the result hash directly, and skip `xdr_from_opaque` event decoding on the no-meta benchmark path.

## Trigger

Run `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` with ledger-close metadata disabled. Each successful swap emits contract events, Rust encodes them for the bridge, and C++ currently decodes every event in `collectEvents` even though the success hash uses the original encoded bytes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:211-248` — internal events are externalized into XDR `ContractEvent` values during `Host::try_finish`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:707-733` and `1107-1123` — apply invocation finishes the host, encodes contract events into `Vec<Vec<u8>>`, and returns them to the bridge.
- `src/rust/src/soroban_proto_any.rs:478-506` — bridge copies encoded event buffers into `InvokeHostFunctionOutput`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-928` — C++ decodes event buffers, tracks event byte limits, then hashes the already-encoded return value and event buffers into the Soroban success result.

## Evidence

- The target path is inside `applyLedger`: the trace's `invoke_host_function@soroban-env-host/src/e2e_invoke.rs:639` is a descendant of `InvokeHostFunctionOpFrame doParallelApply`, and `collectEvents@transactions/InvokeHostFunctionOpFrame.cpp:773` appears on the same successful apply path.
- Current Tracy totals show the event/result bridge is not free: `collectEvents@transactions/InvokeHostFunctionOpFrame.cpp:773` totals **33.96ms / 8705 calls**, `write xdr@soroban-env-host/src/host/metered_xdr.rs:72` totals **168.18ms self-time**, `SHA256::add@crypto/SHA.cpp:65` totals **314.39ms self-time**, and `SAC transfer@soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` totals **2.915s / 17,381 calls** where transfer events are produced. The proposed bridge targets the repeated event externalization/encoding/decode/hash handoff, not the mandatory SAC transfer body.
- Source confirms C++ hashes `out.result_value.data` and each `out.contract_events` buffer directly in `finalizeSuccess`, so decoded `ContractEvent` objects are only needed for event-size accounting and metadata population. Event-size accounting can be performed from the encoded lengths, and metadata population is already unnecessary on the no-meta benchmark path.

## Anti-Evidence

- Prior event-specific investigations were rejected when they targeted only SAC event construction or only C++ event decoding. This hypothesis is viable only if the PoC removes the whole no-meta event/result handoff slice — Rust externalization/encoding duplication plus C++ decode/hash plumbing — and shows a reproducible 3%+ soroswap gain.
- Consensus hashing cannot change. The Rust-computed hash must be byte-for-byte identical to `xdrSha256(InvokeHostFunctionSuccessPreImage)` as currently streamed by C++, including event ordering and return-value encoding.
- Event bytes are still required for metadata-enabled ledgers and for diagnostic/event-size behavior. The no-meta fast path must be gated on the same metadata/diagnostic conditions used by the benchmark and must fall back to the current decoded event path otherwise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — broader than the prior `023-meta-disabled-event-decode-below-threshold.md` summary entry, but the traced removable subset collapses to the same sub-threshold no-meta event-decode class
**Failed At**: reviewer

### Trace Summary

The no-meta apply path is real: `LedgerManagerImpl::applyTransactions` disables transaction meta when no ledger-close meta frame is being emitted, and the downstream `OperationMetaBuilder`/`OpEventManager` calls become no-ops. However, successful Soroban apply still must produce the encoded return value and encoded contract-event bytes because those bytes define the consensus result hash, event-size limit, and refundable fee accounting. Moving success-hash construction from C++ to Rust would mostly shift mandatory SHA/XDR work across the bridge; the actually avoidable work is the C++ `xdr_from_opaque` event decode, result-value decode for disabled meta, and returning event buffers that are only needed by C++ to hash/size them. That slice is covered by the prior failed event-decode finding and is far below the objective's 3% Medium floor.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2835-2846` — `enableTxMeta` is false when `ledgerCloseMeta == nullptr`, which is the benchmark no-meta mode.
- `src/ledger/LedgerManagerImpl.cpp:2992-2999` and `src/transactions/ParallelApplyStage.h:22-25` — each Soroban `TxBundle` still constructs `TxEffects`, but with a disabled `TransactionMetaBuilder`.
- `src/transactions/TransactionMeta.cpp:454-463` — `OperationMetaBuilder::setSorobanReturnValue` returns immediately when meta is disabled, so the C++ result-value decode in `finalizeSuccess` is not needed for no-meta output.
- `src/transactions/EventManager.cpp:503-512` — `OpEventManager::setEvents` returns immediately when meta is disabled, so decoded `ContractEvent` objects are not published on this path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-817` — `collectEvents` computes event counts/bytes and enforces the event-size limit, but also decodes every encoded event into `ContractEvent` solely to populate `success.events`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:819-928` — refundable fee charging consumes `mEmitEventByte`, and `finalizeSuccess` decodes the return value, streams the already-encoded return/event bytes into SHA256, stores the success hash, and calls disabled meta setters on the no-meta path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-580` — after host execution, Rust calls `Host::try_finish`, encodes the returned `ScVal`, computes ledger changes, and encodes contract events whenever invocation succeeds.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:771-777` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:211-248` — finishing the host externalizes internal events into XDR `ContractEvent` values with observable metering.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:954-970` — `encode_contract_events` serializes non-failed, non-diagnostic contract events through `metered_write_xdr`; these XDR bytes are required for the success preimage.
- `src/rust/src/soroban_proto_any.rs:478-506` and `src/rust/src/bridge.rs:34-55` — the bridge returns encoded result bytes, encoded event buffers, modified ledger entries, and fee data to C++.

### Why It Failed

The hypothesis overstates the removable work. Rust event externalization and event/result XDR serialization are not duplicate metadata-only work: they are the source of the consensus success preimage bytes and visible resource accounting. A Rust-computed success hash can avoid returning event buffers to C++ in no-meta mode, but the host must still externalize events, serialize each event, include the event count, hash the same byte stream, compute the same byte totals, and preserve metered XDR behavior. That means the large cited `write xdr` and `SHA256::add` totals are not eliminated; at best they move or shrink by avoiding the C++ bridge/decode layer.

The remaining no-meta-only cleanup is too small for this objective. The cited `collectEvents` total is 33.96 ms across 8705 calls; under the `T=8` parallel soroswap shape, even treating all of it as removable gives only a few milliseconds of critical-path savings, well under 1% of the cited apply baseline and below the 3% Medium acceptance threshold. Adding the small no-meta return-value decode and event-buffer handoff savings does not change that order of magnitude, while a broader design that changes metered event externalization/serialization would be protocol-visible rather than a safe bridge optimization.

### Lesson Learned

For Soroban events, metadata-disabled does not mean event-disabled: event XDR bytes remain consensus input and fee/limit input. Future no-meta bridge hypotheses need to isolate work that is truly not needed for hashing, metering, storage effects, diagnostics, or fees, and then project critical-path savings after dividing aggregate worker totals by cluster parallelism.
