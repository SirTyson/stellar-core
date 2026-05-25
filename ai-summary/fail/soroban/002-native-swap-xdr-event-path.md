# H002: Direct XDR Event Emission for Native Soroswap Swap Events

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce native Soroswap swap apply time by avoiding host-object `VecObject`/`MapObject` construction for a fixed event shape
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The protocol-gated native Soroswap pool `swap` path should emit the exact same `ContractEvent` as the Wasm pair contract: topics `[Symbol("SoroswapPair"), Symbol("swap")]` and a data map with `amount_0_in`, `amount_0_out`, `amount_1_in`, `amount_1_out`, and `to` in the same deterministic order. Because this native path constructs a fixed, known event schema, it should be able to build the event as XDR `ScVal` data directly and append it to the host event buffer without first materializing host `Symbol`, `VecObject`, and `MapObject` objects.

## Mechanism

`call_native_soroswap_pool_swap` currently builds the swap event through generic host object APIs: four integer `Val` conversions, two `symbol_new_from_slice` calls, `vec_new_from_slice` for topics, `map_new_from_slices` for event data, and `record_contract_event`. Those APIs are appropriate for arbitrary contract code, but redundant for this allowlisted native path whose event keys, order, and value types are hard-coded. A native-only `record_contract_event_xdr`/`InternalContractEvent::Xdr` path could store prebuilt XDR topics/data and defer only the normal event-buffer push/rollback behavior, avoiding host-object table churn and metered map/vector construction inside every swap.

## Trigger

Run the current soroswap apply-load benchmark with the accepted native pool stack. Every successful native pool swap reaches `call_native_soroswap_pool_swap` and emits the fixed swap event via `map_new_from_slices` and `record_contract_event`. In the diagnostic Tracy trace, unwrap containment shows most generic object-construction events (`new map`, `new vec`, `add host object`, `map lookup indexed`) occur inside `applyLedger` windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1333-1375` — native Soroswap swap event construction through generic host `Val`/map/vector APIs.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — `record_contract_event` currently requires host-object topics and data.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:15-39` — `InternalContractEvent` stores `VecObject`/`Val` and externalizes by converting host objects back to XDR.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `new map` zone hit by generic event-data map construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:107` — `new vec` zone hit by generic event topic construction.

## Evidence

- Current soroswap Tracy self-times inside the host object/map surface are still large after the accepted raw instance-storage and host-metering work: `new map` is 393,666,531 ns self over 183,555 calls, `new vec` is 109,486,475 ns self over 121,758 calls, `add host object` is 308,563,937 ns self over 1,001,858 calls, and `map lookup indexed` is 532,467,330 ns self over 931,436 calls.
- Unwrap containment against `applyLedger` confirms the target surface is in scope: `new map` has 183,017/183,555 events inside apply windows, `add host object` has 999,140/1,001,858, and `map lookup indexed` has 929,010/931,436.
- The exact source code at `frame.rs:1340-1368` constructs the fixed event schema dynamically on every swap even though all keys are static ASCII symbols and the map order is known. This is a structural observation independent of stale pre-native traces.

## Anti-Evidence

- Broad ScVal/Val conversion and host-object interning proposals have previously failed as sub-threshold when they preserve all p26 metering charges. This hypothesis must remain narrower: direct XDR event emission for the already protocol-gated native Soroswap swap event, with an explicit next-protocol metering schedule if the host-object construction charges are intentionally removed.
- `InternalEventsBuffer` rollback semantics and event externalization must remain unchanged. A direct-XDR variant must still mark failed-call events correctly and produce byte-for-byte equivalent `ContractEvent` XDR for successful swaps.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate in soroban fail/success; prior rows cover adjacent event-symbol and SAC-event sub-slices only
**Failed At**: reviewer

### Trace Summary

The native Soroswap pool `swap` path is real: `call_contract_fn` detects the allowlisted pool Wasm and pushes a `Frame::NativeContract`, then `call_native_soroswap_pool_swap` performs validation, SAC transfers/balance reads, reserve updates, and fixed swap-event construction. The event is currently built through generic host APIs and later converted back to XDR during host finalization. A direct-XDR event variant would remove real per-swap object construction/externalization work, but the whole cited map/vector/object surface is too small after 8-way parallel-apply normalization, and the swap-event-specific slice is only a subset of that already-sub-Medium surface.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-812` — native dispatch matches the p27-gated pool `swap` and executes it inside `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — successful native swaps update reserves, convert four amounts to `Val`, allocate two symbol objects, build a topic `VecObject`, build a five-entry data `MapObject`, and call `record_contract_event`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1021-1065` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1109-1117` — `symbol_new_from_slice`, `map_new_from_slices`, and `vec_new_from_slice` validate inputs, charge/clone, construct host containers, and insert objects into the host object table.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — `record_contract_event` stores `InternalContractEvent { contract_id: BytesObject, topics: VecObject, data: Val }`.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:15-39` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:167-249` — event rollback/status handling is independent of representation, but externalization converts stored host objects back into `ContractEvent` XDR values.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:197-204`, `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:266-273`, and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-478` — `vecobject_to_scval_vec`, `host_map_to_scmap`, and `from_host_val` perform the host-object-to-XDR conversion that a direct-XDR internal event could bypass for this fixed event.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-580` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:954-969` — after `try_finish`, successful contract events are encoded as XDR bytes for the C++ bridge.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:770-799` and `src/transactions/InvokeHostFunctionOpFrame.cpp:909-918` — C++ records metrics, decodes event XDR into metadata, and hashes the already-encoded event bytes into the result.

### Why It Failed

The inefficiency exists, but it does not clear the objective's Medium severity floor. The hypothesis cites broad apply-contained totals for `new map` (393.7 ms), `new vec` (109.5 ms), `add host object` (308.6 ms), and `map lookup indexed` (532.5 ms), but even the impossible upper bound of eliminating all of those categories is only about `(393.7 + 109.5 + 308.6 + 532.5) ms / 8 clusters / 71 ledgers = 2.37 ms/ledger`, roughly 1.1% of a ~218 ms soroswap apply baseline and below the 3% Medium threshold. The native swap-event path can only remove one event's subset of those generic zones per swap, while most calls in the broad categories come from other host/storage/event work that must remain. Existing soroban fail-summary rows independently bound direct event-XDR and event-symbol variants as sub-Low (`007-direct-sac-transfer-event-xdr.md`, `012-pre-intern-native-pair-event-symbols.md + 008-native-pool-swap-event-symbols-precompute.md`, and `013-recordstoragechanges-xdr-from-opaque-redecode.md + 006-collectevents-xdr-redecode-per-tx.md`), reinforcing that isolated event representation work is below the accepted review threshold.

### Lesson Learned

For native Soroswap event optimizations, do not size the proposal from broad host-object and map/vector aggregate zones. A fixed swap event is one event per successful swap; after parallel-worker normalization, even the full generic object/map/vector envelope is below Medium, so a narrower direct-XDR event builder cannot satisfy this objective without being part of a larger, measured redesign that removes additional dominant apply-path work.
