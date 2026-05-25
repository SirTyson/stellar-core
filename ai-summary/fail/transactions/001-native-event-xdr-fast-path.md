# H001: Native Contract Event XDR Fast Path

**Date**: 2026-05-25
**Subsystem**: transactions / Soroban native contract apply
**Severity**: Medium
**Impact**: soroswap apply-time reduction in native Soroswap/SAC event construction and extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-gated native Soroswap pool swaps and native Stellar Asset Contract transfers, apply should emit the exact same `ContractEvent` XDR, result hash input, event ordering, failed-call rollback behavior, and fee/refundable-resource accounting as the current host-object event path. Non-native contracts, older protocols, muxed transfer data, mint/burn classification, diagnostic events, and unexpected event shapes should continue through the existing `VecObject`/`Val`-backed event machinery.

## Mechanism

The native Soroswap/SAC paths build known fixed-shape events by allocating host vectors/maps/symbols and later converting those host objects back to `ContractEvent` XDR during event extraction. A next-protocol-gated `InternalEvent` variant or helper that records a prebuilt/native `ContractEvent` for these allowlisted shapes would avoid the physical host-object construction and `from_host_val`/`vecobject_to_scval_vec` round trip while preserving deterministic event XDR. This is significant for soroswap because each swap emits repeated SAC transfer events plus a native pair swap event inside the parallel apply workers.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load workload where the native pool swap path calls one or more SAC transfers and records the `SoroswapPair` `swap` event. The fast path should trigger only for protocol-gated native event constructors that can construct the final `ContractEvent` XDR directly and should fall back to `record_contract_event` for all generic host events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — classifies SAC transfer/mint/burn events before constructing topics/data through host objects.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-113` — constructs SAC transfer topics with `host_vec!` and records the event through `contract_event`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1336-1374` — native Soroswap pool swap constructs static symbols, a topics vector, a 5-field data map, and records the swap event.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — `record_contract_event` stores events as `VecObject` topics plus `Val` data.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-38` — event extraction converts stored host objects back to XDR.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` confirms these costs are inside `applyLedger`: `SAC transfer` at `contract.rs:212` overlaps apply for 17,333 events and 2,910,469,315 ns total; `new map` overlaps apply for 499,524,207 ns; `add host object` for 389,555,340 ns; `ScVal to Val` for 970,817,255 ns; `Val to ScVal` for 379,268,779 ns; and `write xdr` for 188,155,837 ns. These are worker aggregates and must be divided by T=8, but the combined fixed native-event construction/extraction surface has a Medium-sized upper bound if a large fraction belongs to SAC transfer and native swap events.

## Anti-Evidence

The cited conversion/object zones are broad and include non-event storage, auth, and VM boundary work, so the PoC must add subspans or counters proving that native event construction/extraction accounts for a Medium-sized subset. This cannot skip protocol-visible metering under the current protocol; it likely needs next-protocol gating or explicit equivalent charges for static symbols, vectors, maps, and XDR encoding.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related records exist (`023-auth-event-frame-microcosts-below-threshold.md` for native auth/event construction and `029-skip-collectEvents-decode-disabled-meta.md` for C++ event decode), but this exact Rust-side native `ContractEvent` fast path was not separately reviewed
**Failed At**: reviewer

### Trace Summary

The claimed inefficiency is real: native SAC transfer and native Soroswap swap events are built as host `VecObject`/`MapObject`/symbol objects, then `InternalContractEvent::to_xdr` converts those objects back into `ContractEvent` XDR during host finalization, and C++ decodes the resulting event bytes into metadata. However, the removable portion is only the fixed-shape event object/conversion subset, not the full `SAC transfer`, `add host object`, `ScVal to Val`, `Val to ScVal`, or `write xdr` Tracy totals cited by the hypothesis. Those broad zones include mandatory auth, balance updates, TTL extension, storage conversion, event result hashing, and enabled metadata materialization, so the projected apply-time win falls below the objective's 3% Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `SAC transfer` includes amount validation, `require_auth`, TTL extension, balance debit/credit, and only then calls `event::transfer_maybe_with_issuer`; the event fast path cannot remove most of this span.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,67-113` — SAC classifies transfer/mint/burn and builds transfer topics with `host_vec!`; muxed transfers use a map and should not take the proposed simple transfer fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:780-824,1178-1375,1465-1481` — native Soroswap dispatch calls one or two SAC transfers, reads balances, updates reserves, then builds the `SoroswapPair/swap` event with symbols, a topics vector, and a five-entry data map.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1021-1065,1109-1117` and `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` — the targeted event constructors allocate symbols, maps, vectors, and host objects, but these helpers are also used heavily outside event construction.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,167-245` — contract events are stored as `InternalContractEvent { type_, contract_id, topics, data }`, rollback is tracked separately via `EventError`, and externalization converts every successful contract event to XDR through `vecobject_to_scval_vec` and `from_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-580,954-969` — host finalization externalizes events and then XDR-encodes non-failed, non-diagnostic contract events for the C++ bridge.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-816,879-924,993-1015` — apply collects event byte sizes, decodes `ContractEvent` objects for enabled metadata, consumes refundable resources from event bytes, hashes the raw event XDR for the result, and stores events in operation metadata.

### Why It Failed

This is below the objective severity threshold. A protocol-gated native event representation could remove some fixed-shape host-object construction and Rust-side event externalization for allowlisted SAC transfer and Soroswap swap events, but it cannot remove the dominant work inside the cited `SAC transfer` span or the broad conversion/object zones. It also still needs deterministic event XDR bytes for result hashing, event-size/refundable-resource accounting, failed-call filtering, and enabled metadata, so C++ metadata decode remains on the benchmark path. Prior review of the broader native auth/event bundle already bounded the combined auth/context/event family just under Medium before subtracting mandatory work; this narrower event-only subset is necessarily smaller.

### Lesson Learned

Native event construction is a real inefficiency, but Tracy zones such as `SAC transfer`, `add host object`, `ScVal to Val`, `Val to ScVal`, and `write xdr` are too broad to justify a Medium hypothesis without event-specific counters. Future candidates need to show that allowlisted native event construction/externalization alone reaches at least 3% of apply time after T-way worker parallelism and after preserving protocol-visible metering and metadata requirements.
