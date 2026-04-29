# H002: Build SAC transfer events as XDR directly instead of host-object vectors

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban SAC event emission
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing host-object event topic/data construction and later host-object-to-XDR externalization for hot SAC transfer events
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC event emission should produce exactly the same `ContractEvent` XDR for `transfer`, `mint`, `burn`, and related token events, with the same ordering, contract ID, topics, data, event-size metering, refundable fee behavior, and failure rollback semantics. The efficient path should not first construct event topics and data as host `VecObject` / `Val` objects only for `Events::externalize` to convert those objects back into `ScVal` XDR and for `encode_contract_events` to serialize the same event later.

## Mechanism

The SAC event helpers build topics with `host_vec!`, convert symbols/addresses/amounts into host values, call the generic `contract_event` host function, store an `InternalContractEvent` containing `VecObject` and `Val`, then externalize by calling `vecobject_to_scval_vec` and `from_host_val` on every event. For soroswap, every swap emits SAC transfer events from the token legs, so this round-trip repeats thousands of times inside parallel apply. A SAC-only internal event builder can construct the final `xdr::ContractEvent` from typed `Address`, `String`, amount, and optional muxed ID, push an internal "already XDR" event variant, and charge equivalent deterministic costs while bypassing host-object vector/map construction and the later object externalization walk.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md`. Inside the `applyLedger` windows, `SAC transfer` appears 6,656 times for 2,406.469 ms aggregate and 346.175 ms summed per-window critical-worker time. The same windows contain 2,689,616 `visit host object` events totaling 2,372.465 ms aggregate / 345.834 ms critical-worker time and 132,907 `write xdr` events totaling 1,071.529 ms aggregate / 155.368 ms critical-worker time; SAC event construction and externalization are one concrete repeated source of both object visits and XDR writes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` - `transfer_maybe_with_issuer` / `transfer` build event topics through `host_vec!`, call `read_name`, and emit through `contract_event`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:116-166` - `mint`, `burn`, `clawback`, and other SAC event helpers follow the same host-object event construction pattern.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1284-1291` - generic `contract_event` dispatch records host-object topics/data.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` - `record_contract_event` stores an `InternalContractEvent` with `VecObject` topics and `Val` data.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,211-248` - externalization converts stored host objects back into `xdr::ContractEvent` values before Core receives them.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:874-889` - `encode_contract_events` serializes each externalized event into a fresh byte buffer returned over the C++ bridge.

## Evidence

- Tracy scope check: `SAC transfer`, `visit host object`, and `write xdr` events are inside `applyLedger` windows under the parallel Soroban apply path, not background bucket work or TX-set construction.
- The source forms a round-trip: typed SAC data (`Address`, `amount`, metadata name) becomes host objects through `host_vec!` / `try_into_val`, is stored as host-object handles in `InternalContractEvent`, and is later converted back to XDR by `InternalContractEvent::to_xdr`.
- Event emission is on the soroswap headline path. Every SAC `transfer` calls `event::transfer_maybe_with_issuer` after balance mutation, and the current trace shows two SAC transfer events per invoke-shaped swap in the hot windows.
- This is distinct from the reviewed balance-storage and host-object batching hypotheses. It targets SAC event construction/externalization specifically and can leave generic user-contract `contract_event` behavior unchanged.

## Anti-Evidence

- The generic `contract_event` self-time is small; most potential savings are in the object construction, object visitation, and XDR externalization it triggers. A PoC must add narrow spans or counters around SAC event helpers and `InternalContractEvent::to_xdr` to isolate the event share.
- Event metering is observable through refundable fees and resource-limit failures. A direct-XDR event path must charge the same logical event construction, externalization, and serialized-size costs or intentionally change metering only behind a protocol gate.
- `transfer_maybe_with_issuer` also performs issuer classification and metadata reads; prior work in another subsystem found simple SAC metadata caching alone below threshold. This hypothesis should not be reduced to metadata caching; the proposed win depends on removing the host-object event round-trip and later externalization work.
- The event representation is used by diagnostics and rollback status (`failed_call`). The direct-XDR variant must preserve event cancellation on failed frames and maintain the same filtering of diagnostic versus contract events in `Events::externalize` and `encode_contract_events`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The hypothesized round-trip exists: SAC event helpers create host vectors/maps, `contract_event` stores a `VecObject` plus `Val`, and `InternalEventsBuffer::externalize` later converts those handles into `xdr::ContractEvent`. The path is also in the apply worker: `SAC transfer` calls balance/auth/TTL logic and then emits the event before `Host::try_finish` externalizes events and `encode_contract_events` serializes them. However, the removable subset is much smaller than the cited inclusive zones: final `write xdr` serialization remains required for event-size accounting and bridge output, and a direct-XDR builder still has to visit/clone the address, name, and contract-id data once to produce the same `ScVal` topics. The likely savings are limited to the SAC topics `HostVec` allocation/object-table entry, optional muxed-data map construction, generic `Val`-to-`ScVal` dispatch during event externalization, and the internal contract-id bytes object, which does not plausibly clear the objective's 3% Medium floor.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — hot SAC `transfer` performs amount check, auth, TTL extension, balance debit/credit, then calls `event::transfer_maybe_with_issuer`; the `SAC transfer` Tracy span is inclusive of all of this non-event work.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — `transfer_maybe_with_issuer` classifies issuer/mint/burn cases and `transfer` builds a topics `HostVec` with `"transfer"`, `from`, `to`, and `read_name(e)?`, then records amount or muxed amount data.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:67-89,116-166` — muxed transfer data allocates and updates a host map; mint/burn/clawback/admin event helpers use the same host-vector event construction shape, but soroswap's common transfer amount data is just an immediate `i128` host value.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:63-69` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:1085-1092` — `host_vec!` converts each topic to `Val`, builds a `HostVec`, checks value integrity, and stores it as a host object.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1284-1291` and `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — generic contract-event recording stores the event type, current contract ID as a bytes object, topics `VecObject`, and data `Val` in `InternalContractEvent`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:223-230,254-256,407-419,463-540` — current-contract ID recording copies the 32-byte ID into a host bytes object; address/name conversion to XDR requires visiting host objects and metered cloning, which a direct-XDR builder would still need once.
- `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,211-248` — externalization walks the stored topics vector, calls `from_host_val` for every topic/data value, converts the contract-id bytes object back to `ContractId`, and preserves `failed_call` status when collecting `HostEvent`s.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-225` — frame rollback snapshots the event-buffer length and marks later events as `FromFailedCall`, so any alternate internal event representation must keep the same chronological buffer and rollback status behavior.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:747-755`, `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:836-846`, and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:874-889` — successful invocation finish externalizes events, serializes each non-failed non-diagnostic `ContractEvent` with `metered_write_xdr`, uses encoded lengths for resources, and returns the filtered XDR events; this final serialization is not removed by storing XDR internally.

### Why It Failed

The local inefficiency is real, but the Medium-severity optimization claim is not. The cited `SAC transfer` timing is inclusive of required auth, TTL, balance mutation, issuer classification, and metadata reads; the cited `visit host object` and `write xdr` totals are broad apply-window categories, not event-specific removable work. A correct direct-XDR SAC event path would still perform the address/name/contract-id conversions needed to build equivalent `ScVal` topics and would still run `encode_contract_events` to charge `ValSer`, compute contract-event sizes, and return event bytes. That leaves only a small event-container/externalization dispatch reduction, plus optional muxed-transfer map savings that the common soroswap transfer path does not use. Under the optimize-soroswap objective, Low-tier findings are rejected, and this projected impact is below the 3% Medium threshold.

### Lesson Learned

Do not attribute inclusive `SAC transfer`, broad `visit host object`, or final `write xdr` Tracy time to SAC event construction. Event-representation optimizations must isolate the exact externalization/container work they remove, and must account for the conversions and final metered serialization that remain mandatory for identical events, resources, rollback, and bridge output.
