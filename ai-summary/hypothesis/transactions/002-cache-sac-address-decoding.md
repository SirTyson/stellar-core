# H002: Cache Decoded SAC Address Wrappers

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated host-object visits and metered clones for the same SAC address arguments
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC balance and transfer logic should continue to distinguish account addresses from contract addresses, enforce authorization, construct the same balance keys, emit the same events, and preserve the same externally visible host object handles for contract arguments. Once a SAC `Address` wrapper has been constructed from an `AddressObject`, repeated `to_sc_address()` calls on that wrapper or its clones should not repeatedly look up and clone the same `ScAddress` host object.

## Mechanism

`builtin_contracts::base_types::Address` stores only `{ host, object }`, and `Address::to_sc_address()` calls `Host::scaddress_from_address` every time. That helper enters the hot `visit host object` path and metered-clones the underlying `ScAddress`; SAC `transfer` then clones and reuses the same `from`/`to` addresses through `require_auth`, authorization checks, `spend_balance`, `receive_balance`, and event emission. In the current longest soroswap `applyLedger` interval, `visit host object` accounts for 1.074 s of aggregate overlap across 1.226M calls, while global self-time shows `visit host object` at 657.549 ms and `add host object` at 79.810 ms; caching the decoded `ScAddress` inside the SAC wrapper would remove repeated address-object visits from this dominant SAC path without changing parallel scheduling or ledger ordering.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) using the trace in `ai-summary/CURRENT_STATE.md`. The issue triggers when SAC `transfer` receives `Address` and `MuxedAddress` arguments, then repeatedly converts the same addresses to `ScAddress` while checking authorization, reading/writing balances, and building transfer events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:305-385` — `Address` stores only an `AddressObject`; `to_sc_address` calls back into the host on every use.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — `scaddress_from_address` uses `visit_obj` and `metered_clone` for each address decode.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — SAC `transfer` calls `from.require_auth`, clones `from` and `to`, and passes them through balance and event helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` converts the same wrapper with `to_sc_address`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` converts, clones, and reuses the same address while checking and writing contract balances.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-190` — `spend_balance_no_authorization_check` repeats the same address conversion and balance-key construction.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:232-254` — `is_authorized` converts contract addresses again to decide the authorization path.

## Evidence

The target is under `applyLedger`: the longest steady soroswap apply window contains 3,042 `SAC transfer` calls, 3,039 `SAC balance` calls, 1.112 s of `SAC transfer` aggregate overlap, and 1.074 s of `visit host object` overlap. The source shows that a contract-address transfer can call `to_sc_address()` for the same logical address in `is_authorized`, `spend_balance_no_authorization_check`, `receive_balance`, and event/key construction, and each call currently performs a host object lookup plus `ScAddress` clone. An eager or lazy `Address { host, object, sc_address }` representation, populated once when converting from `AddressObject`, should turn repeated conversions into cheap field reads while keeping the original object handle for `require_auth`, comparisons, and emitted arguments.

## Anti-Evidence

This overlaps the general `visit host object` hotspot, but it is not the previously failed host-object budget batching idea: it removes repeated visits for already-decoded SAC address wrappers rather than reordering or batching budget charges across arbitrary objects. The reviewer must quantify how much of `visit host object` comes specifically from SAC address conversion; if most visits come from maps, vectors, events, or VM boundary conversions, this may fall below the 3% Medium floor. Budget metering also needs an explicit decision: either preserve same-protocol resource accounting by charging equivalent clone/visit costs when returning the cached address, or gate the lower resource usage as an intentional protocol-versioned optimization.
