# H001: Add typed SAC balance storage helpers to avoid generic Val/ScVal round-trips

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / soroban host bridge
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated host-object visits and Val/ScVal conversions in Stellar Asset Contract balance updates
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The built-in Stellar Asset Contract already manipulates strongly typed Rust values such as `DataKey::Balance(Address)` and `BalanceValue`. When the SAC reads, writes, and extends a balance entry during soroswap, the efficient apply path should construct the corresponding `LedgerKey::ContractData` and `LedgerEntryData::ContractData` directly, preserve the same storage access checks and TTL behavior, and avoid converting the same typed key/value into host `Val`s only for `Host::put_contract_data_into_ledger` to convert them back into `ScVal`s.

## Mechanism

`balance.rs` repeatedly converts SAC-native typed values through the generic contract storage API. `read_balance` calls `key.try_into_val(e)?` for both `try_get_contract_data` and `extend_contract_data_ttl`; `write_contract_balance` calls `key.try_into_val(e)?` for `put_contract_data` and again for `extend_contract_data_ttl`, while also converting `BalanceValue` to a host value. The generic `Host::put_contract_data` path then calls `storage_key_from_val(k)` and `from_host_val(v)` in `put_contract_data_into_ledger`, so the built-in code pays host-object allocation/visitation and `Val` -> `ScVal` conversion for values it already had in typed Rust form.

For soroswap this is amplified by every swap invoking SAC transfers for multiple token balances. The current soroswap trace shows the longest `applyLedger` window contains `visit host object` at 1,100.202 ms over 1,178,134 calls, `ScVal to Val` at 342.097 ms over 210,512 calls, `Val to ScVal` at 303.261 ms over 205,928 calls, `storage get` at 401.174 ms, and `storage put` at 69.366 ms. A typed internal SAC write/TTL helper that takes `DataKey`/`BalanceValue` directly, builds the `LedgerKey` once, calls `Storage::{put,extend_ttl}` with that key, and charges an equivalent budget amount for any protocol-visible conversion work should remove a large fraction of this generic conversion overhead without changing ledger effects.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) and inspect the largest `applyLedger` interval in the current trace. The trigger is any SAC transfer between contract addresses: `contract.rs:222-223` calls `spend_balance` and `receive_balance`, which call the balance helpers that repeatedly route through `try_into_val`, `try_get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` converts the same `DataKey::Balance` twice on the found-balance path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:73-97` — `write_contract_balance` converts the same balance key for `put_contract_data` and TTL extension, and converts `BalanceValue` through a host value.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,156-209,233-245` — SAC balance call sites that amplify the generic key/value conversion cost.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/storage_types.rs:24-35` — typed SAC `BalanceValue` and `DataKey::Balance` inputs for the fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2189-2205,2292-2318` — generic host storage API currently used by SAC helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — `put_contract_data_into_ledger` reconstructs storage keys and ledger entries from generic host values.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267,333-389,532-573` — typed fast path should still funnel through storage map get/put/extend primitives after constructing the ledger key once.

## Evidence

- Tracy scope check: the conversion/object zones cited above are inside the longest `applyLedger` window, whose enclosing path is `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame doParallelApply`.
- The local source pattern is a round-trip: `DataKey::Balance` / `BalanceValue` -> host `Val` in `balance.rs`, then `Val` -> `LedgerKey` / `ScVal` / `LedgerEntry` in `data_helper.rs`. For built-in SAC code this generic boundary is not needed for ABI compatibility because no external contract observes the intermediate `Val`.
- Soroswap is SAC-heavy: every swap performs SAC balance reads/writes for the token legs, and the longest apply window has 2,921 `SAC transfer` events totaling 1,141.833 ms of worker time.
- The proposal is narrower than prior reviewed map-construction/XDR-output hypotheses: it targets SAC built-in typed storage calls before they enter the generic host storage API, not `MeteredOrdMap` input building or Rust output materialization.

## Anti-Evidence

- Host budget accounting is protocol-visible. A fast path must either charge equivalent conversion/storage costs or deliberately update the metering model with tests that prove no accepted transaction changes result unexpectedly. Skipping all conversion charges would be fast but may change borderline `INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED` behavior.
- The generic API is still required for user Wasm contracts and non-SAC built-ins; this optimization should be an internal SAC helper only.
- Some host-object visits come from address validation, event construction, map comparisons, and user contract execution, so this will not remove the full 1.1 s `visit host object` worker total. The hypothesis is Medium because eliminating even 20-30 ms wall time from repeated SAC balance conversions would clear the 3% threshold on the 620 ms soroswap baseline.
- Care is needed to keep diagnostic errors identical: storage key support checks, missing balance behavior, authorization flags, TTL extension threshold behavior, and decorated storage errors should remain equivalent to the generic path.
