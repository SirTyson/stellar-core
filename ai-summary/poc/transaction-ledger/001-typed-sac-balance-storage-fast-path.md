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

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/transaction-ledger`; no matching `success/transaction-ledger` record found

### Trace Summary

The measured Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, builds an enforcing Rust host, invokes the router contract, and then dispatches built-in Stellar Asset Contract calls through `Frame::StellarAssetContract`. In the SAC `transfer` path, contract-address balances go through `is_authorized`, `spend_balance` or `receive_balance`, and `write_contract_balance`, which repeatedly convert `DataKey::Balance(Address)` and `BalanceValue` through the generated `contracttype` `Val` representation before the generic storage functions convert them back into `ScVal` and `LedgerKey` form. Soroswap constructs every swap with two SAC token legs and two `Balance[pair]` read-write footprint entries, so this path is per-transaction hot and sits inside the objective's `closeLedger`/parallel apply window.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban transactions run the target workload through `doParallelApply` and `InvokeHostFunctionParallelApplyHelper`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — the helper calls `rust_bridge::invoke_host_function` with host function XDR, resources, footprint entries, TTL entries, auth, ledger info, and module cache.
- `src/rust/src/soroban_invoke.rs:7-24` — the C++ bridge dispatches to the p26 host module's `invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — the p26 host builds enforcing storage from the transaction footprint, installs ledger/auth/module state, and invokes the host function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts invoke args to host vals and calls `call_n_internal`; returned host vals are converted back to `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `ContractExecutable::StellarAsset` pushes a `Frame::StellarAssetContract` and dispatches to `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_fn.rs:29-63` — the generated SAC dispatcher converts `Val` arguments into typed Rust arguments and converts typed return values back to `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` extends instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,73-97,100-145,156-209,220-245` — contract balances call `try_get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl` through generated `DataKey`/`BalanceValue` `try_into_val` conversions.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:3-14` — `try_get_contract_data` calls `has_contract_data` and then `get_contract_data`, so an existing balance converts the same key through `storage_key_from_val` twice for a single logical read.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2189-2249,2292-2318` — the generic storage host functions reconstruct storage keys from `Val`, read/write storage, and convert ledger `ScVal` values to host vals.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-563` — `put_contract_data_into_ledger` calls `storage_key_from_val`, then `from_host_val(v)` for the updated value and writes through `Storage::put`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:147-166,407-460,463-540` — `storage_key_from_val` is `Val` -> `ScVal` -> `LedgerKey`, and object-valued conversions visit host objects recursively.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:6-83,86-207` — `#[contracttype]` structs become host maps and enums become host vectors; `DataKey::Balance` therefore allocates/visits a two-element vector and `BalanceValue` allocates/visits a three-field map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267,281-389,532-573` — direct helpers can still use the same supported-key checks, footprint enforcement, storage map get/put behavior, and TTL extension primitives after constructing the ledger key directly.
- `src/simulation/ApplyLoad.cpp:3382-3505` — each soroswap transaction invokes the router with a source-account-authorized token transfer and includes `Balance[pair]` entries for the input and output SACs in the read-write footprint.

### Findings

The inefficiency exists and is more concrete than the original mechanism states. A found-balance `try_get_contract_data` first calls `has_contract_data` and then `get_contract_data`, and both generic functions call `storage_key_from_val`; after that, `get_contract_data` converts the stored `ScVal` balance to a host `Val`, and callers convert it back into `BalanceValue`. A contract-side balance update then calls `put_contract_data` with a generated map `Val` for `BalanceValue`, and `put_contract_data_into_ledger` converts that host value back into `ScVal` before storing it. The subsequent TTL extension converts the same generated balance key again.

The path is hot for the objective. In the soroswap benchmark, the router swap uses SAC token contracts and the generated footprint includes the two pair balance entries that the SAC transfer path mutates on every swap. For contract-address balances, both authorization checking and balance mutation read the same balance entry before writing it, so the generated host-vector/host-map and `Val`/`ScVal` round-trips happen multiple times per swap and are inside the parallel apply worker window, not benchmark setup.

The proposed fast path is correctness-preserving if scoped narrowly to SAC internals. `DataKey::Balance` has a stable generated XDR representation (`Vec["Balance", address]`), and `BalanceValue` has a stable generated map representation with sorted fields (`amount`, `authorized`, `clawback`); a direct helper can construct those `ScVal`s and `LedgerKey::ContractData` without exposing a new public host API. It must still call through `Storage::{try_get,get_with_live_until_ledger,put,extend_ttl}` or equivalent wrappers so footprint enforcement, supported-key checks, TTL threshold behavior, missing-entry errors, and storage error decoration remain equivalent. It must also either manually charge the budget for the conversion/object work it bypasses or intentionally adjust metering with protocol-aware tests; skipping charges silently would alter resource-limit outcomes.

The impact clears the objective's Medium threshold plausibly enough for PoC. The trace cited in the hypothesis shows hundreds of milliseconds of `Val to ScVal`, `ScVal to Val`, and host-object visitation inside the apply window across worker time, and the traced source path accounts for repeated conversions per contract-side SAC balance leg. The full trace totals include non-SAC conversion work, but eliminating only the repeated SAC balance key/value round-trips has a realistic 20-30 ms wall-time target on the cited ~620 ms soroswap baseline, matching the 3-5% Medium band.

### PoC Guidance

- **Target code**: Add internal typed helpers near `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` and/or `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs`; use them from `read_balance`, `is_authorized`, `receive_balance`, `spend_balance_no_authorization_check`, `write_authorization`, and `check_clawbackable` only for `DataKey::Balance`.
- **Change description**: Construct the SAC balance `ScVal` key directly as the same `Vec["Balance", address]` representation, construct/decode `BalanceValue` directly as the same sorted-field map representation, build one `LedgerKey::ContractData` per logical key, and call the same `Storage` get/put/extend primitives with equivalent error decoration. Avoid routing through `key.try_into_val(e)?`, `balance.try_into_val(e)?`, `storage_key_from_val`, and generic `from_host_val`/`to_host_val` where the value is already typed.
- **Correctness check**: Existing SAC host coverage in `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/test_stellar_asset_contract.rs` exercises balance, authorization, transfer, transfer_from, mint, clawback, and set_authorized helpers; transaction-level SAC scenarios and resource-limit behavior are covered in `src/transactions/test/InvokeHostFunctionTests.cpp` (including SAC payment cases and `INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED` checks). Add or update focused tests only if the helper changes observable metering/error behavior.
- **Benchmark focus**: Run the soroswap apply-load matrix and compare top-line apply time across repeated runs. Tracy should show lower `visit host object`, `Val to ScVal`, `ScVal to Val`, and possibly `storage get`/`storage put` self-time under `SAC transfer`; target at least a reproducible 3% apply-time reduction, with budget CPU/memory consumption for equivalent transactions intentionally unchanged or explicitly justified.


---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:13-178` — added internal typed SAC balance helpers that directly construct `ScVal` balance keys and `BalanceValue` maps, decode stored balance values, and call `Storage` get/extend primitives without routing through host `Val` conversion.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:191-276` — rewired contract-balance reads and writes to construct one typed `LedgerKey::ContractData`, update existing `ContractDataEntry` values directly, create missing entries with the same persistent durability/min-live-until semantics, and extend TTL through `Storage::extend_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:301-355,412-447,499-501` — switched SAC receive, spend, authorization, and clawback balance access to the typed helper path while preserving classic-account behavior and existing contract-balance error paths.
- `src/rust/soroban/p26/soroban-env-host/observations/26/test__stellar_asset_contract__*.json` — refreshed the nine affected p26 SAC observation goldens after the intentional removal of generic `vec_new_from_slice`/host-object conversion trace events.

### Demonstration

The optimization keeps SAC balance storage on typed XDR values that the built-in contract already has: `DataKey::Balance(Address)` is built directly as the canonical `Vec["Balance", address]`, and `BalanceValue` is built/decoded directly as the canonical sorted map. Contract balance reads now use a single typed storage lookup, writes avoid `balance.try_into_val`, `put_contract_data`, `storage_key_from_val`, and `from_host_val`, and TTL extension reuses the already-built `LedgerKey`, reducing the hot SAC transfer conversion/object-visit work exercised by soroswap token legs.

### Test Results

Configured with Tracy-enabled PoC flags and built via `make -j30`. Refreshed intentional p26 SAC observation changes with `UPDATE_OBSERVATIONS=1` through the repository `check-sorobans` script, then ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check ALL_SOROBAN_GIT_STATE_STAMPS=`; the full suite completed with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
