# H001: Fuse SAC Contract-Balance Authorization and Amount Reads

**Date**: 2026-05-01
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by removing duplicate SAC contract-balance storage reads during transfer apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC transfers should keep the same authorization and balance semantics: account endpoints still use trustlines, contract endpoints still read `DataKey::Balance`, missing contract balances still authorize according to the asset's auth-required flag, insufficient balances still fail, and successful transfers still write the same final `BalanceValue` entries, TTL bumps, events, fees, and resource results. The implementation should avoid reading the same contract-balance entry twice for one endpoint when the first read already provides both the `authorized` flag and the `amount`.

## Mechanism

`receive_balance` and `spend_balance` first call `is_authorized`, which reads `DataKey::Balance(addr)` for contract addresses, and then immediately read the same balance key again to update or check the amount. Soroswap SAC transfers are on the measured apply path and frequently use contract endpoints, so this duplicates `try_get_contract_data`, `storage get`, `ScVal` conversion, host-object visits, and metered-map lookup work before every balance update. A SAC-internal helper that reads a contract balance once and returns both authorization state and amount for the update path should preserve deterministic output while cutting a large fraction of repeated SAC storage reads.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md` and inspect SAC transfer calls under `applyLedger`. The issue triggers when `SAC transfer` applies to contract-address balances: `transfer` calls `spend_balance(from)` and `receive_balance(to)`, and each contract endpoint separately performs an authorization read and an amount/update read of the same `DataKey::Balance`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - `SAC transfer` invokes both spend and receive balance paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` - `receive_balance` calls `is_authorized` and then reads the same contract balance again.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-230` - `spend_balance` calls `is_authorized` before `spend_balance_no_authorization_check`, which reads the balance again.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-246` - `is_authorized` reads `DataKey::Balance(addr)` for contract addresses.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2244` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:281-329` - host storage get and conversion path repeated by the duplicated reads.

## Evidence

The current diagnostic soroswap trace shows this path inside `applyLedger`: `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` overlaps apply by 2,245,135,102 ns across 10,172 calls, with 329,402,855 ns self-time. The same apply windows contain `get_contract_data` overlap of 831,315,290 ns across 101,916 calls, `storage get` overlap of 453,518,609 ns across 229,684 calls, `ScVal to Val` overlap of 726,501,061 ns across 521,065 calls, and `visit host object` overlap of 2,728,946,416 ns across 3,491,848 calls. The source-level duplicate read is specific and mechanical: for a present contract balance, `is_authorized` decodes `BalanceValue.authorized`, then the update function decodes the same `BalanceValue` again for `amount`.

This is distinct from the rejected general "cache enforcing storage Val conversions" hypothesis. It does not require a broad host conversion cache or rollback-aware object-handle reuse; it is a SAC-local control-flow change that can keep the already-decoded `BalanceValue` on the stack and update it directly.

## Anti-Evidence

The PoC must preserve missing-balance behavior exactly: missing contract balances use `!is_asset_auth_required(e)?` for authorization, while `receive_balance` creates a new balance with `clawback: is_asset_clawback_enabled(e)?` and `spend_balance` fails for positive spends. Budget accounting is also consensus-visible; if the optimization removes conversion and storage-access charges, it must either be accepted as a protocol-versioned lower-cost path or add compatibility charges for the skipped read. If soroswap endpoints are less contract-heavy than expected, the duplicated-read saving may fall below Medium despite the large SAC aggregate zones.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `ai-summary/fail/transactions/summary.md`; no numbered transactions or cross-subsystem fail/success records were present

### Trace Summary

The apply path reaches SAC transfers through `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge's protocol-dispatched `invoke_host_function`, `e2e_invoke::invoke_host_function`, and `Host::invoke_function` before `Frame::StellarAssetContract` dispatches to `StellarAssetContract::transfer`. In `transfer`, soroswap swaps use account-to-pair and pair-to-account SAC transfers, so each transfer has a contract-address endpoint whose balance is read once by `is_authorized` and then immediately read again by the spend/receive update path. The duplicate is more expensive than a single map lookup: for a present persistent balance, each `try_get_contract_data` performs `has_contract_data` and then `get_contract_data`, causing two `Storage::try_get_full`/`MeteredOrdMap` lookups plus a `ScVal` to host `BalanceValue` conversion. The generated soroswap footprint explicitly includes the user trustline entries and pair `Balance[pair]` contract-data keys, confirming this is in the benchmark's `closeLedger` apply path rather than setup-only work.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply helper serializes auth/resources/ledger entries and calls `rust_bridge::invoke_host_function` on the apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol-23+ Soroban transactions use `doParallelApply`, which constructs the parallel apply helper and invokes the host function during close-ledger apply.
- `src/rust/src/soroban_invoke.rs:7-24` — Rust bridge chooses the protocol-specific host module for the ledger protocol and dispatches invocation.
- `src/rust/src/soroban_proto_any.rs:310-354` — protocol-specific invocation catches panics and enters `invoke_host_function_or_maybe_panic`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — builds enforcing storage from the footprint, sets authorization and ledger context, then calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts the contract address/function/args and calls the contract, returning the result through `from_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `ContractExecutable::StellarAsset` enters `Frame::StellarAssetContract` and calls the built-in SAC implementation directly.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` checks amount/auth, extends SAC instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` first calls `is_authorized`; for contract addresses it then constructs the same `DataKey::Balance(addr)` and calls `try_get_contract_data` again before updating or creating `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-230` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check`; for contract addresses the no-auth helper re-reads the same balance before checking amount and writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-246` — `is_authorized` reads the contract balance and decodes `BalanceValue.authorized`; when missing it falls back to `!is_asset_auth_required(e)?`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` calls `has_contract_data` and, when present, `get_contract_data`; thus each present balance read includes both an existence lookup and a value lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2244` — `get_contract_data` converts the storage key, loads the ledger entry, and converts `ContractData.val` to a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267,421-429,693-720` — storage `get`/`has` both funnel through `try_get_full`, enforce footprint access, and do a metered ordered-map lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460` — ledger `ScVal` to host `Val` conversion is a traced and metered component of each `get_contract_data`.
- `src/simulation/ApplyLoad.cpp:3427-3505` — each soroswap swap transaction invokes the router's `swap_exact_tokens_for_tokens` and declares read-write footprint keys for user trustlines plus pair contract `Balance[pair]` entries for token-in and token-out.

### Findings

The inefficiency exists and is in the hot path. For a present contract balance, the current contract endpoint flow is:

1. `is_authorized(contract_addr)` builds `DataKey::Balance(contract_addr)`, calls `try_get_contract_data`, decodes `BalanceValue`, and uses only `authorized`.
2. `receive_balance(contract_addr, amount)` or `spend_balance_no_authorization_check(contract_addr, amount)` builds the same key again, calls `try_get_contract_data` again, decodes the same `BalanceValue` again, and uses `amount` plus the existing flags to write the updated balance.

The proposed fix is correctness-preserving if it is kept SAC-local and only fuses the contract-address update paths. Account endpoints must continue using `is_account_authorized` and classic trustline transfer logic. Contract missing-balance behavior must be preserved exactly: missing receive should authorize only when `!is_asset_auth_required(e)?`, then create `BalanceValue { amount: 0, authorized: true, clawback: is_asset_clawback_enabled(e)? }`; missing spend should still fail for positive amounts and succeed without writing for zero amounts. Existing deauthorized balances must continue returning `BalanceDeauthorizedError` before amount checks, while clawback must remain on the separate `spend_balance_no_authorization_check` path.

The impact projection meets the objective's Medium floor. The diagnostic trace cited in the hypothesis has 10,172 SAC transfer calls in apply windows. The soroswap benchmark footprint shows each swap's SAC transfers touch pair contract balance keys, so roughly one contract-balance authorization/update fusion opportunity exists per SAC transfer in the steady-state swap path. Removing one present-balance `try_get_contract_data` per contract endpoint removes about 10% of the traced `get_contract_data` calls, plus paired storage `has`/`get` lookups, `DataKey` conversions, `BalanceValue` decoding, and host-object visits. With eight configured dependent clusters, this aggregate removal is plausibly above the ~67 ms aggregate worker-time threshold needed for a 3% wall-time improvement on the ~279 ms soroswap baseline, while leaving the externally visible ledger changes and events unchanged.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, specifically `receive_balance`, `spend_balance`, and the contract branch of `spend_balance_no_authorization_check`.
- **Change description**: Add a SAC-private helper for contract addresses that reads `DataKey::Balance(addr)` once and returns the key plus `Option<BalanceValue>` or equivalent. In `receive_balance`, branch on `addr.to_sc_address()` first: keep the account path unchanged; in the contract path, read once, derive authorization from existing `balance.authorized` or `!is_asset_auth_required(e)?`, then update/create the same `BalanceValue` and call `write_contract_balance`. In `spend_balance`, similarly branch so the contract path reads once, checks authorization from the decoded or missing state, performs the existing amount checks, and writes only when the current implementation writes. Do not change `is_authorized` itself because the public `authorized` SAC function still needs the standalone read behavior.
- **Correctness check**: Existing SAC tests and transaction tests should cover public `balance`, `authorized`, `transfer`, `transfer_from`, `mint`, `burn`, `clawback`, and trustline SAC behavior (`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/test_stellar_asset_contract.rs:112-224`, `src/transactions/test/InvokeHostFunctionTests.cpp:192-375,8826-9007,9465`). Add focused Rust host tests if existing coverage does not directly assert missing contract balance, deauthorized contract balance, zero-amount spend, and auth-required receive semantics for contract addresses.
- **Benchmark focus**: Re-run the soroswap apply-load matrix and compare top-line apply time. The expected improvement should come from fewer `try_get_contract_data`/`get_contract_data`, `storage get`, `ScVal to Val`, and `visit host object` events inside `applyLedger`, with no change in final balances, TTL bumps, events, or authorization outcomes.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-02
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:169-175` adds a SAC-private helper that builds the contract balance key once and returns the decoded `BalanceValue` for a contract ID.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:287-297` centralizes the existing balance-deauthorized error so fused branches return the same error.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:300-337` changes `receive_balance` so contract-address recipients read `DataKey::Balance` once, derive authorization from the decoded balance or `!is_asset_auth_required`, then update/create the same `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:409-460` changes `spend_balance` so contract-address spenders read `DataKey::Balance` once, check authorization from that decoded value or the missing-balance fallback, then perform the existing amount checks and writes. `spend_balance_no_authorization_check` remains unchanged for clawback.
- `src/rust/soroban/p26/soroban-env-host/observations/26/*.json` updates 44 SAC observation snapshots after the intentional CPU-budget reduction from removing duplicate balance reads.

### Demonstration

The optimization fuses the SAC contract-address authorization and balance update read paths: present contract balances are decoded once and reused for both the `authorized` flag and `amount`. This removes one `read_contract_balance`/storage lookup/ScVal decode from each contract endpoint handled by `receive_balance` or authorized `spend_balance`, while preserving missing-balance auth-required behavior, deauthorized errors, insufficient-balance checks, clawback semantics, final writes, and public `authorized` behavior.

### Test Results

`make -j30` completed successfully with Tracy capture enabled. `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make -j30 check` completed successfully after regenerating intentional p26 SAC observation snapshots with `UPDATE_OBSERVATIONS=1`; the final normal run reported `All 2 tests passed` for stellar-core checks and p26 Rust host tests including `750 passed; 0 failed; 2 ignored; 1 filtered out`.
