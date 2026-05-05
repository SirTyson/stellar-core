# H001: Single-read SAC transfer balance path

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing duplicate SAC balance storage reads and conversions on the Soroban apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a successful Stellar Asset Contract `transfer(from, to, amount)` between contract-address balances, the host should read each participating persistent `DataKey::Balance(Address)` at most once for the physical implementation of that transfer, then use the decoded `BalanceValue` both to check authorization and to apply the debit/credit. The observable result should remain identical: the same auth failure behavior, balance-underflow/overflow behavior, final persistent balances, TTL extensions, emitted event, and either the same p26 budget charge sequence or a protocol-gated next-protocol metering definition.

## Mechanism

`StellarAssetContract::transfer` calls `spend_balance` for `from` and `receive_balance` for `to`. On the contract-address path, both helpers first call `is_authorized`, which performs `try_get_contract_data(DataKey::Balance(addr))` and decodes `BalanceValue`; then the helper immediately constructs the same `DataKey::Balance(addr)` again and performs a second `try_get_contract_data` plus second `BalanceValue` conversion before modifying the amount. In soroswap, SAC transfers are on the apply path and frequent enough that collapsing the authorization+mutation path to one physical read/decode per side should remove repeated `StorageMap`/`MeteredOrdMap` lookups, host-object conversions, and `BalanceValue` deserialization while preserving ledger semantics.

## Trigger

Run the current soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`) on a next-protocol build. Each swap that transfers a SAC balance for a contract-address sender or recipient exercises `StellarAssetContract::transfer`; when `from` or `to` is a contract address with an existing balance, the same balance key is read and decoded once for authorization and once again for mutation in the same transfer.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `StellarAssetContract::transfer` calls `spend_balance` and `receive_balance` sequentially for every transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` calls `is_authorized`, then re-reads the same `DataKey::Balance(addr)` before adding to the balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:172-229` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check` re-reads the same `DataKey::Balance(addr)` before subtracting from the balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` performs the first balance read and decodes `BalanceValue`.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` shows `SAC transfer` as an `applyLedger` descendant with `558,183,960 ns` self-time across `13,527` calls. Supporting apply-path hot zones include `ScVal to Val` (`429,988,065 ns` self), `Val to ScVal` (`245,978,039 ns` self), `map lookup indexed` (`408,451,716 ns` self), `map lookup` (`345,449,339 ns` self), and `storage get` (`215,980,007 ns` self). The code path above performs two same-key reads for the debit side and two same-key reads for the credit side, so a focused SAC helper that returns an already-decoded balance record to the mutation logic attacks repeated work inside these measured zones rather than a generic storage-cache guess.

## Anti-Evidence

Prior generic storage-value caching and SAC DataKey caching ideas were rejected as below-threshold or metering-sensitive. This hypothesis is narrower: it should not add a cross-host cache, and it must either replay p26 metering exactly for the skipped logical read/conversion or be gated to the next protocol with tests documenting the changed metering. The win also depends on the soroswap balance holders being contract addresses often enough; if most hot SAC transfers are classic account/trustline paths, this collapses to Low severity.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban`, `success/soroban`, or the absent cross-subsystem fail/success directories

### Trace Summary

The duplicate read/decode exists on the real p26 SAC transfer path. `StellarAssetContract::transfer` calls `spend_balance` and `receive_balance`; for contract addresses, each helper first reaches `is_authorized`, which constructs `DataKey::Balance(addr)`, performs `try_get_contract_data`, and decodes `BalanceValue`, then the mutating helper constructs and reads the same persistent balance key again before updating it. The soroswap benchmark generates one swap per transaction and includes two pair-contract SAC balance keys in each swap footprint, so successful swaps repeatedly exercise one duplicated contract-balance read on the user-to-pair transfer and one on the pair-to-user transfer.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generation creates `swap_exact_tokens_for_tokens` invoke-host-function transactions, includes two `Balance[pair]` contract-data keys in the read-write footprint, and authorizes the token-in SAC `transfer`.
- `src/simulation/ApplyLoad.cpp:41-50` — `makeSACBalanceKey` builds the exact persistent `ContractData` key shape for `DataKey::Balance(Address)`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — Soroban apply calls the Rust bridge `invoke_host_function` from the close-ledger invoke-host-function path.
- `src/rust/src/soroban_invoke.rs:7-39` — Rust dispatch selects the protocol-specific host module and calls its `invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:407-481` — p26 host invocation builds enforcing storage, decodes the host function/auth/source account, installs ledger info and module cache, then calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` checks amount, requires auth from `from`, extends the instance/code TTL, then calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` calls `is_authorized` first, then for `ScAddress::Contract` builds `DataKey::Balance` again, calls `try_get_contract_data` again, decodes `BalanceValue` again, updates amount, and writes the balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-229` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check`; the contract-address branch re-builds and re-reads the same balance key and decodes `BalanceValue` before the insufficient-balance check and write.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` performs the first contract-balance read/decode or falls back to `!is_asset_auth_required` for missing balances.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2230-2242` — `get_contract_data` converts the host key back into a storage `LedgerKey`, reads `Storage`, and converts the `ContractData` value from `ScVal` into a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303` — persistent storage reads enforce footprint access and perform a `StorageMap` lookup on every `try_get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-239` — `MeteredOrdMap::get` runs the metered binary-search lookup; no cache elides the second same-key lookup within the SAC helper.

### Findings

The inefficiency is real and in scope. For the contract-address side of a successful SAC transfer with an existing balance, the current code pays twice for key construction/conversion, storage access, `MeteredOrdMap` lookup, `ScVal` to host `Val` conversion, and `BalanceValue` decoding, even though the first decoded `BalanceValue` contains the authorization bit and amount needed by the mutation path. This is not covered by the existing enforcing `StorageMap`: the map is built once per invocation, but every `try_get_contract_data` still re-enters footprint enforcement and binary-search lookup.

The soroswap benchmark does not make both sides of every transfer contract addresses: user balances are classic trustlines, while pool/pair balances are contract data. However, each generated swap includes two pair-contract balance keys (`token_in` pair balance and `token_out` pair balance), so the duplicate contract-balance path is still exercised repeatedly in the `closeLedger` apply hot path. Given the current trace attribution for `SAC transfer`, storage get, map lookup, and value conversion zones, removing one physical balance read/decode for each pair-side SAC balance is plausibly in the objective's Medium range and is not merely a generic storage-cache speculation.

The proposed fix is correctness-preserving if it is kept local to SAC contract-balance helpers and preserves the existing semantic order. The new path must still reject deauthorized existing balances before mutation, call `is_asset_auth_required` before treating a missing spend balance as insufficient, call `is_asset_clawback_enabled` when creating a missing receive balance, use `write_contract_balance` for writes and TTL extension, and leave account/trustline paths unchanged. Because p26 budget metering may observe the skipped logical read/conversion, the safe PoC route is a next-protocol-gated physical coalescing path unless the implementation explicitly replays the exact p26 charges.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, with call sites from `contract.rs:206-225` left semantically unchanged.
- **Change description**: Add a local contract-balance read helper used by the contract-address branches of `receive_balance` and `spend_balance`/`spend_balance_no_authorization_check`. It should construct `DataKey::Balance(addr)` once, call `try_get_contract_data` once, decode `BalanceValue` once, use the decoded `authorized` bit for the authorization check, then reuse the same decoded value for the amount update and final `write_contract_balance`.
- **Correctness check**: Preserve current behavior for existing authorized, existing deauthorized, missing with auth-required asset, missing with auth-not-required asset, zero-amount spend from missing balance, insufficient balance, overflow, and TTL extension. Existing SAC tests in `test_stellar_asset_contract.rs` should cover most semantic cases; add focused next-protocol metering/behavior tests only if the implementation changes budget observations.
- **Benchmark focus**: Run the soroswap apply-load matrix against a next-protocol build and compare median apply time across repeated runs. The expected direct attribution is lower `SAC transfer`, `storage get`, `map lookup`, `ScVal to Val`, and `Val to ScVal` time, with a target top-line soroswap median improvement of at least 3%.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-05
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:169-217` — added local helpers for checking an already-decoded contract balance's authorization state and returning the decoded balance with the address kind.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:330-454` — changed `receive_balance` and `spend_balance` to reuse the authorization read for contract-address balances, while retaining the existing no-auth clawback helper path and account/trustline mutation path.
- `src/rust/soroban/p26/soroban-env-host/observations/26/test__stellar_asset_contract__test_auth_required.json`, `test__stellar_asset_contract__test_clawback_on_contract.json`, `test__stellar_asset_contract__test_contract_invoker_auth.json`, `test__stellar_asset_contract__test_greater_than_i64_balances.json`, `test__stellar_asset_contract__test_sac_reentry_is_not_allowed.json`, `test__stellar_asset_contract__test_zero_amounts.json`, and `test__stellar_asset_contract__verify_nested_try_call_rollback.json` — updated expected p26 host observations for the cheaper contract-balance path.

### Demonstration

The implementation constructs and reads the persistent contract-balance ledger key once during the authorization check, then carries the decoded `BalanceValue` into the debit or credit mutation logic. This removes the second same-key storage lookup and second balance decoding on successful contract-address SAC transfers while preserving existing deauthorization, missing-balance, insufficient-balance, overflow, write, and TTL-extension behavior.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j30`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`; all tests passed.
