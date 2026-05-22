# H001: Direct SAC balance reads for native Soroswap pair swap

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing read-only SAC `balance` contract frames from the native pair-swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the next-protocol native Soroswap pair `swap` implementation needs the pair contract's current token balances, it should observe the same SAC instance TTL extension, balance contract-data TTL extension, balance value, missing-balance-as-zero behavior, and error behavior as calling the token SAC contract's `balance(pair_address)`. Non-SAC token contracts, non-contract owner addresses, released p26 ledgers, and any non-exact native pair shape should continue through the existing `call_n_internal(..., "balance", ...)` path.

## Mechanism

The accepted native pair `swap` still calls `soroswap_pool_invoke_sac_balance` twice, and that helper re-enters the SAC built-in through `call_n_internal`, pushing a `Frame::StellarAssetContract`, extending SAC instance/code TTL, building the balance key from the current SAC frame, reading the contract-data balance, extending that balance TTL, and returning an `i128`. For the native pair's exact internal use, the token address is already known to be a SAC contract address and the owner is always the current pair contract address, so a protocol-gated helper can construct the SAC contract-data key with `storage_key_for_address(ScAddress::Contract(token_id), Balance(pair_address), Persistent)`, extend the SAC instance TTL directly, read the typed `BalanceValue`, extend the balance TTL, and return the amount without pushing a read-only SAC frame.

## Trigger

Run the current accepted soroswap benchmark (`soroswap, TX=2000, T=8`). Every successful native pair `swap` reaches `call_native_soroswap_pool_swap`, executes the output SAC `transfer`, then calls `soroswap_pool_invoke_sac_balance(token_0, pair)` and `soroswap_pool_invoke_sac_balance(token_1, pair)` to infer the input amounts.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1172-1173` at accepted p26 commit `03d78248` — two SAC `balance` calls after the output transfer in native pair `swap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1346-1359` at accepted p26 commit `03d78248` — `soroswap_pool_invoke_sac_balance` currently enters SAC through `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-193` — SAC `balance` side effects: extend current SAC instance/code TTL, then `read_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-57,150-177,191-201` — typed contract-balance key/value read and balance TTL extension logic that can be reused for an exact SAC contract-owner balance read.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:131-154` — `storage_key_for_address` can construct a contract-data ledger key for a specified SAC contract id instead of relying on the current frame's contract id.

## Evidence

The current diagnostic trace from `CURRENT_STATE.md` shows `SAC balance` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:187` with 416.970093ms total across 14,894 calls; unwrap containment confirms 14,830 calls and 415.920127ms are inside `applyLedger`. Its self-time is only 35.769156ms, which means most cost is child frame/storage/TTL/conversion work that the native pair currently pays solely to read two contract balances.

This path differs from the rejected SAC-transfer specialization: SAC `balance` has no authorization requirement, no event emission, no balance mutation, and no user-visible return metadata beyond the `i128` amount. The mandatory side effects are narrow enough to reproduce directly under the same next-protocol/hash/shape gates already used by native pair `swap`.

## Anti-Evidence

The helper must preserve rollback semantics if a TTL extension or storage read fails; doing the read outside a SAC frame must either use an equivalent rollback scope or fall back before mutating TTLs. It must also preserve metering expectations for any protocol where budget totals are fixed; the safest shape is next-protocol-only, matching the accepted Soroswap native paths. The full 416ms `SAC balance` total is an upper bound because the direct path still performs SAC instance TTL extension, balance key construction, storage lookup, typed value validation, and balance TTL extension.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The accepted native pair `swap` path is next-protocol/hash/shape gated, but it still calls `soroswap_pool_invoke_sac_balance` twice after the output transfer, and that helper re-enters the token contract through `call_n_internal`. For SAC tokens, `call_contract_fn` pushes a `Frame::StellarAssetContract`; the SAC `balance` body then only extends the SAC instance TTL, reads a persistent `Balance(Address(pair))` contract-data entry, extends that balance TTL when present, and returns `0` for a missing balance. Those side effects can be reproduced under the existing native pair frame by using an explicit SAC contract id in the ledger key and falling back to `call_n_internal` for non-SAC token instances or non-exact shapes.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:780-833` — `call_contract_fn` retrieves the callee instance and pushes `Frame::StellarAssetContract` for SAC calls before dispatching the built-in.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1359` — native pair `swap` calls `soroswap_pool_invoke_sac_balance` twice; that helper builds a `balance` symbol, invokes the token through `call_n_internal`, then converts the returned `Val` to `i128`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-192` — SAC `balance` has no auth, mutation, or event behavior; its observable storage side effects are SAC instance TTL extension and the delegated balance read.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-56,150-177,191-201` — contract-balance key construction, typed `BalanceValue` parsing, missing-as-zero behavior, and balance TTL extension are narrow and reusable for a direct SAC contract-owner balance read.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:131-154` — `storage_key_for_address` can build a `LedgerKey::ContractData` for an explicit `ScAddress::Contract(token_id)` rather than the current frame's contract id.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-280` — instance TTL and code TTL helpers show SAC code TTL extension is a no-op once the instance executable is known to be `StellarAsset`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:324-390,533-680` — direct reads and TTL extensions still enforce footprint/access rules and surface missing/out-of-footprint errors through the same storage layer.

### Findings

The inefficiency exists and is in the objective hot path. Each successful native pair swap performs two read-only SAC balance subcalls, and the trace reports 14,830 in-apply SAC balance executions. The current path pays for internal-call dispatch, function-symbol handling, SAC frame push/pop and auth-frame bookkeeping, callee instance lookup, current-contract-id key derivation, object/value conversions around the return, plus the mandatory storage and TTL work.

The proposed fix is correctness-plausible if it is strictly next-protocol and SAC-instance gated. A direct helper must first confirm the token contract instance is `ContractExecutable::StellarAsset`; otherwise it must use the existing `call_n_internal` path so Wasm token contracts or malformed state keep their current behavior. For confirmed SAC tokens, the helper can extend the SAC instance TTL, construct `Balance(pair_address)` as typed `ScVal`, read the `BalanceValue` from storage using `storage_key_for_address(ScAddress::Contract(token_id), ..., Persistent)`, extend the balance TTL only when the entry exists, return `0` when missing, and propagate storage/value errors.

Rollback semantics are preserved by the enclosing `Frame::NativeContract` around `call_native_soroswap_pool_swap`: any error after direct TTL/storage operations rolls back the host storage map and events to the pair-frame rollback point. SAC `balance` has no authorization requirement and emits no events, so skipping the SAC subframe does not skip required auth or event behavior. The full `SAC balance` Tracy total is an upper bound because storage reads and TTL extensions remain, but removing two read-only subframes and redundant instance/key/value scaffolding per swap is substantial enough to clear the optimize-soroswap Medium review floor as a PoC candidate.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` for `soroswap_pool_invoke_sac_balance`, plus `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` if private typed balance-key/value helpers need to be exposed or wrapped.
- **Change description**: Add a next-protocol direct SAC balance helper used only by the native Soroswap pair `swap` path. Gate on confirmed `ContractExecutable::StellarAsset` for the token contract; fall back to `call_n_internal(..., "balance", ...)` for every non-SAC or non-exact case. Reproduce SAC `balance` storage behavior directly: extend the SAC instance TTL, read the pair contract balance with an explicit token contract id, extend balance TTL on hit, parse `BalanceValue`, return `amount`, and return `0` on missing entry.
- **Correctness check**: Existing Soroban host tests should remain unchanged. Add focused equivalence coverage for SAC token pair balances covering present balance, missing balance, malformed balance value, out-of-footprint balance key, out-of-footprint SAC instance, non-SAC token fallback, and rollback after a later pair-swap error.
- **Benchmark focus**: Compare three non-Tracy `scripts/run_apply_load_matrix.py` runs against the current accepted baseline, with `soroswap, TX=2000, T=8` median apply time as the headline metric. The expected signal is fewer SAC balance subframes/internal calls and reduced storage/key/value scaffolding while preserving the mandatory balance storage lookup and TTL extension work.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-22
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract.rs:14-16` exports the direct contract-owner balance helper and SAC instance TTL constants for native host use.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:15-22,180-200` adds `read_contract_balance_for_contract_owner`, which constructs a persistent SAC balance key for an explicit SAC contract id, reads/parses the existing typed `BalanceValue`, extends the balance TTL on hit, and returns `0` for missing balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1-19,1354-1387` routes native Soroswap pair balance reads through the direct helper after confirming the token instance is `ContractExecutable::StellarAsset`; non-contract owners and non-SAC tokens fall back to the existing `call_n_internal(..., "balance", ...)` path.

### Demonstration

The native Soroswap pair `swap` path now avoids pushing two read-only `Frame::StellarAssetContract` SAC `balance` subframes when both pair tokens are SAC contracts. It preserves the required SAC storage side effects by extending the SAC instance TTL, reading the same persistent `Balance(pair)` entry under the token contract id, extending the balance TTL when present, and using the same missing-as-zero and typed-value parsing behavior.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j $(nproc)`. Full regression verification completed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j $(nproc) check`: p26 Rust host tests passed (`751 passed; 0 failed` plus integration/doc tests), `test/selftest-nopg` and `test/check-nondet` passed, and the command exited successfully.
