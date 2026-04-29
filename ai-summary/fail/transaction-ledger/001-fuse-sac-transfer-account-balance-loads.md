# H001: Fuse SAC Account Transfer Authorization and Balance Loads

**Date**: 2026-04-29
**Subsystem**: transaction-ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing duplicate SAC storage reads and conversions on the parallel apply critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For soroswap-shaped successful SAC `transfer` calls between account addresses, the host should read each affected trustline/account entry once, verify authorization and balance bounds from that entry, apply the debit or credit exactly once, and emit the same ledger writes, events, errors, and budget behavior required by the active protocol. The observable order of source-side checks before destination-side checks must remain deterministic and must preserve existing failure precedence.

## Mechanism

`stellar_asset_contract::transfer` currently funnels source and destination updates through separate generic helpers. For credit assets, `spend_balance` first calls `is_authorized`, which calls `read_asset` and loads the source trustline flags, then `spend_balance_no_authorization_check` calls `transfer_classic_balance`, which calls `read_asset` again and loads the same source trustline again for the balance update; `receive_balance` repeats the same pattern for the destination. A SAC-specific account/account transfer helper could read the asset once and, for each side, combine authorization and balance mutation from one storage entry, removing repeated `get_contract_data`, `storage get`, `MeteredOrdMap` lookup, host-object conversion, and `read_asset` work while writing the same source and destination entries in the same order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the trace recorded in `ai-summary/CURRENT_STATE.md`. The long `applyLedger` windows in `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy` contain thousands of SAC transfers; each transfer between account addresses exercises the duplicated authorization-plus-update helper path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - `transfer` calls `spend_balance` and `receive_balance` independently.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` - `receive_balance` checks authorization, then performs a separate balance read/update.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-229` - `spend_balance` checks authorization, then calls the no-authorization update path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:376-430` - `transfer_classic_balance` and `get_classic_balance` call `read_asset` for every generic balance operation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:583-628` - `transfer_trustline_balance` reloads and rewrites the trustline after authorization already loaded its flags.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:786-842` - `is_account_authorized`/`is_trustline_authorized` load the same trustline flags that transfer later reloads.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` - `read_asset` decodes instance `AssetInfo` every time the generic helpers ask for the SAC asset.

## Evidence

The current soroswap Tracy trace shows `SAC transfer` at `contract.rs:212` inside the long `applyLedger` windows with an average per-window critical worker share of 68.842 ms (max thread) and 480.901 ms aggregate across the eight workers. Descendant zones that this fused path targets are also inside those same `applyLedger` windows: `storage get` averages 24.450 ms critical-worker time, `get_contract_data` 28.736 ms, `map lookup` 37.798 ms, and `visit host object` 68.151 ms. The code structure explains why these costs repeat: the source and destination paths separately read SAC asset info and separately load trustline/account entries for authorization and mutation.

Because the benchmark is configured for eight clusters, the estimate uses max per-worker time within each long `applyLedger` window rather than aggregate worker time. Removing even one duplicated storage load plus one duplicated asset-info decode per side should plausibly save a Medium-sized fraction of the current ~300 ms non-Tracy soroswap median, while preserving deterministic single-threaded execution inside each transaction.

## Anti-Evidence

SAC helper calls are metered by their components, so simply skipping reads may change visible budget counters; a production implementation probably needs a protocol gate or explicit equivalent budget charges. The fused helper must exactly preserve current failure ordering for source authorization, source balance underflow, destination authorization, destination overflow, issuer special cases, native assets, and account-creation behavior. The win is strongest for the soroswap account/trustline-heavy path; contract-address balance paths and native-asset paths may need to remain on the generic helpers.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### What's Wrong

The duplicate read pattern exists, but the hypothesis's account/account hot-path model does not match the soroswap benchmark. `ApplyLoad::generateSoroswapSwaps` builds authorized sub-invocations of `token_in.transfer(user, pair, amount)`, where `user` is an account address and `pair` is a contract address; its footprint contains user trustline keys plus SAC `Balance[pair]` contract-data keys, not two account/trustline sides. The liquidity setup similarly invokes `token_a.transfer(root, pair, amount)` and `token_b.transfer(root, pair, amount)`, with the issuer side avoiding a trustline and the pair side using contract balance storage.

The SAC helper trace confirms repeated work, but not in the exact account/account form claimed. `transfer` calls `spend_balance` then `receive_balance`; account sides read asset info and load the trustline once for authorization and again for mutation, while contract sides call `try_get_contract_data`, which itself performs `has_contract_data` then `get_contract_data` for existing balances, before the update path reads again. In enforcing mode these are repeated `StorageMap` / `Footprint` map probes and host-value conversions over already-loaded footprint entries, not repeated live-ledger or bucket reads. The severity estimate also attributes broad inclusive `storage get`, `get_contract_data`, `map lookup`, and `visit host object` timing to the removable duplicate subset without isolating the mixed account/contract transfer shape, so the Medium projection is not established.

### Alternative Angle

Refine this as a mixed-address SAC transfer optimization rather than an account/account helper. The hot shape to target is account-to-contract and contract-to-account transfers: carry the decoded `Asset` or `AssetInfo` through the source update, destination update, and issuer/event classification; for account sides, combine trustline flag validation and balance mutation from one loaded trustline entry; for contract sides, replace paired `has`+`get` and duplicated `try_get_contract_data` calls with one balance lookup that preserves or protocol-gates the same budget behavior. A refined hypothesis needs narrow counters or Tracy scopes for only the duplicate SAC balance reads inside `SAC transfer`, after dividing aggregate worker time by the configured cluster count and after accounting for already-accepted storage-map lookup improvements.

### Additional Code Paths

- `src/simulation/ApplyLoad.cpp:3382-3492` — swap generation authorizes `token_in.transfer(user, pair, amount)` and declares user trustline plus `Balance[pair]` contract-data footprint keys.
- `src/simulation/ApplyLoad.cpp:3214-3338` — liquidity setup invokes token transfers from the issuer/root account to the pair contract, not account/account transfers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` runs source debit before destination credit, so a fused helper must preserve this failure order.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,156-229,232-245` — account and contract balance paths both perform authorization before a separate mutation lookup.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:376-404,583-628,786-842` — account/trustline credit-asset paths reread asset info and trustline entries between authorization and balance mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242` — persistent `try_get_contract_data` is implemented as `has_contract_data` plus `get_contract_data`, so existing contract balances incur multiple storage probes before mutation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303,421-429` — storage reads in enforcing mode validate the key, enforce footprint access, and probe the in-memory `StorageMap`; repeated reads are real host-side work but must preserve metering semantics.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62` — event issuer classification rereads SAC asset info after balance mutation, which may be a separate refinable asset-info carry-through path.
