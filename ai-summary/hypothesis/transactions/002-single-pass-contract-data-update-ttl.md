# H002: Single-Pass Existing Contract-Data Update and TTL Bump

**Date**: 2026-05-01
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated storage-map access and immutable-map rebuilds for SAC balance writes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When SAC balance code writes an existing persistent contract-data entry, Core should preserve the current entry's ledger key, durability, extension fields, live-until ledger, final value, rent accounting, resource-limit behavior, and error ordering. A successful balance write followed by a TTL extension should produce the same final storage entry as today, but should not repeatedly enforce access, search the storage map, clone the same ledger entry, and rebuild the immutable storage map for the same key.

## Mechanism

`write_contract_balance` calls `put_contract_data` and then `extend_contract_data_ttl` for the same `DataKey::Balance`. For an existing persistent entry, `put_contract_data_into_ledger` first calls `Storage::has`, then `Storage::get_with_live_until_ledger`, then `Storage::put`; the follow-up TTL extension calls back into storage to read the same key again and may perform another `MeteredOrdMap::insert`. A host/storage helper that modifies an existing contract-data value and applies the TTL extension in one validated pass could replace the `has` plus `get` plus `put` plus `extend_ttl` sequence with one access check and one final map update for the common SAC balance-write case.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md`. The issue triggers during contract-address SAC balance updates, especially `SAC transfer`, where `spend_balance` and `receive_balance` each call `write_contract_balance` after loading and modifying a `BalanceValue`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-96` - `write_contract_balance` performs `put_contract_data` and then extends TTL for the same balance key.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` - existing-entry `put_contract_data_into_ledger` performs `has`, `get_with_live_until_ledger`, clones/modifies the ledger entry, and then `put`s it back.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` - `put_opt_helper` enforces access and inserts into the storage map.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-573` - TTL extension rereads the entry and can insert another updated map value.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2200,2293-2317` - host dispatch entry points for contract-data writes and TTL extension.

## Evidence

The storage mutation work is inside the current apply path. Timestamp-filtering the current soroswap Tracy trace into `applyLedger` shows `storage put` overlap of 84,640,083 ns across 25,502 calls, `storage has` overlap of 43,790,017 ns across 20,594 calls, `storage get` overlap of 453,518,609 ns across 229,684 calls, `map lookup` overlap of 1,023,076,910 ns across 965,090 calls, and `new map` overlap of 378,707,696 ns across 128,112 calls. The source confirms the write path is not a single mutation: for an existing contract-data entry, it asks whether the key exists, fetches the same key to recover the live-until ledger, writes the modified entry, and then re-enters storage for TTL extension.

This is not the previously rejected bulk-build map-construction hypothesis. It targets runtime mutation of an already-built enforcing `Storage` during SAC balance writes, not initial footprint/storage map construction in `e2e_invoke.rs`. It is also narrower than the rejected conversion-cache hypothesis because it can be implemented as an explicit storage update API with synchronous invalidation and rollback through the existing storage map, rather than as an independent decoded-value cache.

## Anti-Evidence

The current `put` then `extend_ttl` order exposes distinct failure points; a combined helper must preserve any observable error order, including invalid key type, read-only footprint, missing TTL, expired entry, and temporary-entry max-TTL checks. Budget charges may decrease if duplicate `has`/`get`/lookup work is removed, so the PoC must either intentionally update protocol-metered costs or replay compatibility charges where required. If most `new map` and `map lookup` time in the current trace comes from code paths already optimized or rejected elsewhere, the SAC-specific mutation fraction may not clear the 3% Medium floor.
