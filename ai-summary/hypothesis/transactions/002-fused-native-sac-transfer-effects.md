# H002: Fuse Native SAC Transfer Balance Effects on Soroswap Swap Path

**Date**: 2026-05-23
**Subsystem**: transactions, Soroban SAC apply
**Severity**: Medium
**Impact**: soroswap apply-time reduction by collapsing generic SAC transfer storage/auth/event work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a soroswap swap transfers `token_in` from the user to the pair and `token_out` from the pair back to the user, the apply path should produce the same balance deltas, TTL bumps, authorization results, emitted SAC transfer events, resource accounting for the next protocol, and ledger changes as two generic `StellarAssetContract::transfer` calls. The efficient expected behavior is to execute the known SAC transfer effects through a native, typed balance-effect path rather than re-entering generic SAC contract logic for each transfer.

## Mechanism

`StellarAssetContract::transfer` currently performs generic work for every transfer: amount validation, `MuxedAddress` decoding, `require_auth`, instance/code TTL extension, sender balance spend, receiver balance receive, balance-entry authorization checks, persistent storage get/put, balance TTL extension, and event construction. The soroswap swap shape is narrower: the C++ generator declares exactly two SAC balance keys in the RW footprint (`Balance[pair]` for token-in and token-out) plus the two user trustlines, and the auth tree authorizes only the token-in user-to-pair transfer. A next-protocol fused native effect path could apply the two balance moves and required events in deterministic order using typed SAC balance/trustline helpers, amortizing duplicate contract-frame, storage-map, and conversion work without changing cluster scheduling or exceeding `NUM_CLUSTERS`.

## Trigger

Use the current soroswap apply-load scenario (`TX=2000`, `T=8`). Each generated transaction has a two-token path, RW footprint entries for user trustline(token-in), user trustline(token-out), SAC `Balance[pair]` for token-in, SAC `Balance[pair]` for token-out, and the pair instance (`src/simulation/ApplyLoad.cpp:3458-3475`). The auth tree authorizes the source account for `token_in.transfer(user, pair, amount)` (`src/simulation/ApplyLoad.cpp:3477-3496`).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` path currently exercised by soroswap
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — contract balance read and TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` — contract balance write plus TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` generic auth/read/write path
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-229` — `spend_balance` authorization wrapper
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-390` — enforcing storage get/put map path used by SAC balance updates
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ records modified ledger entries returned by the host and validates them against the RW footprint

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` was timestamp-filtered against `applyLedger` windows. The SAC transfer zones are apply descendants and overlap the measured window:

| zone | source | apply-overlap ns | count overlapping apply | critical-path bound at T=8 |
|------|--------|------------------|--------------------------|----------------------------|
| `SAC transfer` | `stellar_asset_contract/contract.rs:212` | 2,477,084,982 | 15,665 | ~309.6 ms / 6.9% of `applyLedger` |
| `storage get` | `soroban-env-host/src/storage.rs:329` | 672,084,842 | 321,802 | ~84.0 ms / 1.9% |
| `map lookup` + `map lookup indexed` | `metered_map.rs:173,330` | 1,223,514,982 | 1,327,079 | ~152.9 ms / 3.4% |
| `new map` | `metered_map.rs:148` | 461,915,256 | 181,114 | ~57.7 ms / 1.3% |
| `ScVal to Val` | `host/conversion.rs:436` | 1,144,488,055 | 800,217 | ~143.1 ms / 3.2% |

The `SAC transfer` overlap alone is a 6.9% critical-path upper bound after dividing worker aggregate time by T=8. The fused path only needs to remove roughly half of the generic SAC transfer envelope to clear the 3% Medium floor, and the storage/conversion/map zones show enough adjacent work to make that plausible if the implementation bypasses generic contract-data `Val` construction for the known balance/trustline updates.

## Anti-Evidence

This is not a proposal to skip authorization, events, TTL extension, or budget accounting. The fused path must preserve token-in source-account auth and token-out invoker-contract auth, exact event order, failure behavior, and rollback semantics. Existing accepted typed SAC balance and direct native-pair balance-read optimizations already cover some balance access, so the viable surface is the remaining generic transfer envelope and write-side effect construction; if implementation can only remove a small storage lookup or key conversion, it will fall below the Medium threshold.
