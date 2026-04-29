# H002: Specialize SAC Transfer Address Handling to Reduce Hot Object Visits

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated host-object lookups in SAC transfer-heavy swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Stellar Asset Contract transfer in soroswap should authenticate the sender, update the same account/trustline/contract balances, extend the same TTLs, and emit identical transfer/mint/burn events. The implementation should avoid repeatedly re-reading the same `AddressObject` from the host object table when a transfer already has a validated `Address` value in hand.

## Mechanism

The SAC transfer path passes `Address` wrappers through `transfer`, `spend_balance`, `receive_balance`, and event helpers. Those helpers repeatedly call `Address::to_sc_address`, `Host::compare`, `MuxedAddress::address`, `MuxedAddress::id`, and contract-data key conversion, each of which can visit immutable host objects. In the current soroswap trace, `visit host object` at `soroban-env-host/src/host_object.rs:468` accounts for 1,225,982,654 ns self time and 2,372,464,656 ns total time across 2,689,616 calls, all inside `applyLedger`; `SAC transfer` itself is also fully inside `applyLedger` and totals 2,406,468,508 ns across 6,656 calls.

A targeted SAC refactor could decode `from`, `to`, and optional muxed-id once at the top of `StellarAssetContract::transfer`, pass borrowed/predecoded `ScAddress` data into balance and event helpers, and still charge the same logical conversion/visit budget where protocol-visible metering requires it. Because host objects are immutable for the host lifetime, reusing decoded address data within a single SAC call should not alter ledger state, event order, or authorization semantics.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and profile `applyLedger`. The issue is triggered by swaps that perform multiple SAC transfers and event emissions, causing repeated address object reads for the same `from` and `to` values inside a single SAC transfer call.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` obtains `to`, authenticates `from`, calls balance helpers, then event helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` converts `Address` to `ScAddress`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` converts/clones address and builds balance keys.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-190` — `spend_balance_no_authorization_check` converts/clones address and builds balance keys.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-62` — event selection compares `from`/`to` and checks issuer status.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:373-383` — `Address::to_sc_address` and `require_auth` are wrapper methods over host object access.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-489` — `visit_obj_untyped` charges and indexes the host object table for every visit.

## Evidence

The current soroswap Tracy trace is `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. `applyLedger` spans 5,774,332,215 ns over 69 windows. All 2,689,616 `visit host object` events and all 6,656 `SAC transfer` events are fully contained in those `applyLedger` windows. Self-time export reports `visit host object,soroban-env-host/src/host_object.rs,468,1225982654,...,2689616` and `SAC transfer,soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs,212,196111660,...,6656`, while total-time export shows `SAC transfer` at 2,406,468,508 ns, indicating most SAC transfer cost is in descendants such as object visits, comparisons, storage accesses, and event construction.

## Anti-Evidence

Some object visits are protocol-metered via `ContractCostType::VisitObject`; eliminating the charge would change near-limit transaction behavior. The optimization must therefore separate performance work from metering semantics, either by preserving equivalent budget charges or by limiting the change to internal unmetered repeated lookups that are demonstrably not part of the guest-visible cost model. The hot `visit host object` zone is global across the host, so a PoC must show that the SAC transfer refactor removes enough visits on soroswap specifically rather than merely moving cost into other conversion paths.
