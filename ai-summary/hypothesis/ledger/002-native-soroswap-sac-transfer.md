# H002: Direct native SAC transfer for allowlisted Soroswap swap legs

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing generic SAC transfer overhead from native swap legs
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the protocol-gated native Soroswap path transfers SAC balances for the exact apply-load swap shape, the host should update the same source and destination balances, extend the same TTLs, require the same authorization, emit the same SAC transfer event, and preserve rollback boundaries. It should do this without routing through the generic `call_n_internal("transfer")` path when the token instance is known to be `StellarAsset` and the endpoints match the allowlisted swap leg.

## Mechanism

The native pool swap currently delegates each output transfer back through `soroswap_pool_invoke_sac_transfer`, which constructs a symbol and performs a nested generic contract call to SAC `transfer`. That lands in the broad SAC transfer helper, which redoes generic address conversion, authorization checks, storage reads/writes, TTL extension, event construction, and frame dispatch for a transfer shape whose token, source, destination, and current-contract relationship are already constrained by the native Soroswap path. A dedicated native transfer primitive can keep the semantic frame/rollback/auth requirements but avoid the generic invocation and repeated helper layering for the two hot swap legs.

## Trigger

Run the current soroswap apply-load Tracy trace and filter to SAC transfer descendants inside `applyLedger`. The diagnostic trace shows `SAC transfer` at `stellar_asset_contract/contract.rs:212` has 16,738 in-apply calls with 668.821 ms self-time and 2.602 s total worker time; the native pool path calls `soroswap_pool_invoke_sac_transfer` for nonzero output legs, while the router Wasm supplies the input transfer leg.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1158-1173` — native pool swap invokes SAC transfer for output amounts.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1346` — `soroswap_pool_invoke_sac_transfer` goes through `call_n_internal` with a constructed `transfer` symbol.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC transfer helper currently used by both swap legs.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:235-299` — balance write path that clones and rewrites contract-data entries.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-428` — receive/spend balance paths for contract and classic endpoints.

## Evidence

`SAC transfer` remains one of the largest measured descendants of `applyLedger` after the accepted native pool optimizations. The current native pool code already validates the pool Wasm hash, fixed storage layout, token addresses, output amounts, and pair address before invoking SAC transfer, and `soroswap_pool_read_sac_contract_balance` demonstrates a precedent for a narrower SAC fast path that first verifies the token instance executable is `StellarAsset`.

## Anti-Evidence

A prior "specialize SAC transfer call boundary" investigation was rejected because the SAC frame semantics are not removable. This hypothesis is narrower but riskier: it must not merely skip the frame; it must either construct an equivalent native SAC frame or prove the enclosing native Soroswap frame plus explicit auth/event/storage handling is semantically identical for the allowlisted transfer. It may fall below Medium if only the output transfer leg is optimized without a matching router/input-transfer path.
