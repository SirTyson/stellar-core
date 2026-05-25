# H001: Direct SAC Transfer for Native Soroswap Pool Output Legs

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce native Soroswap swap apply time by bypassing generic SAC contract-call dispatch for output transfers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the protocol-gated native Soroswap pool `swap` path transfers `amount_0_out` or `amount_1_out` from the pool contract to the recipient, the apply path should produce exactly the same SAC ledger writes, auth outcome, TTL extension, and transfer event as `StellarAssetContract::transfer`. For the allowlisted pool Wasm and existing `Frame::NativeContract`, the host already knows the token contract IDs, the pool contract ID, the recipient address, and the output amounts, so it should not need to re-enter the generic `call_n_internal` contract-call pipeline just to execute this fixed SAC transfer shape.

## Mechanism

`call_native_soroswap_pool_swap` currently calls `soroswap_pool_invoke_sac_transfer` for each nonzero output leg, and that helper immediately re-enters `call_n_internal("transfer")`. The nested call pushes a full `Frame::StellarAssetContract`, runs reserved-name/reentry checks, performs generic argument conversion, snapshots auth/storage, and then dispatches to `StellarAssetContract::transfer`, even though this native pool path has a fixed caller (`pair_address`) and fixed SAC function. A narrow next-protocol helper that performs the SAC transfer body directly for this exact native-pool output leg should remove the nested contract-call dispatch and much of the per-frame/object overhead while preserving deterministic ledger effects.

## Trigger

Run the current soroswap apply-load scenario (`TX=2000, T=8`) on the accepted baseline from `ai-summary/CURRENT_STATE.md`. Each native pool swap with a nonzero output enters `Host::call_native_soroswap_pool_swap`, calls `soroswap_pool_invoke_sac_transfer`, then executes the generic SAC `transfer` frame. In the current Tracy trace, `SAC transfer` has 17,381 calls; unwrap containment shows 17,333 of them fall inside `applyLedger` windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native Soroswap `swap` output transfer and subsequent balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1482` — `soroswap_pool_invoke_sac_transfer` currently re-enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1864` — generic `call_n_internal` checks and frame dispatch that the fixed native output leg could avoid.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer semantics to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-425` — spend/receive balance paths that a direct helper would call or mirror.

## Evidence

- Current soroswap Tracy self-time: `SAC transfer` at `stellar_asset_contract/contract.rs:212` is 771,914,182 ns self over 17,381 calls, and unwrap containment attributes 2,910,469,315 ns of its event duration to `applyLedger`.
- Nearby nested-frame overhead is visible in the same apply-contained trace: `push context` is 112,372,510 ns self over 52,331 calls, `snapshot auth` is 184,674,877 ns self over 52,333 calls, `storage get` is 266,675,391 ns self, and `storage put` is 107,988,169 ns self. The direct helper would still do mandatory storage writes, but should remove the extra contract-frame and generic-dispatch shell around this fixed output transfer.
- The accepted stack already eliminated generic SAC `balance` calls on the native Soroswap pair path: current `SAC balance` is only 16 calls / 16,697 ns self, while `SAC transfer` remains a large apply-contained zone. This makes output transfer dispatch the next remaining SAC-specific native-pool boundary rather than a duplicate of the accepted direct-balance work.

## Anti-Evidence

- Prior failed SAC-transfer investigations show that small read-dedup and address/metadata caches are sub-threshold, and a previous returned-balance variant regressed. This hypothesis is only viable if it removes the nested `call_n_internal`/frame dispatch shell itself, not merely a duplicate storage probe inside SAC.
- The helper must preserve auth semantics for `from.require_auth()`, transfer event order/content, SAC TTL extension, and budget/resource accounting for the next protocol. A p26-preserving version is not viable; it must stay behind the existing post-p26 native Soroswap gate.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` row `001-native-pair-direct-sac-transfer.md` and the retained native-Soroswap-bypass meta-pattern
**Failed At**: reviewer

### Trace Summary

The current source does have the claimed execution path: native pool `swap` enters `call_native_soroswap_pool_swap`, calls `soroswap_pool_invoke_sac_transfer` for nonzero output legs, and that helper re-enters `call_n_internal("transfer")`, which pushes a `Frame::StellarAssetContract` and dispatches to `StellarAssetContract::transfer`. However, this same native pair/pool direct-SAC-transfer dispatch-bypass surface has already been reviewed and rejected in the Soroban fail summary: the prior review found the normalized impact around 2.0%, below the objective's 3% Medium threshold, and found that an auth frame remains required to preserve `from.require_auth()` semantics. The accepted native pool raw-instance-storage success intentionally left existing SAC transfer/balance, event emission, rollback, and storage persistence flow unchanged, so this hypothesis is a re-discovery of the remaining SAC-subcall fusion surface rather than a novel candidate.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-834` — `call_contract_fn` dispatches allowlisted Soroswap pool Wasm calls into `Frame::NativeContract`, but SAC executables still run through `Frame::StellarAssetContract` and `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native pool `swap` performs pool TTL extension, output validation, token/recipient checks, and calls `soroswap_pool_invoke_sac_transfer` for each nonzero output leg before reading balances directly.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1482` — `soroswap_pool_invoke_sac_transfer` converts the amount to `Val`, resolves the token contract id, creates symbol `transfer`, and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1864` — `call_n_internal` performs reserved-name and reentry checks, diagnostics, then calls `call_contract_fn`, producing the nested SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-594` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1371` — `with_frame` / `push_context` snapshot storage, events, and auth, and `AuthorizationManager::push_frame` records every contract frame in the auth call stack.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` checks nonnegative amount, calls `from.require_auth()`, extends current SAC instance/code TTL, updates balances, and emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-425` and `event.rs:47-64` — receive/spend balance and event semantics are not just dispatch shell; they include authorization checks, issuer classification, storage writes, and event selection that a direct helper would have to preserve or intentionally remeter.

### Why It Failed

This is not novel. `ai-summary/fail/soroban/summary.md` already records `001-native-pair-direct-sac-transfer.md` as "Native Pair Swap Direct SAC Transfer to eliminate redundant SAC frame dispatch for native pair swaps" and rejects it because the normalized impact is about 2.0%, below the 3% Medium objective threshold, with required auth-frame semantics and mandatory SAC TTL/event/storage work limiting the removable slice. The broader retained native-Soroswap-bypass meta-pattern also explicitly lists SAC subcall fusion as a previously rejected bypass variant unless a complete next-protocol native-contract semantic and metering specification is supplied. This hypothesis narrows the same mechanism to the currently-existing native pool output legs, but does not add new measurements or resolve the retained auth-frame, event-order, and metering blockers.

### Lesson Learned

For Soroswap native-pool residual work, "remove the SAC frame" must be checked against the existing direct-SAC-transfer fail before promotion. The visible `SAC transfer` zone includes mandatory balance, authorization, TTL, and event semantics, and the remaining frame/dispatch shell must be normalized by parallel Soroban worker count and ledger count; prior review found that slice below the objective's Medium floor.
