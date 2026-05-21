# H002: Skip Auth Snapshots for Statically No-Auth SAC Frames

**Date**: 2026-05-21
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding authorization-manager frame work for high-volume SAC read functions that cannot require auth
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC functions that never call `require_auth` and never perform nested contract calls should not mutate the authorization call stack or snapshot every `AccountAuthorizationTracker`. They still need a normal host frame for current-contract identity, storage rollback, TTL extension rollback, and diagnostics, but the authorization manager should be allowed to return a no-op snapshot for statically no-auth built-ins such as `balance`, `authorized`, `decimals`, `name`, `symbol`, and `admin`.

## Mechanism

`Host::call_contract_fn` wraps every SAC invocation in `Frame::StellarAssetContract`, and `Host::push_context` always calls `AuthorizationManager::push_frame` before creating a rollback point. `push_frame` then pushes an auth stack frame and calls `snapshot`, which iterates all account and invoker-contract trackers even for SAC `balance`, whose body only extends TTL and reads balance state. A static no-auth frame policy for selected SAC functions would keep storage/event rollback intact while bypassing `push auth frame`, `push_tracker_frame`, and `snapshot auth` work for frames where authorization state is provably unchanged.

## Trigger

Run the current soroswap apply-load benchmark and count `Frame::StellarAssetContract` invocations by function symbol. The expected trigger is a high count of SAC `balance` calls: the current trace reports 13,513 `SAC balance` events, and every one currently pays the same authorization-frame setup path as auth-mutating SAC `transfer`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` unconditionally asks the authorization manager for a frame snapshot before pushing any context.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — `AuthorizationManager::push_frame` pushes auth call-stack/tracker frames for every `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1167-1220` — `snapshot` clones or snapshots authorization trackers on every frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-203,371-389` — SAC `balance`, `authorized`, `admin`, `decimals`, `name`, and `symbol` bodies contain no `require_auth` call.
- Tracy zones `push auth frame` and `snapshot auth` — 402,098,282 ns and 235,801,940 ns total inside `applyLedger` in the current soroswap trace; `SAC balance` has 13,513 apply-contained calls.

## Evidence

The current soroswap trace shows all auth-frame work is apply-contained: unwrap containment reported 54,270 `push auth frame` events totaling 402ms and 54,270 `snapshot auth` events totaling 236ms inside `applyLedger`. `SAC balance` alone accounts for 13,513 calls, roughly one quarter of all auth-frame pushes, yet its implementation (`contract.rs:185-192`) performs TTL extension and `read_balance` only. A no-auth frame policy limited to statically audited SAC functions could remove a proportional slice of auth snapshot work while leaving the surrounding `Host::with_frame` rollback semantics unchanged.

## Anti-Evidence

This is not the previously failed broad sparse-auth-tracking idea: it should be limited to functions whose bodies are audited not to call `require_auth`, not a new representation for all auth frames. The estimated gain is close to the Medium floor because only part of the 638ms aggregate auth setup is attributable to no-auth SAC calls, and the apply-load benchmark runs worker clusters in parallel. A reviewer should confirm the selected SAC function set cannot invoke authorization indirectly and should reject any implementation that skips the whole host frame or changes rollback behavior.
