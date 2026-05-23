# H002: Protocol-Gated Direct SAC Transfer Call Path

**Date**: 2026-05-23
**Subsystem**: soroban, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by specializing Stellar Asset Contract `transfer` calls from Wasm while preserving p26 behavior and defining new-protocol metering for the built-in fast path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Wasm contract calls a Stellar Asset Contract with function `transfer(from, to, amount)`, the host should perform the same authorization check, instance/code TTL extension, balance authorization, balance mutation, transfer event emission, rollback, error mapping, and deterministic event/result ordering as the current built-in SAC implementation. For p26 this should remain byte-for-byte and budget-for-budget identical; for the next protocol, the host may define a direct built-in SAC transfer metering schedule that avoids generic contract-call frame overhead while preserving the same ledger effects.

## Mechanism

`Host::call_contract_fn` treats `ContractExecutable::StellarAsset` as a nested contract call: it retrieves the SAC instance, clones arguments into a `Vec`, enters `with_frame(Frame::StellarAssetContract(...))`, snapshots authorization state, clones the whole storage map for rollback, pushes a contract invocation frame, and finally dispatches by symbol through `StellarAssetContract.call`. The soroswap path exercises this built-in `transfer` subcall repeatedly from Wasm even though the callee is not Wasm and the target function has fixed semantics. A protocol-gated direct `transfer` path can detect `ContractExecutable::StellarAsset` + symbol `transfer`, push only the minimal contract-invocation metadata needed for auth/event context, use a small rollback record for the touched balance/TTL/event state, and call the transfer implementation without the generic nested-frame storage-map snapshot and symbol-dispatch machinery.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Each accepted swap reaches SAC `transfer` subcalls from the router/pair Wasm path. The current trace's `applyLedger` windows contain 15,665 `SAC transfer` events and 23,569 generated host-function `call` events; the SAC trace for max-sac shows the same path at higher density with 36,008 in-apply `SAC transfer` events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-783` — `call_contract_fn` retrieves the instance and routes `ContractExecutable::StellarAsset` through `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204` — `push_context` snapshots auth, clones the current `StorageMap`, records event length, and pushes the context.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — `AuthorizationManager::push_frame` builds the contract invocation frame and snapshots tracker state.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — built-in SAC `transfer` semantics that the direct path must call or exactly preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-229` — balance read, authorization, spend, receive, and write helpers used by `transfer`.

## Evidence

Timestamp-filtered in-scope Tracy data shows `SAC transfer` totals 2,477.085 ms over 15,665 calls in the current soroswap trace, and the generic call/frame surface around it is also substantial: generated `call` totals 5,134.323 ms over 23,569 calls, `push context` totals 457.761 ms over 47,163 calls, `push auth frame` totals 339.957 ms over 47,163 calls, and `snapshot auth` totals 202.203 ms over 47,163 calls. The max-sac diagnostic trace confirms the same SAC path is hot and in-scope, with 3,715.312 ms of `SAC transfer` over 36,008 calls and 450.457 ms of `push context` in `applyLedger`. A direct built-in transfer path that removes a large fraction of the nested-frame and generic dispatch work, while retaining the actual balance/storage/event operations, has a plausible Medium impact on soroswap and should help max-sac as well.

## Anti-Evidence

This must not become a native Soroswap router/pair bypass: the scope is only the existing built-in Stellar Asset Contract `transfer` export. Prior p26-preserving SAC cleanup ideas were sub-threshold because exact metering replay left only small physical savings; this hypothesis depends on a next-protocol SAC built-in metering schedule and must include tests proving p26 still uses the generic frame path. The direct path also has to preserve auth-tree matching, event contract IDs, muxed-address event data, balance authorization errors, rollback on any failure, and diagnostic behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `001-native-sac-transfer-pipeline.md`, `001-lazy-storage-rollback-points.md`, and `002-lazy-authorization-frame-snapshots.md`
**Failed At**: reviewer

### Trace Summary

The apply path enters `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the Rust bridge into `e2e_invoke::invoke_host_function`, constructs a fresh enforcing `Host`, and calls `Host::invoke_function`. For `HostFunction::InvokeContract`, `Host::call_n_internal` performs reserved-name, reentry, and diagnostic handling before `call_contract_fn` loads the contract instance. A `ContractExecutable::StellarAsset` call always enters `with_frame(Frame::StellarAssetContract(...))`, which pushes auth/call context, captures storage/event/auth rollback state, calls the built-in SAC dispatcher, and rolls back on error.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:59` — retained failure for a native typed SAC transfer pipeline; broad SAC transfer fast paths were already rejected as narrow/sub-threshold after required semantics and metering are preserved.
- `ai-summary/fail/soroban/summary.md:78` — retained failure for lazy storage rollback points; `push context`/storage rollback self-time is aggregate worker CPU and below Medium after cluster normalization.
- `ai-summary/fail/soroban/summary.md:84` — retained failure for lazy authorization frame snapshots; auth snapshot self-time is likewise below threshold after cluster normalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ invokes the Rust Soroban host during transaction apply.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:424-481` — builds enforcing storage/auth/ledger info/module cache and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — top-level invoke-contract host function converts the target function/args and enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-function, reentry, diagnostic, and return-diagnostic handling around `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-783` — `call_contract_fn` loads the instance, clones args, and routes `ContractExecutable::StellarAsset` through `with_frame(Frame::StellarAssetContract(...))`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-204,401-598` — `with_frame` uses `push_context`/`pop_context` for depth checks, trace hooks, rollback, instance-storage persistence, events, and auth-frame pairing.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369,1376-1410` — SAC frames push a contract invocation into the auth call stack, update account/invoker trackers, snapshot auth state, and pop/rollback symmetrically.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs amount validation, `from.require_auth`, instance/code TTL extension, spend/receive balance mutation, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-229` — transfer balance logic performs persistent storage reads/writes, authorization checks, overflow checks, TTL extension, and classic-balance paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — transfer event emission depends on issuer classification, `read_name`, muxed-address data formatting, and current-frame contract ID.

### Why It Failed

This is substantially the same SAC fast-path family already retained in the Soroban fail summary. The proposed new boundary combines the previously rejected native typed SAC transfer pipeline with lazy storage rollback and lazy auth snapshot ideas; narrowing it to the `transfer` export does not remove those retained blockers.

It also does not clear the optimize-soroswap Medium severity floor. The current baseline average is 218.310 ms/ledger, so a review-stage finding needs a plausible 6.55 ms/ledger saving. Even impossibly deleting the entire cited `SAC transfer` zone would save only `2477 ms / 8 workers / 71 ledgers ~= 4.36 ms/ledger` (~2.0%), and a correct direct path cannot delete the SAC semantics: auth, TTL extension, balance storage, issuer/event logic, and rollback remain. The actually targeted frame/auth surface is smaller still: prorating the cited `push context` + `push auth frame` + `snapshot auth` totals by the SAC-transfer frame count gives roughly `332 ms / 8 / 71 ~= 0.58 ms/ledger` (~0.27%). The broad generated `call` host-function dispatch cannot be eliminated by a `call_contract_fn` fast path because the Wasm caller must still enter the host through the `call` import before the SAC target is known.

Finally, most of the supposedly generic frame work is semantic, not optional overhead. Running SAC `transfer` without a SAC frame would make `get_current_contract_id_internal`, contract events, TTL extension, and auth-tree matching observe the caller contract instead of the SAC. A replacement therefore has to recreate current-frame identity, auth-stack push/pop, event rollback, error conversion, instance-storage persistence rules, and storage rollback. That is the same protocol-visible frame model under a different implementation, with only Low/sub-threshold physical savings left.

### Lesson Learned

Do not size SAC `transfer` optimizations from the full `SAC transfer` or generated `call` parent zones. For a direct SAC fast path, first subtract mandatory SAC semantics and the unavoidable Wasm `call` import boundary, then normalize the remaining frame/auth/rollback worker totals by `NUM_CLUSTERS`; the retained SAC pipeline and lazy frame-snapshot failures already show this residual does not reach Medium.
