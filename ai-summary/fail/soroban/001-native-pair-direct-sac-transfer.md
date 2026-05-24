# H001: Native Pair Swap Direct SAC Transfer

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by keeping native Soroswap pair `swap` on the existing native path through its SAC transfers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the next-protocol native Soroswap pair `swap` fast path has already proven that the pool Wasm hash and instance layout match the allowlisted Soroswap pair, the two token transfers inside that native swap should stay on the same native path. For SAC token addresses, the host should apply the exact SAC `transfer` effects — auth requirement, instance/code TTL extension, balance debit/credit, and transfer event — without re-entering the generic `call_n_internal` contract-call machinery.

## Mechanism

`call_native_soroswap_pool_swap` currently bypasses the pair Wasm but still calls `soroswap_pool_invoke_sac_transfer`, which converts the token address to a contract id, interns the `transfer` symbol, and calls `call_n_internal`. That re-enters `call_contract_fn`, constructs a `Frame::StellarAssetContract`, runs the generic `StellarAssetContract.call` dispatcher, and pays the full SAC transfer frame/dispatch/object-conversion path for each output transfer. A protocol-gated direct helper for known-SAC token contracts can perform the same SAC transfer components in-place, preserving p26 fallback and next-protocol metering while removing the nested native-pair -> SAC contract-call boundary.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Successful native pair swaps with `amount_0_out > 0` or `amount_1_out > 0` call `soroswap_pool_invoke_sac_transfer`; the hypothesis should replace those calls with a direct SAC-transfer helper only when `contract_instance_executable_is_stellar_asset` confirms the token instance is a SAC, otherwise falling back to `call_n_internal`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — `call_native_soroswap_pool_swap`, where native pair execution still delegates output transfers through `soroswap_pool_invoke_sac_transfer`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer`, the nested `call_n_internal` boundary to replace for confirmed SAC token contracts.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` semantics that the direct helper must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:122-145` — existing lightweight executable-discriminant check used by the accepted direct SAC balance path and reusable for transfer gating.

## Evidence

The current Tracy trace listed in `CURRENT_STATE.md` has `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 15,665 apply-contained calls and 2.477s aggregate duration inside `applyLedger` worker windows. The same trace shows the native pair path is active: `SAC balance` is almost absent because accepted direct SAC balance reads already bypass balance subframes, while `SAC transfer` remains hot. This puts the residual nested SAC transfer boundary on the measured `InvokeHostFunctionOpFrame doParallelApply -> call_native_soroswap_pool_swap` path, not in TX-set construction or lazy bucket work.

This is narrower than earlier broad native-SAC-pipeline attempts: it does not define a new router/pair bypass or a generic SAC optimization. It extends the already accepted, protocol-gated native pair `swap` implementation by replacing only the two output-transfer subcalls that are still visibly routed through the generic SAC frame.

## Anti-Evidence

Prior SAC-transfer investigations found isolated balance-read, event-XDR, and generic typed-pipeline sub-slices below threshold. This hypothesis needs to remove the whole nested SAC contract-call boundary, not just a duplicate storage read or event construction. The direct helper must preserve auth-tree shape, event contract id/order, TTL extension, p26 fallback, budget semantics for the next protocol, and all non-SAC fallback behavior; if it only shaves a small piece of `SAC transfer`, it will fall below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prior failures covered broader/native-precompile or generic SAC-transfer variants, but this exact post-native-pair residual transfer boundary was not present in the checked success/fail set
**Failed At**: reviewer

### Trace Summary

The native Soroswap pair path is active and `call_native_soroswap_pool_swap` still calls `soroswap_pool_invoke_sac_transfer` for each positive output amount. That helper converts the token address to a contract id, builds the `transfer` symbol, and goes through `call_n_internal`, which loads the SAC instance, pushes `Frame::StellarAssetContract`, and dispatches `StellarAssetContract.call`. However, preserving SAC transfer semantics requires the current SAC contract id for auth and event emission, plus the mandatory TTL, storage, authorization, and event work; the removable boundary is only a subset of the measured `SAC transfer` zone.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pair `swap` validates output/reserves, then invokes SAC transfer once per nonzero output before direct SAC balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — `soroswap_pool_invoke_sac_transfer` is the residual nested `call_n_internal` boundary.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` loads the instance, copies args, pushes `Frame::StellarAssetContract`, and calls the generic SAC dispatcher.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs amount validation, `from.require_auth`, instance/code TTL extension, balance debit/credit, and transfer/mint/burn event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `require_auth` uses the current frame's function args and auth stack frame, so a direct in-pair call would change the authorized invocation unless it recreates the SAC transfer frame/function context.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:250-263` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:223-234` — contract events derive their contract id from the current frame, so event identity also depends on preserving a SAC-token frame or explicitly recreating equivalent event behavior.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:122-145` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1368-1393` — the accepted direct balance path can safely use only the SAC executable discriminant because balance reads have no auth/event frame identity requirement.

### Why It Failed

The optimization is below the objective severity threshold. The hypothesis's own measured ceiling for the entire `SAC transfer` zone is 2.477s aggregate worker time; normalized by `T=8` and the 71-ledger Tracy run, that is about 4.36 ms/ledger, roughly 2.0% of the current 218.31 ms soroswap median baseline. A correct direct helper cannot remove the whole zone because it must keep authorization, TTL extension, balance mutation, and event construction, and preserving auth-tree shape/event contract id likely requires retaining or explicitly recreating the SAC transfer frame context. Therefore the realistic removable portion is below the 3% Medium floor required by the optimize-soroswap objective.

### Lesson Learned

Residual native-pair SAC transfer work is real, but SAC transfer aggregate Tracy time must be normalized by worker parallelism and ledger count, then discounted for mandatory semantic work. Frame/dispatch cleanup alone is not enough for a Medium soroswap apply-time finding after the accepted native pair and direct-balance baseline.
