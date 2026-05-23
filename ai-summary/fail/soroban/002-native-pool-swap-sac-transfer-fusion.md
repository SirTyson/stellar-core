# H002: Fuse Native Pool Swap SAC Transfer and Balance Accounting

**Date**: 2026-05-23
**Subsystem**: soroban, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating residual SAC subcall and redundant balance-read work inside native pool `swap`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The native Soroswap pool `swap` path should move the output SAC balance from the pair contract to the recipient, emit the same SAC transfer event, compute the post-transfer pair balances, enforce the same input and constant-product checks, update reserves, and emit the same pool swap event as the current native pool swap plus SAC subcalls. The optimized path should preserve authorization, TTL extension, storage errors, rollback behavior, and event order exactly, while avoiding generic SAC frame dispatch and avoidable balance reads for the hash-gated native pool shape.

## Mechanism

`call_native_soroswap_pool_swap` still calls `soroswap_pool_invoke_sac_transfer` through `call_n_internal`, then calls `soroswap_pool_invoke_sac_balance` for both token balances before deriving `amount_0_in` and `amount_1_in`. For the normal apply-load one-output swap, the output-side pair balance after transfer is known from `reserve_out - amount_out`, and only the input-side balance read is needed to detect the incoming amount transferred by the router. A pool-local typed SAC helper can perform the same transfer storage mutation and event emission, return the updated output pair balance to the caller, and fall back to generic SAC for non-SAC or non-contract-owner cases.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the accepted baseline. Every accepted native pool `swap` with exactly one positive output amount enters `call_native_soroswap_pool_swap`, performs one output SAC transfer, and then reads both pair balances before updating reserves.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — native pool `swap` performs output SAC transfer(s), then reads both post-transfer balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1266` — computes input amounts and updates reserves from the post-transfer balance values.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1366` — `soroswap_pool_invoke_sac_transfer` and `soroswap_pool_invoke_sac_balance` re-enter generic SAC call/read paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` semantics that must be preserved.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199` — direct contract-owner SAC balance reader added by the accepted current state.

## Evidence

The current Tracy trace is in the measured apply path: timestamp-filtered events that start inside `applyLedger` windows show `SAC transfer` at 15,665 calls / 2.477s aggregate worker time, `storage get` at 321,802 calls / 672ms, generated dispatch `call` at 23,569 calls / 5.134s, and `ScVal to Val` conversion at 800,217 calls / 1.144s. Source at p26 commit `fbbea0d9` shows the native pool path already knows the token addresses, pair address, reserves, output amounts, and recipient before calling the SAC; it also already contains a direct SAC balance read helper for contract-owner balances. This makes the output-transfer-plus-known-balance fusion a narrower and more testable target than a generic SAC fast lane.

## Anti-Evidence

SAC transfer work is semantically load-bearing: source auth, balance authorization, TTL extension, exact event emission, and rollback must remain unchanged. The projected Medium impact is tight because `SAC transfer` alone normalizes to only a few milliseconds per ledger; the PoC must show that removing generic `call_n_internal` dispatch plus one balance read per swap clears the 3% floor on the current 215-222ms soroswap baseline. If the safest implementation can only skip the post-transfer output balance read while keeping the SAC subframe unchanged, this should be downgraded below the objective threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry for `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md + 001-binary-specified-pool-swap-native-precompile.md + 001-native-soroswap-pool-swap-and-liquidity.md + 002-fuse-native-soroswap-sac-subcalls.md + 002-inline-native-pair-sac-balance.md + 001-raw-native-pair-instance-storage.md`
**Failed At**: reviewer

### Trace Summary

The live invocation path starts in `InvokeHostFunctionOpFrame`, crosses the Rust bridge, constructs a fresh enforcing Soroban `Host`, and calls `Host::invoke_function`. `HostFunction::InvokeContract` then enters `call_n_internal`, which performs reserved-name and reentry checks and falls through to `call_contract_fn`. In the checked-out p26 source, `call_contract_fn` has no `call_native_soroswap_pool_swap`, `soroswap_pool_invoke_sac_transfer`, or `soroswap_pool_invoke_sac_balance` branch: Wasm contracts instantiate a VM and run `vm.invoke_function_raw`, while only `ContractExecutable::StellarAsset` enters the built-in SAC frame. The SAC `transfer` implementation remains the generic load-bearing path with amount validation, `from.require_auth`, instance/code TTL extension, spend/receive balance mutation, and `transfer_maybe_with_issuer` event emission.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:117` — prior retained failure already covers pool-only native Soroswap precompile variants, including SAC subcall fusion and inline pair SAC balance reads.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — apply serializes auth/resources/ledger entries and invokes the Rust Soroban host for each transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge creates the budget and delegates to protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — host invocation builds enforcing storage, auth, ledger info, PRNG, module cache, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `HostFunction::InvokeContract` converts function/args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1114` — `call_n_internal` handles reserved-name checks, reentry checks, diagnostics, test-only native contracts, and otherwise delegates to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785` — `call_contract_fn` unconditionally runs Wasm contracts through VM instantiation and `vm.invoke_function_raw`; only `ContractExecutable::StellarAsset` dispatches to the built-in SAC.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs auth, TTL extension, balance mutation, and event emission that any native shortcut would have to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-71,100-153,220-230` — SAC balance reads and mutations go through persistent `DataKey::Balance` storage for contract addresses, with authorization and overflow/error behavior embedded in `receive_balance` and `spend_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-65,94-113` — SAC transfer event shape depends on issuer checks, asset name reads, muxed-address data formatting, and contract event emission order.

### Why It Failed

This is a duplicate of a retained failed/refinement family for pool-only native Soroswap precompiles, specifically the variants named `002-fuse-native-soroswap-sac-subcalls` and `002-inline-native-pair-sac-balance`. The current hypothesis also assumes a native pool-swap implementation that is not present in the checked-out source, so its target code cannot be modified as described. Even if that prerequisite existed, the prior blocker remains: a safe native pool/SAC fusion needs a complete native-contract semantic and metering specification covering approved Wasm hashes, storage schema, event ordering, auth-frame context, error/trap mapping, rollback, and p26/next-protocol budget behavior before it can be promoted.

### Lesson Learned

Do not resubmit native Soroswap pool subcall-fusion variants by narrowing the residual SAC transfer or balance-read boundary. First verify the native pair frame exists in the current source, then provide the full binary-equivalence and metering specification required by the retained pool-only native precompile failure.
