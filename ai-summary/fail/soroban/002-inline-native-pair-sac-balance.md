# H002: Inline Native Pair SAC Balance Reads

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing two generic SAC `balance` subcall frames from each accepted native pair `swap`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the accepted next-protocol native Soroswap pair `swap`, the two post-transfer balance checks should return exactly the balances that the current `SAC balance(pair_address)` subcalls return for token_0 and token_1. The optimized path should still extend the relevant SAC instance/code TTLs, extend the pair contract-balance TTLs when balances exist, preserve missing-balance-as-zero behavior, preserve failure and rollback behavior, and fall back to the existing subcalls if the token or owner shape is not the benchmark's contract-balance case.

## Mechanism

`call_native_soroswap_pool_swap` delegates `balance_0` and `balance_1` to `soroswap_pool_invoke_sac_balance`, which pushes two full SAC frames via `call_n_internal` even though the owner is always the pair contract address and the value needed is just the typed SAC contract balance already handled by the accepted typed SAC storage fast path. Each subcall pays frame/auth snapshot overhead, symbol construction, generic SAC dispatch, current-contract TTL extension, balance key construction, storage lookup, return conversion, and frame pop. A narrow internal helper can enter the token contract context just enough to perform the required TTL extensions and typed contract-balance read, returning `i128` directly to the native pair body.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Every accepted native pair `swap` calls `soroswap_pool_invoke_sac_balance(token_0, pair_address)` and `soroswap_pool_invoke_sac_balance(token_1, pair_address)` after the output transfer and before computing input amounts and the fee-adjusted K invariant.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1169-1170,1346-1359` at p26 commit `03d78248` — native pair swap invokes two SAC `balance` calls through `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-193` — SAC `balance` extends the token instance/code TTL and delegates to `read_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178,191-210` at p26 commit `03d78248` — typed contract-balance read path constructs the balance ledger key, reads storage, decodes `BalanceValue`, extends balance TTL, and returns zero for missing balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-598` — `with_frame` rollback semantics that any inline helper must preserve or deliberately avoid mutating until it can safely commit.

## Evidence

Apply-window Tracy totals show `SAC balance` at 415.9ms over 14,830 events, matching roughly two balance calls per native pair swap, and the surrounding frame/auth machinery is also substantial in the same apply windows: `push context` 545.2ms, `push auth frame` 407.1ms, and `snapshot auth` 238.6ms. Unlike generic SAC dispatch shortcuts, this target is not trying to remove top-level XDR conversion or the mandatory SAC transfer body; it targets the fixed pair-owned balance reads after the accepted native pair `swap` has already established the token addresses, pair owner address, and next-protocol gate. The same trace also reports `get_contract_data` at 613.8ms and `storage get` at 633.9ms, so avoiding two full subcall stacks around the actual balance read has a plausible Medium-scale ceiling if the frame/auth and conversion slices fall with it.

## Anti-Evidence

This hypothesis must not turn into the previously rejected broad Soroswap SAC-subcall fusion. It is only viable if the PoC scopes the optimization to pair-owned `balance` reads and measures the removable frame/dispatch/conversion overhead separately from the storage read that must remain. The current SAC `balance` function has observable TTL side effects, and even though it does not require auth or emit events, an inline helper must reproduce those side effects under the token contract ID and preserve rollback on later swap failure. If narrow spans show the two balance subcalls are only a sub-1% wall-time slice after parallelism normalization, the record should be moved to `fail/`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/002-fuse-native-soroswap-sac-subcalls.md`, with the same false premise also noted in `ai-summary/fail/soroban/001-raw-native-pair-instance-storage.md` and `ai-summary/fail/soroban/001-exact-router-native-swap-plan.md`
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban path reaches p26 host execution through parallel `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge, `e2e_invoke`, and `Host::invoke_function`. In this checkout, `HostFunction::InvokeContract` enters `call_n_internal`, which delegates to `call_contract_fn`; `call_contract_fn` dispatches Wasm contracts through `Frame::ContractVM` and only SAC through `Frame::StellarAssetContract`. Searches for `soroswap`, `call_native_soroswap_pool_swap`, `soroswap_pool_invoke_sac_balance`, and `NativeContract` found no production native Soroswap router/pair dispatch or helper at the cited line ranges, so the exact optimization target does not exist here. The real SAC `balance` path does extend the current SAC instance/code TTL and reads contract balances with missing-as-zero behavior, but that path is reached only through generic SAC calls, not through an accepted native pair swap body that could inline two balance reads.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584,1359-1377` — parallel Soroban apply calls `rust_bridge::invoke_host_function` from the apply path.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge builds the p26 budget/context and calls protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-485` — host storage/auth/ledger info are installed before `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` — production frames are `ContractVM`, `HostFunction`, and `StellarAssetContract`; there is no native Soroswap frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` routes `ContractExecutable::Wasm` to `instantiate_vm` + `Frame::ContractVM` and routes only `ContractExecutable::StellarAsset` to native SAC dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-988,1125-1194` — `call_n_internal` performs generic checks/diagnostics and top-level `InvokeContract` delegates through it; there is no `call_native_soroswap_pool_swap` or `soroswap_pool_invoke_sac_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-598` — `with_frame` supplies frame push/pop, instance persistence, and rollback behavior that a real inline helper would have to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:185-193` — SAC `balance` extends the current contract instance/code TTL and delegates to `read_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — contract-address balance reads construct `DataKey::Balance`, load persistent contract data, extend balance TTL when present, decode `BalanceValue`, and return zero when missing.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2293-2335` — TTL helpers depend on the current contract frame for instance/code TTL extension and use the current storage footprint for contract data TTL extension.
- `ai-summary/fail/soroban/002-fuse-native-soroswap-sac-subcalls.md:46-76` — prior review already rejected fusing the same native Soroswap SAC transfer/balance subcall family as duplicate and absent from the traced source.

### Why It Failed

The hypothesis is not novel and its specific mechanism is not present in the actual code. The prior failed `002-fuse-native-soroswap-sac-subcalls.md` record already covered eliminating SAC `balance` subcall frames from a claimed native Soroswap pair path and found both that this belongs to the previously rejected native-Soroswap bypass family and that the current p26 source has no native Soroswap pair helper. This narrower balance-only version still depends on the same absent `call_native_soroswap_pool_swap` / `soroswap_pool_invoke_sac_balance` boundary, so there is no concrete hot path to optimize.

Even if the two SAC `balance` calls are real in a benchmark trace, in this checkout they occur as ordinary SAC invocations reached from Wasm contract execution. Inlining them would require introducing the same new native Soroswap frame/helper design, auth/event/error/rollback equivalence story, protocol metering, and isolated Medium-threshold measurement retained as blockers in the previous native-Soroswap reviews.

### Lesson Learned

Before proposing residual cleanup below a native Soroswap implementation, first verify that the native implementation exists in the reviewed source tree. Narrowing a rejected native-Soroswap SAC fusion to only pair-owned `balance` reads is not a new viable target when the claimed native pair swap helper is absent and the previous review already covered SAC `balance` subcall fusion.
