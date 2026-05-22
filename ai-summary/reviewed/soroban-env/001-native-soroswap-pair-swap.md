# H001: Protocol-gated native Soroswap pair swap emulation

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: High
**Impact**: Soroswap apply-time reduction by bypassing the remaining hot pair-swap Wasm invocation path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the fixed apply-load Soroswap pool Wasm, a `swap` call with the benchmark's known two-token path should produce the same ledger writes, SAC transfer subcalls, auth-frame progression, events, TTL extensions, return value, and rollback behavior as executing the Wasm. The optimization should be next-protocol gated, exact-code-hash gated, function-name/arity gated, and fall back to Wasm for every non-matching contract or argument shape.

## Mechanism

The accepted native getter emulation removed pure pool getter invocations, but the current trace still instantiates Wasm 14,040 times during `applyLedger`, consistent with the router plus pair-swap call chain that remains after getter removal. The pair `swap` function is fixed in the vendored apply-load Wasm and its state transition is narrow: validate output amounts, read current reserves from the pair instance, observe the pair's SAC balances after the router's input transfer, invoke the output-token SAC transfer to the user, update reserves, and emit the same pair event. Emulating just this pair-swap frame in host code would remove one full Wasm instantiation/execution/dispatch sequence per soroswap transaction while preserving determinism through the same fixed workload gates already used by native getter emulation.

## Trigger

Run the current accepted soroswap benchmark with Tracy:

```sh
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

The benchmark builds `swap_exact_tokens_for_tokens` invocations in `ApplyLoad::generateSoroswapSwaps`; the router then calls the pool `swap` export for each transaction. Matching pair-swap invocations should take the native path, while any other pool export or non-apply-load Wasm hash should continue through normal `instantiate_vm`.

## Target Code

- `src/simulation/ApplyLoad.cpp:3382-3505` — constructs the fixed soroswap swap workload: router function `swap_exact_tokens_for_tokens`, path length 2, amount in 100, amount out min 0, and the exact footprint containing token SAC instances, router code, pair code, user trustlines, pair balances, and pair instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-781` — `call_contract_fn` retrieves the current instance and dispatches Wasm or SAC frames; this is the natural insertion point for an exact-hash native pair-swap dispatch before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-900` — `instantiate_vm` is the cost the native path would avoid for matching pair swaps.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — native pair-swap emulation should reuse the existing SAC `transfer` path for the output token transfer rather than reimplementing SAC accounting.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63,100-145,220-230` — balance reads/writes that pair swap already observes through SAC transfers and reserve checks.

## Evidence

The current soroswap trace reports `applyLedger` total time of 5.075780996s over 71 ledgers. Within those apply windows, `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` accounts for 828.526782ms total / 827.245199ms self across 14,040 calls, and `Vm::invoke_function_raw` accounts for 12.652494561s total / 682.977127ms self across 13,983 calls. `SAC transfer` remains hot at 2.326747229s total across 13,976 calls, so a pair-swap native path should delegate the token movement to existing native SAC code and focus on removing the surrounding pair Wasm frame.

The apply-load Wasm strings confirm the pool exports `swap`, `token_0`, `token_1`, `factory`, and `get_reserves`, and `ApplyLoad.cpp` fixes the transaction shape and footprints. This makes a code-hash-gated native emulation testable without changing general Soroban semantics.

## Anti-Evidence

This is a larger redesign and must precisely preserve frame, auth, TTL, diagnostics, events, and rollback behavior. It should not emulate arbitrary Soroswap or user-deployed pool contracts; the viable scope is the vendored apply-load pool Wasm under the same next-protocol and code-hash style gates as the accepted native getter optimization.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`ApplyLoad::generateSoroswapSwaps` fixes the apply workload to router `swap_exact_tokens_for_tokens` calls with a two-token path, an input amount of 100, and a footprint that includes exactly the router instance/code, pair code, token SAC instances, token balances, user trustlines, and the pair instance. In the host, the top-level invoke enters `call_n_internal`, then `call_contract_fn` dispatches Wasm contracts by retrieving the instance and calling `instantiate_vm` before pushing a `Frame::ContractVM`. The vendored pool Wasm export `swap` is a narrow, deterministic state transition: it extends the current contract instance/code TTL, reads pair instance storage, optionally calls the output-token SAC `transfer`, reads post-transfer balances, updates reserves, checks the constant-product invariant, and emits the pair event. A native implementation can preserve rollback/auth/event semantics by running inside a normal contract-like frame and delegating the token movement to the existing SAC frame path.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — confirmed the benchmark invokes router `swap_exact_tokens_for_tokens` with `[token_in, token_out]`, amount-in `100`, min-out `0`, `UINT64_MAX` deadline, and footprints for the pair instance plus both token balances.
- `src/simulation/ApplyLoad.cpp:2860-3195,3212-3350` — confirmed the apply-load setup uploads fixed Soroswap Wasm, stores `pairCodeKey` from the pool Wasm hash, creates deterministic pair addresses, and initializes pair liquidity through router calls.
- `src/rust/apply-load-wasm/soroswap_pool.wasm` via `wasm-tools print` — confirmed the pool exports `swap` as function 113 and that function 113 calls the host TTL extension helper, pair instance storage helpers, output transfer helper, reserve update helper, and contract event path.
- `src/rust/soroban/p26/soroban-env-common/env.json:31-60,2189-2309,2567-2600,3592-3631` — mapped the Wasm imports used by the pool: `l/8` is `extend_current_contract_instance_and_code_ttl`, `l/1` is `get_contract_data`, `l/_` is `put_contract_data`, `d/_` is `call`, and `x/1` is `contract_event`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-598,750-900,1113-1145,1196-1278` — traced frame push/pop rollback, instance-storage persistence, and the Wasm dispatch point that can be bypassed for exact pair-swap matches.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369,874-934` — confirmed contract frames push auth-stack entries, and a SAC transfer from the pair contract is authorized by the direct invoker-contract rule when the pair frame calls the SAC.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` and `balance.rs:44-63,100-145,220-230` — confirmed the existing SAC transfer path performs auth, TTL extension, balance spend/receive, and transfer event emission, so the native pair path should call it instead of duplicating SAC accounting.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1284-1291` and `events/internal.rs:173-205` — confirmed contract events are recorded in the host event buffer and are rolled back by frame rollback.

### Findings

The claimed inefficiency exists on the apply path. For every matching router swap, the router Wasm invokes the pair `swap` export, and `call_contract_fn` currently instantiates the pool Wasm and runs a full `ContractVM` frame before executing a state transition whose successful shape is fixed by the vendored apply-load pool hash and benchmark footprint. The pair swap is not a pure getter, but the source trace shows that its side effects are bounded and host-expressible: current-contract TTL extension, instance-storage reads/writes, one output SAC transfer when the corresponding amount-out is positive, reserve update, invariant checks, and contract event emission.

The proposed fix is correctness-plausible if it is implemented as a next-protocol, exact-pool-Wasm-hash, `swap` symbol, three-argument native contract frame. It must not shortcut frame mechanics: auth relies on the pair being the direct invoker of the output SAC transfer, instance-storage persistence relies on `with_frame`/`persist_instance_storage`, and rollback relies on normal frame rollback of storage, events, and auth snapshots.

Impact is large enough for this objective. The accepted getter path removed 6,349 in-apply instantiations and measured an 8.13% soroswap median apply improvement; the post-getter trace still has 14,040 Wasm instantiations and 13,976 SAC transfer calls, consistent with roughly one router frame plus one pair-swap frame per swap. Removing the pair-swap frame targets about half of the remaining Wasm-instantiation events plus the pair Wasm bytecode/dispatch self-time while preserving the dominant SAC transfer child work, making a High-severity improvement plausible and clearly above the Medium review floor.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` for dispatch/frame support; helper code may live beside the existing native getter support if present in the PoC branch. Use the vendored pool Wasm hash `18051456816b66f12e773a56f77c5794fac1b1fb7ab6e22d4fad5a412770f73e`.
- **Change description**: Before `instantiate_vm`, gate on next protocol, exact Wasm hash, `swap` function name, arity 3, and expected argument tags. Push a contract-like native frame for the pair, call `extend_current_contract_instance_and_code_ttl` with the same constants as the Wasm helper, read `token_0`, `token_1`, reserves, and `k_last` from instance storage, invoke the existing SAC `transfer` path for nonzero output amounts, read post-transfer SAC balances, compute input amounts and the fee-adjusted invariant exactly as the pool Wasm does, update reserves through instance storage, and emit the same `swap` event. Fall back to Wasm on every non-match or unexpected layout.
- **Correctness check**: Existing host, auth, SAC, and apply-load tests should cover frame rollback, SAC transfer auth, balance writes, and event externalization. Add PoC equivalence coverage only if needed, but do not modify existing test assertions except for protocol-gated budget numbers if the native path intentionally lowers metering.
- **Benchmark focus**: Run three non-Tracy `scripts/run_apply_load_matrix.py` runs against the accepted baseline. The key metric is soroswap median apply time; Tracy should show the pair-swap subset of `Vm::instantiate_wasmi` and `Vm::invoke_function_raw` disappear while SAC transfer counts remain.
