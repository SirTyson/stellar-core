# H002: Manifest-Backed Native Soroswap Router Trampoline

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-8% soroswap apply-time reduction by removing the remaining top-level router Wasm invocation for the benchmarked two-token swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the next-protocol soroswap apply-load path, a call to the allowlisted Soroswap router Wasm hash for `swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)` with a two-token path should execute through a protocol-defined native trampoline when a generated binary manifest proves the exact ABI, storage, error, auth, and event behavior. The native trampoline should push a router-native frame for the root authorized invocation, validate the same argument and deadline conditions, compute the same pair address from the router's stored factory and sorted token IDs, call the existing native pair `swap` path, and fall back to Wasm for any shape not covered by the manifest.

## Mechanism

The current native Soroswap fast paths only intercept pair contract getters and `swap` after the router Wasm has already been instantiated and interpreted. Every accepted swap still enters `Host::call_contract_fn` for the router, builds a `ContractVM` frame, invokes `Vm::invoke_function_raw`, and executes router Wasm imports that are deterministic for the generated two-token benchmark shape. A manifest-backed trampoline keyed by the exact vendored `soroswap_router.wasm` hash can make the previously under-specified native-router idea concrete: the manifest records the router storage keys, supported export, exact error-code mapping, no-router-event assertion, auth root/subinvocation shape, pair-address derivation, and the required next-protocol metering schedule.

The significant deviation is that the current apply path pays full Wasm VM instantiation/execution and import dispatch for a router whose hot-path behavior is already constrained by the benchmark generator and by the existing native pair implementation. Replacing just that root router execution with a manifest-verified native frame should remove the remaining router VM and dispatch work while preserving per-transaction Host, budget, auth, event, PRNG, and rollback isolation.

## Trigger

Run `scripts/run_apply_load_matrix.py` for the current soroswap scenario. `ApplyLoad::generateSoroswapSwaps` constructs every swap as a router `swap_exact_tokens_for_tokens` invocation with `amount_in = 100`, `amount_out_min = 0`, `path = [token_in, token_out]`, `to = source_account`, and `deadline = UINT64_MAX`, plus a source-account auth tree whose root is the router call and whose only subinvocation is `token_in.transfer(user, pair, amount)`. A PoC should gate on the router Wasm hash and this exact manifest-covered shape, then compare three non-Tracy runs; any unsupported shape must continue through the Wasm router unchanged.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-828` — `Host::call_contract_fn`; currently checks native pair getter/swap only, then instantiates a Wasm VM for the router.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — existing next-protocol native pair `swap` implementation to reuse from the router trampoline after computing the pair address and output amounts.
- `src/simulation/ApplyLoad.cpp:3382-3505` — generated soroswap swap shape, footprint, and auth tree that define the initial trigger surface.
- `src/rust/src/soroban_test_wasm.rs:135-137` and `src/rust/apply-load-wasm/soroswap_router.wasm` — vendored router Wasm bytes whose hash should key the manifest.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:122-145` — existing executable-discriminant checks used by native Soroswap/SAC fast paths; the router trampoline needs analogous next-protocol gating and fallback.

## Evidence

- Current Tracy trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
- `csvexport-release -e` reports router-relevant apply-path worker costs that remain after the accepted native pair and direct SAC balance successes: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` is **459,741,743 ns self** over 7,956 calls; `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` is **476,515,633 ns self** over 7,907 calls; `call` dispatch at `soroban-env-host/src/vm/dispatch.rs:304` is **1,216,408,561 ns self** over 23,696 calls.
- Unwrap samples place `Host::invoke_function`, `Vm::invoke_function_raw`, and dispatch `call` events inside `applyLedger` windows; this is not TX-set construction.
- After native pair `swap`, the remaining per-swap Wasm instantiation count is approximately one per invoke-host-function call, making the top-level router the dominant remaining Wasm contract in the steady-state swap path.
- `ApplyLoad::generateSoroswapSwaps` deliberately uses a narrow two-token path and round-robins across eight pairs for eight clusters, so the first trampoline can be limited to one deterministic export shape rather than a generic router implementation.

## Anti-Evidence

- Prior native-router and native-pool proposals were rejected as under-specified. This hypothesis is only viable if the PoC includes a binary-derived manifest and tests proving storage schema, pair-address derivation, error/trap mapping, auth-tree shape, event order, and next-protocol metering equivalence for the exact vendored Wasm hash.
- Broad VM and dispatch zones include mandatory SAC transfer, pair swap, storage, auth, event, and budget work that the router trampoline must preserve. The Medium claim depends on removing the root router VM/import layer plus related conversions, not the whole `parallelApply` body.
- If instrumentation shows that most `call` dispatch self-time belongs to pair/SAC work that remains after bypassing the router, the realistic saving may fall below the 3% Medium threshold.
