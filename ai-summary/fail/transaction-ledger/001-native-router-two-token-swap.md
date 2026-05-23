# H001: Native two-token Soroswap router swap trampoline

**Date**: 2026-05-23
**Subsystem**: transaction-ledger, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by bypassing the remaining router Wasm frame for the benchmark's fixed two-token swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the official apply-load Soroswap router contract, `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)` should produce the same authorization checks, SAC input transfer, pair-address selection, pair swap call, event/error behavior, storage effects, and return value whether executed through Wasm or a protocol-gated native trampoline. The native path should only run when the router Wasm hash, function symbol, argument shape, router instance layout, and two-token path match the audited benchmark shape; all other calls should fall back to Wasm unchanged.

## Mechanism

The accepted baseline already adds native emulation for the Soroswap pool getters and pool `swap`, but `Host::call_contract_fn` still only checks `try_call_native_soroswap_pool_getter` and `try_call_native_soroswap_pool_swap` for `ContractExecutable::Wasm`; router calls still instantiate and execute the router Wasm before reaching those native pool hooks. In the current Tracy trace, `Vm::invoke_function_raw` accounts for 7,271.630 ms aggregate worker time inside `applyLedger` windows, `call` accounts for 5,134.323 ms, and `Host::invoke_function` accounts for 8,244.655 ms; normalized by 71 apply windows and T=8, the VM raw-call and generated-host-call envelopes are about 12.8 ms and 9.0 ms per critical ledger respectively. A hash-gated native router path that validates the exact two-token swap shape and dispatches directly to the existing native pool-swap machinery should remove a material part of this remaining router Wasm/frame work, plausibly clearing the 3% Medium threshold on the current 215-222 ms soroswap median baseline.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the accepted baseline from `ai-summary/CURRENT_STATE.md`. Each generated transaction invokes the router contract function `swap_exact_tokens_for_tokens` with `amount_in = 100`, `amount_out_min = 0`, a two-element `[token_in, token_out]` path, the source account as recipient, and `deadline = UINT64_MAX`, so every accepted swap enters the router Wasm before calling the pair/pool path that is already partly native.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `call_contract_fn` dispatches Wasm contracts and currently only recognizes native Soroswap pool getter/swap hooks, not the router.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — existing native pool `swap` implementation that the router trampoline could reuse after deriving the pair and output amounts.
- `src/simulation/ApplyLoad.cpp:3431-3439` — generated benchmark invocation shape for `swap_exact_tokens_for_tokens`.
- `src/simulation/ApplyLoad.cpp:3447-3475` — footprint confirms the steady-state swap path reads router/pair code and instances plus two SAC balance entries and pair instance.
- `src/rust/src/soroban_test_wasm.rs:135-138` — vendored apply-load router Wasm used to compute the router code hash for the gate.

## Evidence

`ai-summary/CURRENT_STATE.md` records the active soroswap trace as `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. Timestamp-filtering individual events against the 71 `applyLedger` windows shows the remaining execution is dominated by Soroban worker execution: `parallelApply` totals 34,603.209 ms aggregate, `invoke_host_function` totals 21,578.080 ms, `Host::invoke_function` totals 8,244.655 ms, and `Vm::invoke_function_raw` totals 7,271.630 ms. The accepted p26 source at `fbbea0d9` already has code-hash and next-protocol gates for native pool getters and pool swap, demonstrating that this branch is willing to bypass known Soroswap Wasm only when gated and shape-validated.

The generated workload is especially favorable: `ApplyLoad.cpp` constructs a fixed two-token path, a known router contract, known pair contracts, and a source-account authorization tree for exactly the input SAC transfer. A router trampoline does not need to be a general Soroswap interpreter; it can accept only this narrow `swap_exact_tokens_for_tokens` form, derive the pair from the same deterministic setup data/layout the Wasm uses, invoke the existing native pool swap, and otherwise return `None` to the Wasm path.

## Anti-Evidence

A prior broad code-hash native-precompile attempt was rejected because the vendored router/pair Wasms are opaque binaries without a general audited source-equivalence harness. This hypothesis is viable only if the PoC keeps the scope narrow, protocol-gated, and exhaustively shape-checked, with fallback for any non-matching router call. The reviewer should also confirm the router path does not depend on hidden factory state omitted from the steady-state footprint; if deriving the pair address requires reimplementing unaudited router/factory logic beyond the fixed apply-load shape, this should be rejected or moved to a more thoroughly specified native-Soroswap design.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-codehash-native-soroswap-precompiles.md` and meta-pattern #22
**Failed At**: reviewer

### Trace Summary

The soroswap benchmark does generate the claimed router invocation shape, but the current apply path executes it as a normal Soroban `InvokeContract` through `parallelApply` and the Rust host. In the reviewed p26 source, `Host::call_contract_fn` has only two production executable branches: instantiate and run `ContractExecutable::Wasm`, or call the built-in `ContractExecutable::StellarAsset`; there are no `try_call_native_soroswap_pool_getter`, `try_call_native_soroswap_pool_swap`, or router trampoline hooks to extend. This is also already recorded as a failed native-Soroswap precompile family in the transaction-ledger fail summary, so the hypothesis is both non-novel and based on an absent prerequisite.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:74` — prior `002-codehash-native-soroswap-precompiles.md` failure covers code-hash native precompiles for Soroswap router/pair Wasm.
- `ai-summary/fail/transaction-ledger/summary.md:221` — records that native Soroswap pool swap/getter helpers, SAC helpers, and native router trampolines are absent from the current tree.
- `src/ledger/LedgerManagerImpl.cpp:2483-2510` — Soroban worker threads call `txBundle.getTx()->parallelApply` inside the apply path.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `TransactionFrame::parallelApply` requires a single Soroban operation and dispatches to `op->parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — `OperationFrame::parallelApply` directly delegates to the operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the C++ helper invokes `rust_bridge::invoke_host_function` with the host function, footprint entries, auth, ledger info, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — v23+ Soroban apply uses `InvokeHostFunctionParallelApplyHelper` and returns the helper's normal host invocation result.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust dispatches to the protocol-specific host module for the current ledger protocol.
- `src/rust/src/soroban_proto_any.rs:310-340` — the protocol-specific bridge catches panics and calls the host invocation implementation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — p26 host builds enforcing storage, installs the module cache, decodes the host function, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the contract instance, copies args, then either instantiates Wasm and enters `Frame::ContractVM` or dispatches `ContractExecutable::StellarAsset`; no native Soroswap branch exists.
- `src/simulation/ApplyLoad.cpp:2896-3026` — setup uploads the vendored router Wasm and deploys the router with `txtest::makeWasmExecutable(routerCodeKey.contractCode().hash)`.
- `src/simulation/ApplyLoad.cpp:3431-3475` — steady-state swap transactions call `swap_exact_tokens_for_tokens` with the two-token path and include router/pair Wasm keys in the footprint.
- `src/rust/src/soroban_test_wasm.rs:135-138` — the router Wasm is included from `../apply-load-wasm/soroswap_router.wasm`.

### Why It Failed

The proposed router trampoline depends on existing native Soroswap pool getter/swap machinery, but the reviewed source tree does not contain that machinery. The only production bypass in `call_contract_fn` is for `ContractExecutable::StellarAsset`; the router and pair contracts deployed by the benchmark are ordinary Wasm contracts. A native router trampoline would therefore be a new code-hash native precompile effort, substantially equivalent to the already failed `002-codehash-native-soroswap-precompiles.md` family and still blocked by the same consensus-equivalence and absent-hook issues.

### Lesson Learned

Do not propose follow-on optimizations for native Soroswap router, pool, or raw instance-storage paths unless those native hooks are present in the reviewed p26 host source; benchmark traces of router Wasm execution cannot justify a trampoline that has no existing audited native machinery to reuse.
