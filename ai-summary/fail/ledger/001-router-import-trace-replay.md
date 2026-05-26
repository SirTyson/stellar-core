# H001: Deterministic Soroswap Router Import-Trace Replay

**Date**: 2026-05-26
**Subsystem**: ledger / Soroban host apply path
**Severity**: High
**Impact**: dominant-phase redesign of the soroswap `InvokeHostFunction` worker path by replacing repeated fixed-shape router Wasm dispatch with a verified deterministic host-call trace
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For an exact next-protocol official Soroswap router swap transaction, the apply path should preserve the same router contract id, source-account auth root, pool/SAC calls, events, result value, TTL/rent effects, rollback boundaries, resource reporting, and final ledger entries as the current Wasm router execution. If the router code hash, function, arguments, auth tree, diagnostics mode, footprint shape, or callee layout differs from the supported benchmark shape, the existing `Host` + Wasm VM path should run unchanged.

For the recognized shape, the router's sequence of host imports should be a deterministic template parameterized by the transaction's path, amount fields, recipient, and current pool/balance state. The apply path should be able to replay that verified import schedule through normal host frame/SAC/native-pool helpers instead of re-entering `Vm::invoke_function_raw` and generated import thunks for every transaction.

## Mechanism

The current native pool/SAC optimizations only fire after the outer router Wasm has been instantiated and invoked. `Host::invoke_function` still converts the router `HostFunction` into host values, pushes a host-function frame, calls `call_n_internal`, dispatches through `call_contract_fn`, instantiates the router VM, and then crosses generated `call` imports to reach the already-native pool and SAC paths.

A protocol-gated router import-trace replay path would validate that the router Wasm hash and `swap_exact_tokens_for_tokens` ABI match the official benchmark router, then execute a preverified sequence of host calls under a router frame. This is not a direct ledger-effects builder: it would still use existing `call_n_internal`, native pool, SAC transfer/balance, auth, storage, TTL, event, and rollback machinery for each semantic operation, but it would skip the router bytecode interpreter and generated import dispatch envelope that merely rediscover that fixed call graph.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with next-protocol native Soroswap optimizations enabled. The trigger is a successful official router swap invocation whose router contract executable hash, function name, argument count/types, route length, auth tree, source account, and footprint entries match the validated template. Any mismatch must fall back before replay and execute the current Wasm path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:528-552` — decodes auth/host function/source account, constructs the `Host`, and invokes the router through `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1868-1937` — `HostFunction::InvokeContract` pushes the host-function frame, converts router args, and calls `call_n_internal`; the replay path must preserve this frame/auth root.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` falls through to `instantiate_vm` and `Vm::invoke_function_raw` for the router Wasm, while native pool calls are only recognized after router imports call the pool.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` converts host args to VM-relative values and runs the Wasm function.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-import thunks wrap each router `call`/vector/object import with fuel reconciliation, dispatch charging, argument conversion, result conversion, and trap escalation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1528` — existing next-protocol native pool swap and direct SAC balance paths that replay would call as semantic building blocks, not reimplement.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer semantics that replay must preserve through the existing implementation.

## Evidence

The current trace is `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` reports `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` with 4,412,547,914 ns total over 71 calls. Timeline intersection against `applyLedger` windows confirms the targeted zones are in-scope descendants: `Host::invoke_function` contributes 8,237,885,814 ns over 8,018 in-window events, `Vm::invoke_function_raw` contributes 7,231,631,147 ns over 8,034 events, generated `call` contributes 4,937,728,356 ns over 24,078 events, and `SAC transfer` contributes 2,644,782,958 ns over 16,005 events.

The source shows the router remains on the Wasm VM path: `call_contract_fn` only special-cases Soroswap pool getter/swap calls and otherwise instantiates the callee VM. Since the official router workload has a fixed, hash-checkable call pattern and the expensive state-mutating leaves already have native helpers, removing the router VM/import envelope from the slowest worker phase is plausibly Medium-to-High if the template covers the headline soroswap swaps.

## Anti-Evidence

This overlaps conceptually with prior native-router/direct-effects failures, so novelty depends on the mechanism: replay must preserve the router frame and call existing host semantics rather than synthesize final ledger effects or hand-write an unconstrained router. It must also handle diagnostics, failed inner calls, auth recording, event order, result hashing, budget changes, and fallback exactly. If the replay still performs most generated import conversion or if the recognized subset is narrower than the benchmark's hot path, the improvement may fall below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `001-native-soroswap-router-swap.md`
**Failed At**: reviewer

### Trace Summary

The current apply path enters Rust through `InvokeHostFunctionOpFrame::invokeHostFunction`, builds a `Host`, decodes auth and the `HostFunction`, then calls `Host::invoke_function`. `HostFunction::InvokeContract` pushes the top host-function frame and reaches `call_n_internal`, but the router contract itself falls through `call_contract_fn` to `instantiate_vm` and `Vm::invoke_function_raw`; only subsequent router imports can reach the existing native pool/SAC helpers. A deterministic router import-trace replay that skips the router VM while preserving the router frame would be a protocol-gated native router body that drives `call_n_internal` for the exact official swap shape, which is substantially the same mechanism already recorded as the native Soroswap router swap path.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:74,92` — records prior native-router findings, including `001-native-soroswap-router-swap.md`, a protocol-gated native Soroswap router swap path bypassing router Wasm instantiation and VM dispatch for the same benchmark shape.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ always calls the Rust bridge with encoded host function, resources, source account, auth, ledger entries, TTL entries, rent config, and module cache.
- `src/rust/src/soroban_proto_any.rs:391-488` — Rust bridge builds budget/accounting, invokes the p26 host path, then converts ledger changes and rent output for C++.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:528-552` — p26 decodes auth, host function, and source account, configures the `Host`, and invokes `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1868-1937` — `HostFunction::InvokeContract` pushes the host-function frame, converts router args, and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1735` — `call_n_internal` enforces reserved-function and reentry semantics before dispatching to the actual contract body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — router Wasm currently instantiates a VM and runs `Vm::invoke_function_raw`; native pool dispatch only applies when the callee is a recognized pool contract.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2591-2625` — router Wasm imports cross generated dispatch, convert VM-relative handles, reconcile fuel, charge dispatch, and call back into `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-630` — frames are rollback/lifecycle/storage-persistence boundaries that any router replay must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1528` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — current native pool and SAC paths provide semantic building blocks, but the missing piece is still a native router execution body.
- `src/simulation/ApplyLoad.cpp:3381-3515` — soroswap benchmark generates the same official router `swap_exact_tokens_for_tokens` transaction, path, footprint, and source-account auth shape targeted by the prior native-router finding.

### Why It Failed

This is not novel under the review rules. The proposed "import-trace replay" avoids direct final ledger-effect synthesis, but it still replaces the official router Wasm body with a protocol-gated native implementation for the same `swap_exact_tokens_for_tokens` benchmark shape and the same required semantic coverage: router frame/auth root, pool/SAC calls, diagnostics, rollback, TTL/rent effects, events, budget/resource reporting, result hashing, and fallback. That is substantially equivalent to the recorded `001-native-soroswap-router-swap.md` finding, which was already reviewed viable but failed during PoC due to exactly this implementation complexity.

### Lesson Learned

Renaming the native router body as a deterministic import-trace replay is not enough to make it a new hypothesis. A future reattempt needs a materially new solution to the recorded PoC blocker, such as a concrete, bounded equivalence strategy for router auth/events/TTL/rent/rollback/resource accounting and a safe implementation seam, not another protocol-gated replay of the same router swap semantics.
