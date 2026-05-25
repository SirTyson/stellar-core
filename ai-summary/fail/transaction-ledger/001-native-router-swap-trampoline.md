# H001: Native Soroswap Router Swap Trampoline

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / Soroban host apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the remaining top-level router Wasm invocation before the existing native pair path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load Soroswap workload, `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)` should produce the same source-account authorization consumption, nested SAC transfer authorization, pair reserve update, transfer events, router return value, diagnostics, and rollback behavior as the vendored router Wasm. The optimized path should trigger only behind the next-protocol gate, for the exact embedded router Wasm hash/function/argument shape used by the benchmark, and must fall back to the existing Wasm path for every unknown hash, function, route shape, storage layout, or released protocol.

## Mechanism

The current accepted p26 source has native hooks for the Soroswap pool getter and pair `swap`, but `Host::call_contract_fn` still recognizes only the pool Wasm hash before falling through to `instantiate_vm` for the router contract. Every soroswap transaction therefore pays the top-level router Wasm store/instance, router guest execution, and router host-call dispatch before reaching the already-native pair logic. A native router trampoline can reuse the existing `Frame::NativeContract` machinery to preserve deterministic frame/auth/rollback semantics while executing the fixed benchmark route directly: validate deadline and path, derive or confirm the pair address, perform the input SAC transfer inside the router frame, invoke or inline the existing native pair swap, enforce `amount_out_min`, and return the same amount vector.

## Trigger

Run the current protocol-27 `soroswap, TX=2000, T=8` apply-load scenario. Each successful transaction is a top-level `HOST_FUNCTION_TYPE_INVOKE_CONTRACT` to `mSoroswapState.routerContractID` with function `"swap_exact_tokens_for_tokens"` and a two-token path (`src/simulation/ApplyLoad.cpp:3427-3505`). The current host dispatch does not contain a router hash hook, so these calls instantiate and execute router Wasm before the native pair path is considered.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-825` — `Host::call_contract_fn` only matches native pool getter/swap hooks before `instantiate_vm`; add a router hash/function hook before the VM fallthrough.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1333-1375` — existing native pair reserve update and swap-event construction to preserve or reuse from the router trampoline.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1735` — external-call validation, diagnostics, reentry, and frame semantics the trampoline must preserve by using `with_frame` rather than bypassing context machinery.
- `src/simulation/ApplyLoad.cpp:3427-3505` — fixed benchmark call shape, footprint, and source-account auth tree used to gate the trampoline.

## Evidence

The current soroswap trace shows the router/contract execution region remains a dominant apply descendant: `invoke_host_function` totals ~11.899s over 8,687 calls inside `applyLedger`, `Host::invoke_function` totals ~9.047s, `Vm::invoke_function_raw` totals ~7.951s, and generated host `call@vm/dispatch.rs:304` totals ~5.428s over 26,079 events. The current accepted source confirms that only pool Wasm calls are hash-gated to native handlers (`frame.rs:795-813`); the top-level router still reaches `instantiate_vm` (`frame.rs:814-825`). Removing the router Wasm frame attacks a Medium-sized parent region rather than a sub-threshold micro-zone, and it stays within `NUM_CLUSTERS` because it changes per-worker execution, not parallelism.

## Anti-Evidence

This is only viable if it preserves router-observable semantics exactly. Prior narrow SAC-transfer and frame-dispatch shortcuts failed because auth frames, diagnostics, storage rollback, and event ordering are required; the trampoline must push a router native frame and must not skip the SAC transfer auth sub-invocation or pair frame semantics. The benchmark-specific route is intentionally narrow: multi-hop routes, different router hashes, unexpected storage layouts, and released protocols should fall back to Wasm, so the performance win is scoped to the apply-load Soroswap shape.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/001-native-router-exact-swap-trampoline.md`
**Failed At**: reviewer

### Trace Summary

The soroswap apply-load generator constructs the same canonical top-level router `swap_exact_tokens_for_tokens` invocation with a two-token path, five fixed argument positions, declared router/pair/SAC footprint entries, and a source-account auth tree that sub-invokes the input SAC `transfer`. In p26, that call reaches `Host::call_contract_fn`, which only checks native Soroswap pool getter/swap hooks for Wasm executables before falling back to `instantiate_vm` and `Vm::invoke_function_raw` for the router contract. This is the same mechanism already reviewed in the existing failed `Native Soroswap Router Exact-Swap Trampoline` record, including the requirement to preserve router frame/auth/rollback/event semantics while leaving mandatory pair/SAC work intact.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/001-native-router-exact-swap-trampoline.md:15-19` — prior failed hypothesis describes the same router Wasm fallback and exact `swap_exact_tokens_for_tokens` trampoline mechanism.
- `ai-summary/fail/transaction-ledger/001-native-router-exact-swap-trampoline.md:47-78` — prior review marks the mechanism as a duplicate of earlier router-trampoline/fused-executor work and rejects it below the objective's Medium threshold.
- `src/simulation/ApplyLoad.cpp:3427-3505` — constructs the benchmark router invoke, footprint, and auth shape referenced by this hypothesis.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` recognizes native pool hooks only, then instantiates/invokes Wasm for non-pool Wasm contracts such as the router.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1333-1375` — native pair swap still performs reserve updates and swap event emission, which the router trampoline would have to preserve rather than remove.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1665-1735` — `call_n_internal` performs reserved-function checks, reentry checks, and call diagnostics before dispatching, so a viable trampoline must retain this context path.

### Why It Failed

This hypothesis is substantially equivalent to the already-investigated native router exact-swap trampoline. The current source still matches the asserted dispatch shape, but novelty fails: the prior record already covered the same top-level router Wasm bypass on the native-pool-hook baseline and rejected promotion because the removable router-only portion did not clear the optimize-soroswap Medium threshold after accounting for mandatory SAC transfer, native pair swap, reserve mutation, auth, event, rollback, TTL, and metadata work.

### Lesson Learned

Do not re-promote router `swap_exact_tokens_for_tokens` trampolines unless there is new benchmark evidence that isolates the router-only critical-path savings above the 3% objective threshold; otherwise this remains the same below-threshold duplicate rather than a novel Medium finding.
