# H002: Soroswap Router Call-Import Fast Path

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction in router Wasm host-import dispatch
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the top-level Soroswap router Wasm invokes the host `call` import for the benchmark's exact pair/pool/SAC call shapes, apply should run the same downstream contract call, authorization stack update, event ordering, storage effects, budget/fuel accounting, and error behavior as the generic generated VM dispatch path. Calls from non-router modules, calls with unexpected target IDs, functions, or argument shapes, and all older protocol versions should continue through the existing generated dispatch wrapper unchanged.

## Mechanism

Every router-side cross-contract call currently enters the macro-generated `vm/dispatch.rs` wrapper for the `call` host function, which performs generic protocol checks, fuel transfer, dispatch charging, `VmCaller` construction, argument conversion/checking, error augmentation, result conversion, and fuel refill before reaching the already-native pair/pool/SAC call paths. A protocol-gated router-module fast path could bind a specialized `call` import or branch at the start of the generated `call` wrapper that recognizes the exact Soroswap benchmark call shapes and jumps directly into typed host call helpers while still applying the same dispatch charge and fuel synchronization. This differs from the prior native-router hypothesis: the router Wasm still executes, but the hottest VM->host import boundary for its repeated internal calls is shortened.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the current baseline with `soroswap, TX=2000, T=8`, protocol 27 enabled, and the benchmark router Wasm making its normal sequence of `call` host imports into the native Soroswap pair/pool and SAC contracts. The fast path should activate only for the known router module hash and exact call signatures used by the benchmark; all other host imports must use the current generated wrapper.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:205-296` — generated host-function wrapper for VM imports; line 304 emits the hot `call` zone.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-321,393-411` — VM function invocation and argument conversion around the host import boundary.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — downstream `Host::call_contract_fn` dispatch, including native Soroswap pool and SAC paths.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1366` — native pool swap and SAC helper paths reached by router `call` imports.

## Evidence

The current soroswap Tracy trace shows the `call` VM dispatch zone at `soroban-env-host/src/vm/dispatch.rs:304` with 1,142,798,682 ns self-time across 25,183 events, and timestamp filtering confirms every event overlaps the 72 measured `applyLedger` windows. Dividing by T=8 gives roughly 142.8 ms of critical-path upper bound, almost exactly the 3% Medium floor against the 4,802.2 ms apply-window total; nearby apply-descendant boundary zones (`Vm::invoke_function_raw` self-time 511,441,472 ns and `Host::invoke_function` self-time 129,581,052 ns) add further headroom if the specialized import removes conversion and wrapper work around repeated router calls.

## Anti-Evidence

The generated dispatch wrapper contains mandatory work: VM fuel synchronization, `DispatchHostFunction` budget charging, argument validation, and error-context behavior cannot simply be skipped. The PoC must show that enough of the `call` self-time is removable in a non-Tracy build after preserving those semantics; if the fast path only removes symbol/arity checks or Tracy-span overhead, it will fall below the objective's Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a router Wasm `call` import-boundary fast path
**Failed At**: reviewer

### Trace Summary

The top-level Soroswap `InvokeContract` host function enters `Host::invoke_function`, pushes a host-function frame, and calls `call_n_internal` for the router contract. The router Wasm is then invoked through `Vm::invoke_function_raw`/`metered_func_call`; each router-side cross-contract call reaches the generated `dispatch.rs` `call` wrapper, which transfers VM fuel to the host, charges `DispatchHostFunction`, converts relative VM object handles to absolute host objects, calls `Host::call`, augments errors, converts the return value back to a relative VM object, and refills VM fuel. `Host::call` then copies the argument vector, resolves the contract address, and re-enters `call_n_internal`, whose downstream `call_contract_fn` already dispatches protocol-gated native Soroswap pool getter/swap paths and Stellar Asset contract calls where applicable.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-552` — Rust bridge invocation builds the host and calls `Host::invoke_function` inside the apply path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1733-1756` — top-level `HostFunction::InvokeContract` converts the router function/args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-390` — `metered_func_call` resolves the Wasm export, transfers fuel into and out of wasmi, runs the router function, and converts the returned VM value to a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `invoke_function_raw` allocates and fills the Wasm argument vector with absolute-to-relative object conversion before entering `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:205-296` — the generated `call` import wrapper performs the mandatory boundary work: host clone, protocol guard, optional tracing, fuel return, dispatch charge, `VmCaller` creation, relative-to-absolute argument conversion/checking, host call, optional tracing, error augmentation/escalation, return-value checking, absolute-to-relative return conversion, and fuel refill.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2591-2625` — `Host::call` unpacks the `VecObject` args, resolves the contract ID from the address object, invokes `call_n_internal`, and records the same `"contract call failed"` context on error.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` — `call_n_internal` enforces reserved-function and reentry rules, pushes the correct contract/auth/frame context, dispatches the contract, and emits function diagnostics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` retrieves the target contract instance and routes Wasm contracts through native Soroswap pool getter/swap checks before generic VM invocation; Stellar Asset contracts already call the built-in SAC directly.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1366` — the native Soroswap pool swap path reached by router `call` imports still uses `call_n_internal` for SAC transfers/balance fallback where needed and depends on correct frame/auth/event semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:308-440` — relative object handles are the VM isolation boundary, so address/function/args and return values must still be translated at host import entry/exit.

### Why It Failed

The inefficiency is a composite Tracy zone, but the hypothesis does not identify a Medium-sized safely removable subset. A correct fast path must still perform VM fuel synchronization, `DispatchHostFunction` charging, relative-to-absolute conversion for the address/function/args, argument-vector extraction or equivalent shape validation, contract-address resolution, reentry checks, auth-frame/context push and rollback, error-context behavior, return-value validation, absolute-to-relative conversion, and VM fuel refill. Branching early in the generated `call` wrapper can at most save small generic glue such as `VmCaller` construction or a few already-required wrapper conversions; jumping around `Host::call`/`call_n_internal` would either break consensus-visible frame/auth/error semantics or become a larger native-router/native-contract dispatch redesign already covered by prior router/pool investigations. Because the measured 142.8 ms is an upper bound for the entire `call` wrapper and the safe removable part is much smaller than the 3% objective floor, this is below the required Medium severity threshold.

### Lesson Learned

Generated VM dispatch spans must be decomposed before promoting import-boundary hypotheses. For `call`, most apparent self-time is either mandatory VM/host isolation and metering or downstream contract-call framing that cannot be skipped without turning the idea into a full native router/contract executor.
