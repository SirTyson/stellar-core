# H002: Single-Hash Compiled Backend for the Remaining Soroswap Router Wasm

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: High
**Impact**: Dominant-phase redesign for the remaining router Wasm invocation inside soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the vendored Soroswap router Wasm hash used by apply-load, invoking
`swap_exact_tokens_for_tokens` should preserve the same Wasm-visible host-call
order, fuel/budget accounting policy for the next protocol, auth behavior,
storage effects, events, return value, and fallback errors as the current
wasmi-interpreted router execution. Non-matching module hashes, symbols,
argument shapes, protocol versions, diagnostic-sensitive modes, or modules that
fail a deterministic compiled-backend eligibility check should continue through
`Vm::instantiate_wasmi` and `Vm::invoke_function_raw`.

## Mechanism

After the accepted native pool getter, native pair swap, direct SAC balance,
raw pool instance-storage, and sparse no-meta ledger-change work, the current
soroswap path still pays one fresh wasmi store/instance plus interpreted router
bytecode for almost every applied transaction. Instead of hand-emulating the
router's economic logic or rebuilding pair ids natively, a next-protocol
single-hash backend can attach a preverified compiled/traced implementation to
the cached `ParsedModule` for the exact router hash and call it from
`Host::call_contract_fn` before constructing `Vm`. The compiled backend would
still enter normal host functions for calls into SAC/pair contracts, preserving
observable ordering, but it would remove the per-transaction wasmi
instantiation, export lookup, value trampoline, and interpreter dispatch for
the router frame.

## Trigger

Run the current next-protocol soroswap apply-load benchmark. Each top-level
transaction invokes the vendored router's `swap_exact_tokens_for_tokens` export;
matching router calls should execute through the cached compiled backend,
whereas every non-matching contract or argument shape should fall back to the
existing wasmi VM path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` currently only recognizes native pool getter/swap calls and otherwise instantiates a `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1644` — `instantiate_vm` constructs a fresh VM from the module cache for every non-native router call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-215` — cached modules still create a fresh wasmi store and instance per invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` performs the remaining router export invocation through wasmi.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs` and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` — natural places to cache the exact-hash compiled router backend next to the parsed module.

## Evidence

The current Tracy trace confirms this work is inside the benchmark window:
unwrap containment shows `Vm::instantiate_wasmi - instantiate` at
`soroban-env-host/src/vm.rs:171` has 8,113 events and 464,646,606 ns inside
`applyLedger` (99.2% of its total), and `Vm::invoke_function_raw` at
`soroban-env-host/src/vm.rs:400` has 8,066 events and 7,231,631,147 ns inside
`applyLedger` (99.7%). These counts align with the remaining top-level router
frame after the downstream pool/pair paths were specialized. The proposal is
not the previously rejected native-router salt/hash reconstruction: it avoids
new XDR/SHA pair-id work by executing the router's verified control flow
directly from a cached backend while keeping host calls in their original order.

## Anti-Evidence

This is a redesign, not a small local patch. It must prove deterministic Wasm
semantics for the exact router hash, preserve or intentionally next-protocol
recalibrate fuel/budget behavior, and avoid exceeding `NUM_CLUSTERS` worker
parallelism. The existing wasmi store-reuse failures still apply to generic
modules; this hypothesis is only viable if the backend is exact-hash gated and
does not attempt to reset or reuse mutable wasmi store state. If implementation
falls back to hand-emulating router economics, it risks duplicating the rejected
native-router path and must be rejected.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The soroswap apply-load path constructs one top-level `InvokeContract` to the vendored router `swap_exact_tokens_for_tokens` per swap transaction, with a fixed five-argument shape and a footprint containing the router instance/code, token instances, pair code, token balances, trustlines, and the pair instance. `Host::call_contract_fn` still only intercepts the accepted native pool getter/swap cases; the router's Wasm executable falls through to `instantiate_vm`, creates a fresh wasmi `Store`/`Instance` even on module-cache hits, pushes a `Frame::ContractVM`, and calls `Vm::invoke_function_raw`. A single-hash compiled backend placed before `instantiate_vm` can preserve the router's own control-flow and host-call sequence while removing the router frame's store/instance construction, export lookup, VM value trampoline, relative-handle dispatch boundary, and interpreter loop.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3506` — confirms the benchmark invokes router `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, path=[token_in, token_out], to=source, deadline=UINT64_MAX)` and includes one source-account auth tree rooted at the router invocation with a token-in `transfer` sub-invocation.
- `src/simulation/ApplyLoad.cpp:2860-3075` — confirms apply-load uploads and deploys the vendored router Wasm, records its code hash/key and instance key, and initializes it with the factory address.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` retrieves the instance, copies args into the frame-owned vector, checks only pool getter/swap native matchers for Wasm contracts, and otherwise constructs a `ContractVM` frame around a freshly instantiated `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1644` — `instantiate_vm` uses the module cache only for `Arc<ParsedModule>` and a shared linker; cache hits still call `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-215` — `from_parsed_module_and_wasmi_linker` calls `instantiate_wasmi`, which creates a new `wasmi::Store`, charges cached-instantiation costs, checks imports, instantiates the module, and records the memory export for every invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345,393-411` — `invoke_function_raw` marshals args through relative object handles, resolves the export, transfers budget/fuel around the VM call, and returns the result through the same value boundary.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-253,270-295` — every router-originated host call crosses the generated wasmi dispatch wrapper, returns fuel to the host, charges `DispatchHostFunction`, converts relative VM values into host values, calls the host method, marshals the result back, and refills VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-25,160-183,189-195` and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:146-153,212-228` — the cache/parsed-module structures currently store only wasmi module state and cost inputs; there is no exact-hash native backend slot yet.
- `src/rust/src/soroban_proto_any.rs:700-737` and `src/rust/src/soroban_module_cache.rs:38-53` — core precompiles Wasm into per-protocol module caches before apply, giving a natural place to attach a router-hash backend during compilation.
- `src/rust/apply-load-wasm/README.md:1-6` and `src/rust/apply-load-wasm/soroswap_router.wasm` (`sha256=4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`) — the target router Wasm is a vendored fixed binary, and its export table includes `swap_exact_tokens_for_tokens`.

### Findings

The inefficiency exists and is hot: the remaining router call is inside `closeLedger`, happens once per soroswap swap transaction, and still pays fresh wasmi store/instance creation plus `Vm::invoke_function_raw` despite earlier accepted native specializations removing the downstream pool getter, pair swap, and SAC balance Wasm frames. Existing cache infrastructure mitigates parsing but not execution setup: `ModuleCache` stores parsed modules, yet `instantiate_vm` still creates per-call mutable VM state because wasmi store/instance reuse is unsafe and was already rejected for generic contracts.

This is novel relative to the checked fail/success records. `fail/soroban-env/summary.md` and `fail/soroban-env/002-footprint-resolved-native-router-swap.md` cover hand-written/native router fast paths; they failed because a footprint-only pair match was not authoritative, while canonical pair-ID proof reintroduced native XDR/SHA work and undermined the claimed optimization. This hypothesis does not trust footprint state and does not add a new pair-ID derivation path: the compiled backend must execute the router's verified control flow and call the same host functions in the same order, so pair derivation remains whatever the router Wasm already did. The accepted successes cover pool getters, pair swap, SAC balance reads, and storage-map lookup specialization, but none attaches an exact-hash compiled backend to the cached router module.

The proposed fix is mechanically correct only if the backend is generated or audited against the exact Wasm function, not implemented as a new economic shortcut. It must run under a normal contract frame (likely `Frame::NativeContract` or a dedicated equivalent), preserve auth-frame visibility and rollback, keep all router host calls and their ordering, preserve or intentionally recalibrate next-protocol metering, and fall back before side effects for non-matching hashes, symbols, argument shapes, protocols, diagnostic-sensitive modes, or backend eligibility failures. It must also avoid any attempt to cache or reset mutable `wasmi::Store`/`Instance` state; the backend should be independent immutable code attached beside `ParsedModule`, not reused VM state.

The likely impact clears the objective's Medium floor but should not be called High before measurement. The trace totals for `Vm::invoke_function_raw` are an upper bound because a correct backend still pays the router's real host-function bodies, SAC transfer, native pair swap, storage, events, and pair-ID host calls. However, it can remove the router-specific wasmi instantiation/export/value/fuel/relative-object dispatch layers and interpreter execution for roughly 8k in-apply router calls, which is plausibly in the 3-10% soroswap apply-time range. A PoC must prove this with repeated non-Tracy matrix runs and reject the approach if the direct backend's own scaffolding or metering replay consumes the win.

### PoC Guidance

- **Target code**: extend `ParsedModule` / `ModuleCache` to optionally hold an exact-router backend for hash `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`; add a guarded router dispatch in `Host::call_contract_fn` before `instantiate_vm`; keep helper code in `host/frame.rs` or a small router-backend module inside p26 `soroban-env-host`.
- **Change description**: during module-cache compilation, recognize the exact vendored router hash and attach a preverified backend for `swap_exact_tokens_for_tokens`. On invocation, require next protocol, exact function symbol, exact arity/type eligibility, normal diagnostics policy, and a backend eligibility check; push the same contract-frame semantics and execute the compiled router control flow with direct `Host`/`Env` calls instead of wasmi. Do not hand-emulate pair economics or use footprint-only pair selection; if the backend cannot execute a branch faithfully, fall back before side effects.
- **Correctness check**: existing host/auth/storage tests cover the underlying frame, auth, rollback, and host-function behavior, but the PoC should add focused equivalence coverage for the exact router call if practical: successful benchmark swap, malformed arg fallback, non-router hash fallback, non-positive/edge reserve behavior, missing footprint errors, deadline/amount-min failure behavior, and diagnostic/error ordering. Released p26 must always fall back.
- **Benchmark focus**: run three non-Tracy `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` runs against the accepted baseline and require at least 3% soroswap median apply-time reduction. Capture one diagnostic Tracy run only for attribution, confirming top-level router `Vm::instantiate_wasmi` and `Vm::invoke_function_raw` events disappear inside `applyLedger` while expected router host-call zones remain and no new pair-ID XDR/SHA work appears beyond what the router already performed.
