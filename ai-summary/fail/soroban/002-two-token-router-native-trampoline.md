# H002: Two-Token Soroswap Router Native Trampoline

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by bypassing the fixed router Wasm frame for benchmark-shaped swaps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-next apply-load ledgers, a top-level `InvokeContract` to the vendored
Soroswap router Wasm hash
`4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07` and export
`swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)` should use a
native trampoline when the call has the benchmark's exact shape: `path` length 2,
`amount_out_min == 0`, `deadline == u64::MAX`, and a source-account auth tree containing
the single token-in SAC `transfer` sub-invocation. The trampoline should produce the same
observable result as the router Wasm: consume the same auth, compute the same pair address,
perform the same token-in transfer and pool swap, return the same value, and emit events
from the same contracts in the same order.

## Mechanism

The apply-load generator always builds a two-token path and fixed argument pattern for
measured swaps. The current host nevertheless instantiates and interprets the router Wasm
for every swap before it reaches the already-fixed child calls. A hash-gated native
trampoline can validate the exact argument/auth shape, perform the router's deterministic
two-token routing logic in host code, and then invoke the same SAC transfer and pool
contract call that the router would have made. This removes one wasmi VM frame per swap
without changing parallelism or transaction ordering; all child calls still execute through
the existing host frame machinery, so auth and event attribution remain deterministic.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the current
protocol-next soroswap benchmark. Every generated measured transaction in
`ApplyLoad::generateSoroswapSwaps` calls router `swap_exact_tokens_for_tokens` with
`amount_in=100`, `amount_out_min=0`, a two-address path, `to=source account`, and
`deadline=UINT64_MAX`. The native path should trigger only for that exact code hash and
shape; a test run with the router hash changed or path length not equal to 2 should fall
back to the existing Wasm path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — add a guarded router dispatch before the generic Wasm `instantiate_vm` path.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — VM instantiation avoided for the router frame on matched calls.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — raw router function invocation avoided on matched calls.
- `src/simulation/ApplyLoad.cpp:3412-3439` — fixed measured router arguments.
- `src/simulation/ApplyLoad.cpp:3447-3475` — exact footprint shape containing router instance/code, token SAC instances, pair code, user trustlines, SAC pair balances, and pair instance.
- `src/simulation/ApplyLoad.cpp:3477-3492` — source-account auth tree with one token-in `transfer` sub-invocation.

## Evidence

The current trace has **14,040** `Vm::instantiate_wasmi` events for **7,000** host invocations, matching the router-plus-pool call shape. `Vm::instantiate_wasmi - instantiate` contributes **827,245,199 ns self-time**, while `Vm::invoke_function_raw` contributes **12,652,494,561 ns total-time** inside `applyLedger`; unwrap containment and worker-window aggregation show VM descendants are the dominant parallel-worker critical-path component. The router binary's contract spec exports `swap_exact_tokens_for_tokens`, `router_pair_for`, `router_get_amount_out`, and `router_get_amounts_out`, but the measured harness uses only the simple two-token `swap_exact_tokens_for_tokens` path, so the native implementation can be deliberately narrow and fallback-driven.

## Anti-Evidence

Router-only native dispatch was previously under-specified when it did not isolate router-specific time or define auth/event semantics. This trampoline must therefore be measured separately from the pool-native hypothesis: first run with only router trampoline enabled and pool still on Wasm to prove the router frame alone clears the Medium floor. It also must not synthesize child effects directly; doing so would risk auth-tree consumption, event contract IDs, rollback behavior, and budget observations. If router interpreter time is mostly child pool/SAC work included in the parent `Vm::invoke_function_raw` total, the router-only saving may be below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-router-only-native-soroswap-trampoline.md + 002-native-two-token-router-swap-plan.md`
**Failed At**: reviewer

### Trace Summary

The soroswap setup uploads the vendored router Wasm, hashes it into `mSoroswapState.routerCodeKey`, deploys a router instance, and the measured swap loop invokes `swap_exact_tokens_for_tokens` with the fixed two-token path, zero minimum output, `UINT64_MAX` deadline, and a single token-in SAC `transfer` sub-invocation in the source-account auth tree. In the p26 host, `InvokeContract` enters `invoke_function_and_return_val`, then `call_n_internal`, then `call_contract_fn`; every `ContractExecutable::Wasm`, including the router, instantiates a fresh `Vm`, pushes `Frame::ContractVM`, and calls `Vm::invoke_function_raw`. This confirms the targeted path exists, but the exact router-only native trampoline has already been investigated and retained as a failed/refinement record because router-specific VM cost was not isolated and the native-contract semantics were incomplete.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:131` — records the prior `001-router-only-native-soroswap-trampoline.md + 002-native-two-token-router-swap-plan.md` failure with the same router-only trampoline idea and the same blockers.
- `src/simulation/ApplyLoad.cpp:2896-2913` — loads `get_apply_load_soroswap_router_wasm()`, hashes it, stores `routerCodeKey`, and uploads the router code.
- `src/simulation/ApplyLoad.cpp:3412-3439` — constructs the measured `swap_exact_tokens_for_tokens` arguments: two-token path, `amount_in=100`, `amount_out_min=0`, recipient source account, and `UINT64_MAX` deadline.
- `src/simulation/ApplyLoad.cpp:3447-3496` — declares the router/token/pair footprint and the source-account authorization tree containing the router root invocation plus the token-in SAC `transfer` sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1148` — top-level `HostFunction::InvokeContract` converts XDR args and delegates to `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1115` — `call_n_internal` performs reserved-function and reentry checks before dispatching production calls to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` has only two production paths: Wasm contracts instantiate a `Vm` and execute a `Frame::ContractVM`; SAC uses `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` — the production frame enum has no native router/native contract frame variant to carry router-equivalent auth/event context.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218` — `Vm::from_parsed_module_and_wasmi_linker` runs the `Vm::instantiate_wasmi` path and creates a new store/instance.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` converts absolute handles to relative Wasm args and enters the exported Wasm function.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3592-3632` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `require_auth` derives the authorized function from the current auth stack frame and current frame args.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — auth stack frames are pushed from `Frame::ContractVM` and `Frame::StellarAssetContract`, so a router trampoline would need an equivalent frame/context design to match the root router auth node.

### Why It Failed

This is a duplicate of the previously investigated router-only native Soroswap trampoline. The current hypothesis narrows the trigger shape, but it repeats the prior unresolved issues: no router-code-hash-specific attribution proving that the router frame alone clears the objective's Medium floor after excluding child pool/SAC work, and no complete next-protocol native-contract specification for root `require_auth` consumption, event contract attribution/order, `router_pair_for` semantics, exact error mapping, and metering equivalence. Under the objective's Medium-or-higher acceptance rule, aggregate router-plus-pool VM timing is insufficient to promote this again.

### Lesson Learned

Router-native Soroswap proposals should not be resubmitted unless they first complete the retained refinement requirements: diagnostic per-code-hash timing that isolates removable router-only work, plus a concrete native frame/auth/event/metering specification that preserves the observable router invocation rather than only replaying its child calls.
