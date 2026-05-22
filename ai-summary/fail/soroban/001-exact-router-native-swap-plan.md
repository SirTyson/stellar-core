# H001: Exact Native Soroswap Router Swap Plan

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the remaining top-level router Wasm frame
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol apply-load transactions that call the exact vendored Soroswap router hash `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07` with `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)`, the host should produce the same source-account auth check, SAC input transfer, pair swap sub-invocation, return value, events, storage writes, rollback behavior, and errors as the router Wasm. The efficient path should recognize only the fixed benchmark shape (`amount_out_min == 0`, two-token path, `deadline == UINT64_MAX`, exact router instance layout) and fall back to Wasm for every non-matching call.

## Mechanism

The current accepted stack has native pool getters and a native pair `swap`, but the top-level router call still goes through `Host::call_contract_fn`, `Vm::instantiate_wasmi`, and `Vm::invoke_function_raw` once per soroswap transaction. The current diagnostic trace confirms this residual work is inside `applyLedger`: `Vm::invoke_function_raw` total is 7.310519968s over 7,457 in-apply events, `call` total is 5.379186081s over 22,353 in-apply host-function dispatches, and `Vm::instantiate_wasmi - instantiate` total is 443.597600ms over 7,508 in-apply events. A protocol-gated native router plan would remove the router VM orchestration layer while reusing the already accepted native pair swap and SAC paths for the actual state transition.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the current soroswap scenario (`TX=2000,T=8`) from a next-protocol build. Each generated transaction invokes router `swap_exact_tokens_for_tokens` with the exact two-token path and footprint assembled by `ApplyLoad::generateSoroswapSwaps`.

## Target Code

- `src/simulation/ApplyLoad.cpp:3382-3505` — constructs the exact two-token router call, source-account auth tree, and footprint used by every benchmark swap.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:780-825` at submodule commit `03d78248` — `call_contract_fn` retrieves the router instance, clones args, misses the pool-native gates, instantiates the router VM, and calls `vm.invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1360` at submodule commit `03d78248` — existing exact-hash native pair swap helpers that the router plan can call instead of reproducing pair semantics from scratch.

## Evidence

The current trace path from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/183979915cef-20260522-114338/logs/183979915cef-20260522-114338-02-soroswap-tx-2000-t-8.tracy`. Unwrap containment against `applyLedger` shows the VM and dispatch events above occur inside the measured apply windows, not TX-set construction. The C++ generator fixes the call shape: `functionName = "swap_exact_tokens_for_tokens"`, args are `[i128(100), i128(0), [token_in, token_out], from, u64::MAX]`, and the footprint includes router instance/code, pair code, two SAC instances, two user trustlines, two pair SAC balances, and the pair instance. The accepted p26 native pool work demonstrates this branch already has protocol-gated exact-hash native Soroswap emulation machinery.

## Anti-Evidence

Native router emulation is correctness-sensitive and must not be a vague code-hash precompile. The PoC needs an equivalence harness or exact audited spec for deadline handling, path validation, `amount_out_min`, auth/sub-invocation order, diagnostic events, and all router error codes. If the implementation only removes VM instantiation but still routes most router arithmetic through generic host objects, the win may fall below Medium; the benchmark should include narrow Tracy spans for native-router hits and fallback counts.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/002-two-token-router-native-trampoline.md` and `ai-summary/fail/soroban/summary.md:131`
**Failed At**: reviewer

### Trace Summary

The apply-load setup uploads fixed vendored Soroswap pool and router Wasms and stores their code hashes, then every measured swap invokes router `swap_exact_tokens_for_tokens` with amount-in 100, amount-out-min 0, a two-token path, source-account recipient, `UINT64_MAX` deadline, the router/pair/SAC footprint, and a source-account auth tree containing the token-in SAC `transfer` sub-invocation. In the p26 host, top-level `InvokeContract` converts XDR args, enters `call_n_internal`, then calls `call_contract_fn`; production `ContractExecutable::Wasm` calls instantiate a fresh `Vm`, push `Frame::ContractVM`, and call `Vm::invoke_function_raw`, while SAC is the only production built-in/native contract path in this checkout. This confirms the targeted router Wasm frame is real, but the exact fixed two-token router-native trampoline has already been reviewed and failed novelty/severity due to missing router-specific cost isolation and incomplete native auth/event/error/metering semantics.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:131` — records `001-router-only-native-soroswap-trampoline.md + 002-native-two-token-router-swap-plan.md` as the prior router-only native trampoline for fixed two-hop soroswap swaps, with unresolved router-specific attribution and semantic-spec blockers.
- `ai-summary/fail/soroban/002-two-token-router-native-trampoline.md:62-95` — prior reviewer traced the same router hash, export, fixed two-token shape, auth subtree, and Wasm dispatch path, then rejected it as a duplicate of the retained router-only native trampoline failure.
- `src/simulation/ApplyLoad.cpp:2855-2913` — setup uploads the vendored factory, pair, and router Wasms; hashes the pair and router bytes; and stores `mSoroswapState.pairCodeKey` and `mSoroswapState.routerCodeKey`.
- `src/simulation/ApplyLoad.cpp:3382-3505` — measured swaps construct the exact `swap_exact_tokens_for_tokens` call with `[i128(100), i128(0), [token_in, token_out], from, UINT64_MAX]`, the router/token/pair footprint, and the source-account auth tree with a token-in SAC `transfer` sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` retrieves the contract instance, clones args, routes every `ContractExecutable::Wasm` through `instantiate_vm` plus `Frame::ContractVM`, and routes only `ContractExecutable::StellarAsset` through the native SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — top-level `HostFunction::InvokeContract` converts XDR args and delegates to `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — `Vm::from_parsed_module_and_wasmi_linker` creates a fresh wasmi store and instance for each Wasm contract call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` converts host values to relative Wasm values and invokes the exported Wasm function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` and `src/rust/soroban/p26/soroban-env-host/src/` search for `soroswap`, `swap_exact_tokens_for_tokens`, and `NativeContract` — no production native Soroswap router/pair dispatch exists in this checkout, so the hypothesis's "already accepted native pair swap helpers" premise is not present in the traced source tree.

### Why It Failed

This is substantially the same optimization as the previously investigated fixed two-token Soroswap router-native trampoline: hash-gate the vendored router, recognize `swap_exact_tokens_for_tokens` with the benchmark's two-token shape, bypass the router VM frame, and rely on child SAC/pair behavior for the actual state transition. The current hypothesis adds the claim that native pair `swap` helpers already exist, but the traced p26 source still has only generic Wasm dispatch and SAC native dispatch; there is no in-tree native Soroswap router/pair frame to reuse. More importantly, it does not resolve the retained blockers from the prior review: code-hash-specific router-only timing after excluding child pair/SAC work, exact root auth-frame consumption, event contract attribution/order, router error mapping, pair-for/path/deadline semantics, artifact equivalence, rollback behavior, and a next-protocol metering schedule. Under the objective's Medium-or-higher floor, aggregate VM timing is not enough to resubmit this duplicate router shortcut.

### Lesson Learned

Do not resubmit router-native Soroswap shortcuts unless they complete the retained refinement requirements: isolated router-code-hash timing that clears the Medium floor by itself, plus a concrete next-protocol native-contract/frame specification for auth, events, errors, fallback, rollback, and metering. Narrowing the trigger to the exact apply-load router hash and two-token args is not novel because that exact shape was already the basis of the prior failed router-trampoline review.
