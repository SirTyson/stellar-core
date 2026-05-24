# H001: Protocol-gated native Soroswap router `swap_exact_tokens_for_tokens`

**Date**: 2026-05-24
**Subsystem**: crypto-adjacent rust/Soroban apply path
**Severity**: High
**Impact**: remove remaining router Wasm invocation from soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the current apply-load soroswap workload, the root contract call is the vendored router Wasm's `swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`. When the ledger protocol is the next-protocol optimization gate, the router Wasm hash matches the vendored apply-load router, the function symbol and argument shape match the benchmark's two-token path, and all storage layout checks pass, the host should produce the same ledger changes, auth consumption, events, return value, and errors as the router Wasm path while falling back to Wasm for every non-matching input.

## Mechanism

The accepted branch already bypasses the vendored pool Wasm for pool getters and pool `swap`, but `Host::call_contract_fn` still instantiates and invokes Wasmi for the root router call before it reaches the native pool fast path. A `SOROSWAP_ROUTER_WASM_HASH`-guarded `try_call_native_soroswap_router_swap_exact_tokens_for_tokens` next to the existing pool fast paths can emulate the benchmark's exact one-hop router call: validate deadline/path/min-output shape, resolve the pair from the factory/pair storage already in the footprint, perform the input-token SAC transfer, and then call the existing native pair swap helper. This removes a dominant apply descendant (`Vm::invoke_function_raw`) without changing determinism because dispatch is keyed only by protocol, fixed Wasm hash, function symbol, validated XDR argument/storage shape, and the existing deterministic host storage APIs.

## Trigger

Run `scripts/run_apply_load_matrix.py` with the current soroswap scenario (`model_tx="soroswap"`, `tx_count=2000`, `thread_count=8`). Each benchmark swap is generated in `src/simulation/ApplyLoad.cpp:3382-3505` as a root router `swap_exact_tokens_for_tokens` call with `amount_in=100`, `amount_out_min=0`, a two-token path, source-account credentials, and a single `token_in.transfer(user, pair, amount)` sub-invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `Host::call_contract_fn` currently tries native pool getter/swap only after loading the contract instance, then falls through to `instantiate_vm` and `vm.invoke_function_raw` for the router.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-1074` — existing next-protocol native Soroswap pool getter/swap pattern to mirror for router hash/function/layout gating.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` converts host args and calls Wasmi for the root router call.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-552` — top-level host invocation zone containing the router call.
- `src/simulation/ApplyLoad.cpp:3382-3505` — benchmark construction of the exact router swap trigger and footprint.

## Evidence

Current trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.

- `applyLedger` total: 4,475,605,676 ns across 71 calls.
- `Vm::invoke_function_raw` total: 7,297,837,145 ns, self: 476,515,633 ns, 7,907 calls at `soroban-env-host/src/vm.rs:400`.
- Timestamp filtering against `applyLedger` windows found 7,867 of 7,907 `Vm::invoke_function_raw` events inside apply, totaling 7,271,629,987 ns.
- With `NUM_CLUSTERS=8`, the apply-contained `Vm::invoke_function_raw` envelope is roughly 909 ms wall-clock equivalent, about 20% of the traced `applyLedger` envelope. Even a partial router-native emulation that removes half of the root Wasmi envelope clears the 3-10% Medium floor; removing most of it qualifies as High.
- The existing accepted pool-native successes demonstrate that protocol-gated emulation of fixed vendored Soroswap Wasm exports can be benchmark-meaningful and deterministic when hash/layout checks are strict.

## Anti-Evidence

The router contract's full behavior is larger than the benchmark trigger; implementing a general router replacement would be risky and unnecessary. The viable scope is intentionally narrow: exact vendored router hash, exact `swap_exact_tokens_for_tokens` symbol, exact two-hop path shape, source-account auth tree, and validated storage layout, with Wasm fallback for anything else. The PoC must prove event order, return value, auth consumption, budget/fee changes under the next-protocol gate, and ledger-entry output match the current optimized path for the benchmark before benchmarking.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record for a native Soroswap router fast path; existing VM-call and Wasmi-pooling failures target different mechanisms.
**Failed At**: reviewer

### Trace Summary

The apply-load workload does issue the root `swap_exact_tokens_for_tokens` call against the vendored router Wasm, and `Host::call_contract_fn` has no router hash gate, so the router currently falls through to `instantiate_vm` and `Vm::invoke_function_raw`. The disassembled router export confirms it validates the deadline/argument shape, calls `require_auth(to)`, computes one-hop amounts, invokes `token_in.transfer`, calls the pool swap path, and returns the amounts vector. A strict native emulation appears technically possible, but the performance claim counts the entire `Vm::invoke_function_raw` total envelope as removable even though most of that envelope is descendant host work that the native router must still perform.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `call_contract_fn` only attempts the existing native Soroswap pool getter/swap gates; a router contract with hash `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07` falls through to VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-1074` — pool getter/swap gates are protocol- and pool-hash-gated and already bypass the pool Wasm for nested router calls; they do not remove the root router VM call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1366` — native pool swap still performs the required SAC transfers/balance reads, invariant checks, reserve writes, and swap event emission, so a native router would keep this descendant work.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` self work is host-to-Wasmi argument conversion plus the Wasmi call; its cited self time is 476.5 ms aggregate for all in-apply VM calls, not just router calls.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-552` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1733-1801` — top-level host invocation enters a host-function frame and then the contract frame used by auth matching.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3657` — `Frame::NativeContract` participates in the same auth call stack as `Frame::ContractVM`; a correct router emulation would need an explicit `require_auth(to)` before the SAC transfer to consume the root auth.
- `src/simulation/ApplyLoad.cpp:3382-3505` — benchmark transactions use a two-token path, `amount_in=100`, `amount_out_min=0`, `deadline=UINT64_MAX`, source-account credentials, and one SAC-transfer sub-invocation.
- `src/rust/apply-load-wasm/soroswap_router.wasm:export swap_exact_tokens_for_tokens` — `wasm-tools print` shows export function 60 calling the address `require_auth` host function (`a.0`) on `to` before the transfer/swap sequence.

### Why It Failed

The inefficiency exists, but the severity projection is not supported. The hypothesis treats the full `Vm::invoke_function_raw` total of ~7.27 s aggregate as the router-native savings surface; however that total includes descendant SAC transfer, pool getter/swap, storage, auth, and event work that remains necessary under any correct native router. The removable VM self surface is only 476.5 ms aggregate for all in-apply VM calls, which normalizes to about 59.6 ms wall-clock at `NUM_CLUSTERS=8` — roughly 1.3% of the cited 4.476 s `applyLedger` envelope before restricting to the router subset. Even adding the avoided one-hop pool getter/frame overhead does not plausibly lift the router-specific savings to the objective's 3% Medium floor.

### Lesson Learned

For Soroban VM-call optimizations inside parallel apply, size native-emulation savings against removable self work and any truly eliminated child calls, not against the parent `Vm::invoke_function_raw` total envelope. Parent VM spans include required descendant host work; replacing the parent with native Rust changes dispatch and Wasmi execution but still must preserve auth consumption, SAC transfer, pool invariant checks, storage writes, and events.
