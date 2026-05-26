# H002: Binary-Derived Native Router Manifest for Exact Soroswap Swaps

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: High
**Impact**: >10% soroswap apply-time reduction if the remaining router Wasm frame is replaced by a protocol-gated, binary-proven native execution plan
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the fixed apply-load Soroswap router call shape, the host should produce the same source-account auth requirement, SAC transfer, native pool swap, events, return value, failure ordering, budget schedule, and transaction success hash as the vendored router Wasm. Non-matching router hashes, functions, argument shapes, deadlines, path lengths, or storage layouts should fall back to the existing Wasm execution unchanged.

## Mechanism

The accepted native pool getter/swap path removes the pair Wasm frames, but the top-level router contract still instantiates and executes Wasm for each swap before it reaches the native pool helpers. A next-protocol native router path backed by a checked-in binary-derived manifest can make the router equivalence reviewable: the manifest records the exact vendored router hash, exported function, accepted argument shape, expected call sequence (`require_auth` -> token-in SAC transfer -> pair swap), return-value layout, event contract IDs, error-code mapping, and metering schedule. With that manifest, `call_contract_fn` or the top-level host-function invocation can dispatch the exact router swap directly to the already-accepted SAC and pool helpers instead of entering `Vm::invoke_function_raw`.

## Trigger

Run `scripts/run_apply_load_matrix.py` for `soroswap, TX=2000, T=8` on a next-protocol build. Each benchmark transaction invokes the vendored router `swap_exact_tokens_for_tokens` shape over a two-token path and reaches `applyLedger -> applyParallelPhase -> InvokeHostFunctionOpFrame::doParallelApply -> invoke_host_function -> Host::invoke_function`; matching invocations should take the manifest-gated native router path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` recognizes native pool getter/swap calls, but matching router Wasm still falls through to `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1375` — existing native pool swap helper already preserves pool reserve updates, SAC subcalls, K-invariant validation, and pair swap event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1528` — existing native pool helper already invokes SAC transfer and direct SAC balance reads.
- `src/rust/src/soroban_proto_any.rs:391-488` — apply-mode Rust bridge invokes the host function and extracts return/events/effects for C++ consensus handling.

## Evidence

The current Tracy profile shows the remaining Wasm/router envelope is apply-contained and large enough for a structural redesign: `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` has 504.887964ms self-time, `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has 467.581245ms self-time, and the generated host `call` dispatch zone at `soroban-env-host/src/vm/dispatch.rs:304` has 1.166051341s self-time; unwrap containment confirms nearly all corresponding events fall inside `applyLedger`. The source also shows the native pool machinery already handles the lower half of the router path, so the remaining dominant semantic gap is the router frame and its exact auth/ABI/error/metering specification.

This is testable by adding the manifest as a protocol artifact, refusing to match unless the exact router hash and call shape are present, and comparing host outputs byte-for-byte against the Wasm path in focused tests before running the three required non-Tracy soroswap matrices.

## Anti-Evidence

The correctness burden is high. A hash gate alone is insufficient: the manifest must prove auth-tree ordering, event ordering and contract IDs, return vector encoding, deadline and slippage behavior, pair resolution, trap/error mapping, and next-protocol metering. If the manifest cannot be generated from the vendored router binary and reviewed as a stable protocol artifact, this collapses into an under-specified native-router bypass and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md:131` (`002-manifest-backed-native-router-trampoline` / exact router native swap variants) and `ai-summary/fail/soroban/summary.md:222` (all native Soroswap bypass variants share unresolved specification blockers)
**Failed At**: reviewer

### Trace Summary

The soroswap apply-load transaction targets the vendored router contract directly with `HostFunction::InvokeContract` and `swap_exact_tokens_for_tokens`. The Rust bridge deserializes that host function, constructs a fresh `Host`, and calls `Host::invoke_function`; the host then enters `call_n_internal`, and `call_contract_fn` only recognizes the allowlisted Soroswap pool hash for pool getters and `swap`. There is no checked-in router hash, native router manifest, or native router dispatch path in the current source, so router calls still instantiate the router Wasm and execute through `Vm::invoke_function_raw` before any pool-native fast path can be reached.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2888-2913` — the benchmark uploads the vendored `soroswap_router.wasm` and records its code hash as ledger state, not as a native protocol artifact.
- `src/simulation/ApplyLoad.cpp:3427-3479` — swap transactions invoke `mSoroswapState.routerContractID` with function `swap_exact_tokens_for_tokens`; the auth root is the router call and the pool/SAC effects are sub-invocations.
- `src/rust/src/soroban_invoke.rs:7-38` — C++ calls dispatch to the protocol-specific Soroban host module based on ledger protocol.
- `src/rust/src/soroban_proto_any.rs:310-352` and `391-488` — apply-mode Rust bridge catches panics, builds budget/host inputs, invokes the host, then extracts return value, events, modified ledger entries, and rent fee.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — `e2e_invoke::invoke_host_function` builds enforcing storage, auth, ledger info, module cache, and calls `host.invoke_function(host_function)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:42-49` — only `SOROSWAP_POOL_WASM_HASH` and pool TTL constants are defined; there is no router hash or manifest constant.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` performs pool getter/swap matching for the allowlisted pool hash and otherwise falls through to `instantiate_vm` and `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1375` and `1465-1528` — native pool swap semantics and SAC subcalls exist, but they are entered only after the callee is already identified as the pool contract.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1890` — `call_n_internal` enforces reserved-function, reentry, diagnostics, and then calls `call_contract_fn`; top-level `InvokeContract` uses this same generic path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2591-2624` — Wasm `call` imports also unpack arguments and call `call_n_internal`, so router-to-pool calls made by router Wasm reach the pool-native path only through the generic host-call boundary.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — Wasm contract execution still enters `Vm::invoke_function_raw` for unmatched Wasm contracts, including the router.

### Why It Failed

This exact optimization class has already been investigated and rejected: prior records explicitly include a manifest-backed router-native trampoline and exact router swap fast-path variants, and state that a manifest is only a solution if it already exists as a binary-derived, reviewable protocol artifact. This hypothesis restates that requirement but does not provide the artifact, isolated per-router attribution, or the complete next-protocol semantic/metering specification; the checked source still contains no router manifest or native router dispatch surface. Under the objective rules, the prior duplicate and unresolved specification blockers make it NOT_VIABLE at review.

### Lesson Learned

For native Soroswap router bypass proposals, "add a binary-derived manifest" is not itself new evidence or a viable mechanism. A future submission must arrive with the checked-in binary-derived manifest/protocol specification and source-visible dispatch design, plus isolated apply-path attribution for the router frame, before it can be considered distinct from the prior manifest-backed router-native failures.
