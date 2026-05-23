# H002: Typed native Soroswap pool frame state

**Date**: 2026-05-23
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce residual native-pool frame setup, instance clone, and instance-storage map churn during soroswap swap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The accepted native Soroswap pool getter/swap path should avoid Wasm execution while preserving the same contract ID, frame/auth context, event order, storage writes, and next-protocol metering boundary. Once a call has been proven to target the allowlisted pool Wasm and a supported export, the native frame should carry only the state needed by that native export and should not clone or repeatedly re-parse the same small instance-storage map.

## Mechanism

`call_contract_fn` retrieves a full `ScContractInstance`, then the native getter/swap probes borrow it for shape checks but construct `Frame::NativeContract` with `instance.metered_clone(self)?`. The swap path then repeats instance-storage lookups for token/reserve keys that were just validated, and reserve updates rebuild the small `MeteredOrdMap` twice. A typed native-pool frame/state object that is created only after the hash/function/argument gate succeeds could move or shallow-share the already-retrieved instance, extract token/reserve `Val`s once, and update both reserves through a single specialized small-map replacement while keeping all externally visible behavior unchanged.

## Trigger

Run the current soroswap apply-load benchmark with protocol 27 enabled so the native pool getter/swap path is active. A PoC should restructure only the accepted native pool path: keep generic Wasm fallback untouched, preserve `Frame` ordering and rollback behavior, but avoid the successful-native-path `ScContractInstance` clone and repeated key scans/lookups. Measure three non-Tracy soroswap runs against the current 215-222 ms median baseline.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:179-199` — `Frame::NativeContract` stores a full `ScContractInstance` just like VM/SAC frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `call_contract_fn` builds `args_vec` and probes native getter/swap before falling back to VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872` — native getter path validates instance storage and then clones the full instance into the frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native swap path validates token/reserve shape and then clones the full instance into the frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native swap re-reads token/reserve values and updates reserves through two `MeteredOrdMap::insert` calls.

## Evidence

In the current trace, apply-contained native/Soroban frame support zones remain material after the accepted direct-balance optimization: `push context` accounts for 47,163 in-apply events / 457.761 ms aggregate, `new map` for 181,114 events / 461.915 ms aggregate, and `map lookup`/`map lookup indexed` together exceed 1.07 s aggregate. The accepted native pool path is now a first-class soroswap hot path, so reducing its residual generic frame/instance-storage work targets repeated work on successful swaps rather than speculative fallback behavior.

## Anti-Evidence

These Tracy zones also include SAC transfer frames, VM frames, metering, and unrelated map operations, so the removable native-pool slice must be isolated before implementation. Prior native-bypass variants failed on incomplete semantic/metering specifications; this hypothesis is narrower because it does not add a new native contract boundary, but it still must preserve rollback, auth-frame, event, and budget-observation behavior exactly.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry for `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md + 001-binary-specified-pool-swap-native-precompile.md + 001-native-soroswap-pool-swap-and-liquidity.md + 002-fuse-native-soroswap-sac-subcalls.md + 002-inline-native-pair-sac-balance.md + 001-raw-native-pair-instance-storage.md`
**Failed At**: reviewer

### Trace Summary

The live soroswap apply path enters C++ `InvokeHostFunctionOpFrame`, crosses the Rust bridge, constructs a fresh enforcing Soroban `Host`, and calls `Host::invoke_function`. For `HostFunction::InvokeContract`, the p26 host reaches `call_contract_fn`; in this checkout every `ContractExecutable::Wasm` retrieves the contract instance, instantiates a VM, pushes a `ContractVM` frame, and invokes Wasm. There is no `Frame::NativeContract`, native pool getter/swap branch, or `call_native_soroswap_pool_swap` implementation in the source being reviewed, so the proposed typed native-pool frame has no concrete target. The same residual instance-storage cleanup is already covered by the retained pool-only native precompile failure family.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:117` — prior retained failure covers pool-only native Soroswap precompile variants, explicitly including residual instance-storage cleanup and the prerequisite absence of a native frame/helper in current source.
- `ai-summary/fail/soroban/summary.md:174-178` — retained lessons require a full native-contract semantic and metering specification before any native Soroswap bypass or sub-optimization proceeds.
- `ai-summary/fail/soroban/002-native-pool-swap-sac-transfer-fusion.md:41-70` — substantially equivalent native-pool sub-optimization rejected as duplicate because it assumes the same absent native pool-swap implementation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — apply serializes auth, resources, ledger entries, and invokes the Rust Soroban host for each transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge creates the per-invocation budget and delegates to the protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — enforcing storage, auth, ledger info, module cache, and `Host::invoke_function` are constructed for the host call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-149` — `Frame` has `ContractVM`, `HostFunction`, `StellarAssetContract`, and test-only variants; no `NativeContract` variant exists.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:749-785` — `call_contract_fn` sends Wasm contracts through VM instantiation and `vm.invoke_function_raw`; only SAC uses a native built-in frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` — instance storage is lazily initialized from the current frame's full `ScContractInstance`, but there is no native-pool-specific typed state path.

### Why It Failed

This is not novel: the retained fail summary already includes a pool-only native Soroswap precompile family with "residual instance-storage cleanup" and the exact prerequisite blocker this hypothesis depends on. The checked-out source also contradicts the target-code premise: it lacks `Frame::NativeContract`, native getter/swap probes, reserve update helpers, and the successful-native-path `ScContractInstance` clone described in the mechanism. Because the supposed hot path does not exist here, and because all native Soroswap pool sub-optimizations still require the unresolved binary-equivalence, event-order, auth-frame, rollback, error/trap, storage-schema, and next-protocol metering specification, this cannot proceed to PoC.

### Lesson Learned

Do not propose residual native-pool frame or instance-storage cleanup until the native pool precompile itself exists in the reviewed source and its full semantic/metering contract has been specified. Narrowing the cleanup to typed frame state does not bypass the retained native Soroswap specification blockers.
