# H002: Protocol-gated code-hash native precompiles for soroswap router and pair contracts

**Date**: 2026-05-02
**Subsystem**: transaction-ledger / Soroban VM execution
**Severity**: High
**Impact**: Soroswap apply-time reduction by bypassing Wasm interpretation for known hot soroswap contract code hashes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a contract instance's executable Wasm hash matches a protocol-approved native precompile for the soroswap router or pair contract, Core should execute a native Rust implementation that is bit-for-bit equivalent to the approved Wasm for ledger reads/writes, authorization, events, diagnostics, return values, and resource accounting under that protocol. Contracts with any other code hash must continue through the existing wasmi path. The dispatch decision must depend only on ledger state, protocol version, and the exact Wasm hash, so every node observes the same execution path and ledger output.

## Mechanism

The current production host has only two fast execution classes: `ContractExecutable::StellarAsset` dispatches the built-in SAC natively, while all `ContractExecutable::Wasm` contracts instantiate a `Vm` and call wasmi. The soroswap workload repeatedly executes a small fixed set of router and pair Wasm contracts; these dominate the VM envelope and mostly orchestrate storage reads, arithmetic, and SAC calls. A protocol-gated precompile registry keyed by exact Wasm hash could route those known contracts to audited native implementations, using the same frame/auth/storage/event APIs as Wasm execution but avoiding wasmi instantiation, interpreted guest execution, VM import dispatch, linear-memory argument decoding, and fuel shuttling.

This is a dominant-phase redesign rather than a local micro-optimization. In the accepted applyLedger-filtered trace, the Wasm/Soroban worker path accounts for most of the measured apply window: `Vm::invoke_function_raw` totals 11,517,335,816 ns over 15,229 events, `call` totals 8,072,233,108 ns over 30,432 events, `Vm::instantiate_wasmi` totals 1,229,493,688 ns, and `Host::invoke_function` totals 8,839,505,342 ns inside `applyLedger`. Bypassing the router/pair Wasm layer while preserving SAC/native storage behavior would materially restructure the dominant Soroban execution phase and plausibly exceed the High threshold for the soroswap benchmark.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Transactions that invoke the benchmark's router/pair Wasm code hashes should dispatch through the new precompile registry instead of `Vm::invoke_function_raw`; all other contracts and non-matching soroswap versions should remain on the existing Wasm path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the contract instance and dispatches either `ContractExecutable::Wasm` through `instantiate_vm`/`invoke_function_raw` or `ContractExecutable::StellarAsset` through native `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-name checks, reentry checks, diagnostics, and then enters the Wasm or native contract dispatch path.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — `Vm::metered_func_call` resolves and executes a Wasm export with wasmi fuel synchronization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:50-63` and `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs:337-385` — test-only `ContractFunctionSet` / native contract registration demonstrates an existing native-contract frame shape, but it is compiled out and not protocol-safe today.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:629-650` — `is_test_contract_executable` uses an executable marker to select test-native dispatch; a production precompile must instead key off protocol-approved Wasm hashes to avoid ledger-entry format changes.

## Evidence

- Timestamp filtering confirms the targeted execution zones are descendants of `applyLedger`, not transaction-set construction: `Vm::invoke_function_raw` totals **11.517 s**, `call` totals **8.072 s**, `Vm::instantiate_wasmi` totals **1.229 s**, and `Host::invoke_function` totals **8.840 s** aggregate worker time inside the 70 apply windows.
- Production code already has a deterministic native dispatch precedent for `ContractExecutable::StellarAsset`, and test builds already have a `ContractFunctionSet` frame abstraction for native Rust contract calls. The missing piece is a protocol-approved production registry keyed by exact Wasm hash, not a new nondeterministic execution mechanism.
- Prior rejected hypotheses targeted SAC micro-optimizations, host-dispatch trampolines, or wasmi instantiation caches. This hypothesis bypasses the user-contract Wasm interpreter for approved hot code hashes and therefore attacks a much larger part of the soroswap critical path.

## Anti-Evidence

- This is a major protocol and maintenance commitment, not a small optimization. The native implementation must be audited against the exact approved Wasm, including edge-case errors, event ordering, auth tree shape, diagnostics, storage footprint behavior, and budget/resource totals.
- It only helps workloads using the approved soroswap code hashes. If production soroswap deployments are not code-hash stable, or if the benchmark's contracts are not representative of deployable protocol precompiles, the scope may be too narrow.
- Exact metering compatibility may be infeasible without a protocol-gated cost-model change. A native precompile that is faster but charges different CPU/memory could alter borderline resource-limit behavior unless the protocol deliberately defines the new charges.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge into p26 `invoke_host_function`, and calls `Host::invoke_function` for each invoke-host-function operation. `HostFunction::InvokeContract` reaches `call_n_internal`, which performs reserved-name and reentry checks, then production `call_contract_fn` dispatches `ContractExecutable::Wasm` only by instantiating a `Vm` and calling `Vm::invoke_function_raw`; the only production native fast path is `ContractExecutable::StellarAsset`. The soroswap benchmark uploads bundled router and pool Wasms, stores their SHA-256 hashes as code keys, and every generated swap invokes the router with router and pair code in the footprint, so a hash-keyed native router/pair dispatch would run on the measured apply path and bypass the wasmi envelope for the benchmark's hot user contracts.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ apply helper serializes the invoke inputs and calls `rust_bridge::invoke_host_function`; this is inside operation apply, not transaction-set construction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban operations execute through `InvokeHostFunctionOpFrame::doParallelApply` in the parallel apply phase.
- `src/rust/src/soroban_proto_any.rs:391-505` — bridge creates the p26 `Budget`, calls `invoke_host_function_with_trace_hook_and_module_cache`, then reads CPU/memory/time metrics and extracts ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — p26 host builds enforcing storage, installs the module cache, calls `Host::invoke_function`, then computes ledger changes and events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts invoke args, calls `call_n_internal`, and converts the result back to `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` enforces reserved-name and reentry rules before delegating to `call_contract_fn`; the test-native path is compiled only under `test`/`testutils`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-900` — production dispatch sends every `ContractExecutable::Wasm(wasm_hash)` through `instantiate_vm` and `vm.invoke_function_raw`; only `ContractExecutable::StellarAsset` calls a native `BuiltinContract`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-217` — VM construction instantiates wasmi, links imports, checks protocol imports, sets up store/memory, and charges instantiation cost.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345,393-412` — each Wasm function call translates host values to relative wasmi values, resolves the export, refills/returns fuel, calls wasmi, and translates the return value back.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every VM-to-host import returns fuel to the host, charges dispatch, converts relative values, invokes the host function, converts the result, and refills VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs:337-385` — test-only native contracts demonstrate a native frame shape but are marked by empty-Wasm test executables and are not production-safe.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:629-650` — test-native selection keys off the hash of empty Wasm; a production precompile must instead key off exact approved hashes without changing ledger entry format.
- `src/rust/src/soroban_test_wasm.rs:122-138` — the apply-load soroswap factory, pool, and router Wasms are bundled with `include_bytes!`, giving stable benchmark code bytes.
- `src/simulation/ApplyLoad.cpp:2855-2913` — setup uploads the bundled factory, pair/pool, and router Wasms and records their SHA-256 hashes as `CONTRACT_CODE` keys.
- `src/simulation/ApplyLoad.cpp:3006-3034,3079-3210` — setup deploys the router by `ContractExecutable::Wasm(router hash)` and creates pairs using the pair Wasm hash.
- `src/simulation/ApplyLoad.cpp:3381-3505` — each measured soroswap swap invokes router function `swap_exact_tokens_for_tokens`, includes router code and pair code in the footprint, and touches the pair instance and SAC balance keys.
- `ai-summary/CURRENT_STATE.md:39-78` — accepted non-Tracy soroswap baseline averages 278.740030 ms; the Medium floor is about 8.4 ms and the High numeric floor is about 27.9 ms.

### Findings

The inefficiency exists and is in the hot path. Production p26 has no code-hash native dispatch for user Wasm: `ContractExecutable::Wasm` always attempts module-cache lookup or storage retrieval, instantiates a per-call `Vm`, marshals arguments through relative handles, executes wasmi, and crosses the generated VM dispatch layer for host imports. The soroswap benchmark's steady-state swap path repeatedly invokes exactly the bundled router and pool/pair Wasms, with code hashes derived from stable `include_bytes!` payloads during setup; a registry keyed by those hashes and protocol version would be deterministic.

The proposed fix is conceptually correct only if treated as a protocol-gated native precompile, not as a transparent local cache. The native implementation must define protocol-visible budget charges, errors, auth invocations, event order, diagnostics, storage accesses, and return values for the approved hashes; exact old metering compatibility is unlikely, but a protocol-gated cost-model change is acceptable for a precompile-style redesign. The existing SAC native path proves production native dispatch can use the same `Host` storage/auth/event APIs, while the test-native path shows an alternate frame shape but cannot be reused directly because it is compiled out and uses the empty-Wasm marker.

The severity is Medium rather than High on the available objective baseline. The cited `Vm::invoke_function_raw` aggregate is 11.517 s over 70 apply windows; normalized by eight configured clusters this is roughly 20.6 ms per ledger before subtracting mandatory native-equivalent work. Adding avoidable wasmi instantiation and VM import/marshalling overhead plausibly clears the objective's 8.4 ms Medium floor, but the available normalized data does not prove a reproducible >27.9 ms top-line reduction on the authoritative non-Tracy soroswap median. The change is still a large, real, benchmark-hot redesign and should proceed to PoC under the objective's Medium-or-higher acceptance rule.

### PoC Guidance

- **Target code**: Add a protocol-gated lookup before the `ContractExecutable::Wasm` branch instantiates a VM in `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784`. Implement the native registry/dispatcher in a new p26 host module, keyed by exact router and pool Wasm hashes from `src/rust/apply-load-wasm/soroswap_router.wasm` and `src/rust/apply-load-wasm/soroswap_pool.wasm`, and leave all non-matching hashes on the existing wasmi path.
- **Change description**: Native router/pair calls should push a production frame that preserves contract ID, function name, args, instance storage, rollback behavior, diagnostics, auth tracking, events, and storage footprint enforcement. Do not reuse the empty-Wasm test-contract marker; the ledger entry must remain `ContractExecutable::Wasm(hash)` so the dispatch decision is deterministic from protocol version plus ledger state.
- **Correctness check**: Existing Soroban host, auth, storage, SAC, and invoke-host-function tests cover much of the shared host machinery, but the PoC needs focused equivalence checks against the bundled soroswap Wasms for successful swaps, liquidity setup, missing/invalid functions, deadline and slippage failures, auth tree shape, event ordering, diagnostics, storage changes, and budget/resource-limit behavior under the new protocol gate.
- **Benchmark focus**: Run the current `soroswap, TX=2000, T=8` matrix from `ai-summary/CURRENT_STATE.md` repeatedly. The expected improvement should appear as lower top-line apply time, with Tracy attribution showing large reductions in `Vm::invoke_function_raw`, `Vm::instantiate_wasmi`, and generated VM dispatch `call` zones for router/pair calls while SAC/native storage zones remain present.
