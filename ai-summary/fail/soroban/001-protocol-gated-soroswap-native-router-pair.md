# H001: Protocol-Gated Native Soroswap Router/Pair Fast Path

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: High
**Impact**: >10% soroswap apply-time reduction by bypassing repeated Wasm interpretation for known Soroswap router/pair contracts while preserving SAC/storage effects
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a protocol-defined, hash-gated Soroswap router/pair contract implementation, `closeLedger` should produce the same ledger effects, authorization checks, events, return values, and deterministic budget semantics as executing the matching Wasm bytecode. When the active ledger protocol enables the native path and the contract instance executable/hash matches the approved Soroswap router or pair code hash, the host should call a native `BuiltinContract` implementation instead of instantiating a Wasm VM and dispatching through wasmi. All non-matching code hashes, released p26 ledgers, and simulation/diagnostic compatibility paths should continue to execute the existing Wasm path.

## Mechanism

The current path dispatches every router/pair call through `Host::call_contract_fn`: it retrieves the contract instance, checks `ContractExecutable::Wasm`, calls `instantiate_vm`, pushes a `Frame::ContractVM`, and then invokes `Vm::invoke_function_raw`. The soroswap benchmark is intentionally dominated by those router/pair Wasm calls plus SAC transfers: the current trace shows `Vm::invoke_function_raw` at `12,842,366,133 ns` total across `20,313` calls, generated host-function dispatch `call` at `9,353,235,883 ns` total across `40,605` calls, and `Vm::instantiate_wasmi` at `1,648,211,481 ns` total across `20,389` instantiations, all under the `applyLedger -> applyParallelPhase -> InvokeHostFunctionOpFrame doParallelApply` subtree. A protocol-gated native implementation for the exact router/pair hashes would remove the interpreter, import-dispatch, and per-call VM-instantiation overhead for the headline workload while still using the existing host storage/SAC helpers for ledger-visible state transitions.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) on a next-protocol build. Each transaction invokes `swap_exact_tokens_for_tokens` on the router, uses the router and pair code keys in the read-only footprint, and touches pair-specific SAC balances plus the pair instance. With native hash dispatch enabled for the benchmark's router/pair Wasm hashes, the same transactions should route through the built-in Soroswap implementation instead of `Vm::instantiate_wasmi`/`Vm::invoke_function_raw`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `Host::call_contract_fn` chooses between Wasm and built-in SAC execution; this is the protocol-gated dispatch point for known native Soroswap contracts.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `instantiate_vm` is the cached-module path bypassed for approved native router/pair hashes.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a fresh wasmi store/instance per Wasm call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` marshals args and enters the wasmi function call path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts.rs:11-15` — existing `BuiltinContract` trait surface for adding a native contract implementation.
- `src/simulation/ApplyLoad.cpp:3430-3475` — soroswap benchmark invokes the router and includes router/pair code plus pair state in every swap footprint.

## Evidence

The targeted zones are descendants of `applyLedger`, not TX-set construction: `applyLedger` totals `5,230,315,999 ns`, `applyParallelPhase` totals `3,842,725,964 ns`, and worker-side `InvokeHostFunctionOpFrame doParallelApply` totals `12,664,159,786 ns` in the current soroswap trace. The broad Wasm execution path is the only remaining surface large enough to plausibly clear the Medium/High threshold after prior failures capped bridge, storage-map, budget-tracker, auth-snapshot, and VM-instantiation micro-optimizations below Medium. The design is deterministic if it is protocol-gated and keyed by exact contract code hash: every node either executes the same approved native implementation for the same hash/protocol or falls back to the existing bytecode interpreter.

## Anti-Evidence

This is a substantial protocol feature, not a cleanup patch. The native implementation must exactly match router/pair Wasm semantics for storage keys, authorization trees, events, panic/error behavior, TTL extension, and budget/resource charging, or explicitly define a new next-protocol metering schedule. It is also application-specific: if governance rejects hash-gated native acceleration for a deployed DEX workload, the optimization is not viable even though it targets the dominant soroswap apply cost.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The hot path is real, but the proposed fix is not yet a concrete, correctness-preserving optimization. Current production dispatch has only two executable cases: `ContractExecutable::Wasm` builds a fresh `Vm` and enters `Frame::ContractVM`, while `ContractExecutable::StellarAsset` enters the single production built-in contract path. The native-test-contract path is compiled out of production and is explicitly a best-effort VM emulation for tests, not a reusable proof that arbitrary Wasm contracts can be replaced safely.

The hypothesis also requires exact Soroswap router and pair semantics, but the checked-out tree only contains `soroswap_router.wasm`, `soroswap_pool.wasm`, and `soroswap_factory.wasm` blobs, not a native semantic spec for storage layout, function behavior, emitted events, traps, recoverable contract errors, instance-storage flush behavior, or authorization sub-invocation ordering. Bypassing `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, generated dispatch, fuel transfer, and Wasm instruction fuel also cannot preserve released-protocol budget observations unless the implementation replays the skipped charges, which would erase much of the claimed benefit. A viable version must explicitly be a new-protocol native-metering feature, not "same deterministic budget semantics as executing the matching Wasm bytecode."

Finally, the claimed High severity is not established from the cited aggregate worker totals. Those totals must be normalized by the configured parallel cluster count and apply windows, then reduced by mandatory work that a native implementation must still perform: host storage access, SAC transfers, authorization tracking, frame rollback snapshots, event construction, result/ledger-change extraction, and deterministic budget charges. The remaining removable router/pair Wasm execution may still be Medium or High, but this review could not promote the current hypothesis without an isolated upper-bound measurement and a complete native semantics/metering design.

### Alternative Angle

Refine this into an explicit next-protocol native-contract proposal. The refined hypothesis should define the approved router/pair code hashes, exact function set (`swap_exact_tokens_for_tokens` and any pair functions reached by the router), ABI conversions, persistent and instance storage keys, event order, error/trap mapping, auth-tree behavior, TTL behavior, and a new deterministic metering schedule. It should also introduce a production native-contract frame shape analogous to `Frame::StellarAssetContract` so `AuthorizationManager::push_frame`, `Host::with_frame` rollback, instance-storage persistence, trace hooks, and diagnostics all see the same invocation tree as the Wasm path.

Before PoC handoff, add measurement that bounds only the removable work: router/pair Wasm invocation and VM dispatch time after subtracting SAC/storage/event/output work and normalizing aggregate worker time by `NUM_CLUSTERS`. If that isolated bound is still at least 3% of non-Tracy soroswap apply time, the refined next-protocol feature can be reviewed as Medium/High.

### Additional Code Paths

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-562` — `with_frame` pushes rollback/auth context, handles `Ok(Error)` contract returns, persists instance storage, and rolls back on error; a native Soroswap frame must preserve these semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — production contract dispatch currently chooses only Wasm or SAC built-in execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` enforces reserved names, reentry rules, diagnostics, and then calls `call_contract_fn`; this would be the refined native dispatch entry.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1369` — authorization stack frames are derived from `Frame::ContractVM` or `Frame::StellarAssetContract`; a new native frame must participate identically.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — VM host-function calls drain/refill fuel, charge `DispatchHostFunction`, marshal relative/absolute objects, and augment errors; a native path must intentionally replace this with a new protocol metering model.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:407-521` — bridge invocation builds enforcing storage, runs `Host::invoke_function`, then extracts result, ledger changes, and events; the native path must produce byte-identical ledger-visible outputs.
- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swaps invoke the router, declare router/pair code keys and pair state in the footprint, and authorize the token-in SAC transfer; this is the workload shape a refined proposal must benchmark.
