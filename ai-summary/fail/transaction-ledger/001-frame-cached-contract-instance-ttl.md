# H001: Reuse the current frame's contract instance when extending current contract code TTL

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban host frame storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing redundant enforcing-storage lookups on current-contract TTL extension
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a contract is executing, the host frame already owns the current contract's `ScContractInstance` because `Host::call_contract_fn` loads it before pushing `Frame::ContractVM` or `Frame::StellarAssetContract`. A current-contract TTL extension should reuse that frame-local instance/executable to decide whether a code TTL key must be extended, and should not reload the same instance ledger entry from enforcing storage solely to recover `ContractExecutable`.

## Mechanism

`Host::extend_current_contract_instance_and_code_ttl` builds the current contract instance key, extends the instance TTL, and then calls `extend_contract_code_ttl_from_contract_id`. That helper immediately calls `retrieve_contract_instance_from_storage(&instance_key)` even though the active frame already contains the same instance loaded at `Host::call_contract_fn`. The actual behavior therefore adds an extra enforcing-storage `get`, map lookup, `Rc` clone, and `ScContractInstance` clone to every current-contract TTL extension; in soroswap this is hit by router, pair, and SAC entry points inside each swap.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each Soroban swap enters `applyLedger -> applyParallelPhase -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply -> invoke_host_function`. Guest contracts and SAC builtins call `extend_current_contract_instance_and_code_ttl`, which enters `host.rs:2320-2334` and then reloads the current instance in `data_helper.rs:247-264` for code-TTL classification.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — loads `instance` before pushing the contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` — current-contract instance+code TTL extension call site.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-264` — reloads the current instance to inspect `executable`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:113-120` — enforcing-storage `get` and instance extraction.

## Evidence

Timestamp-filtered Tracy on the current soroswap trace confirms these zones are inside `applyLedger`: `extend_current_contract_instance_and_code_ttl` totals 586.029 ms at `soroban-env-common/src/vmcaller_env.rs:270` plus 374.663 ms at generated dispatch `vm/dispatch.rs:304`; `storage get` totals 641.711 ms, `map lookup indexed` 543.656 ms, and `map lookup` 580.114 ms in the same apply windows. Source inspection shows the current frame has already loaded `instance` before dispatching the contract body, while the TTL helper reloads it only to branch on `ContractExecutable::Wasm` vs `StellarAsset`.

## Anti-Evidence

Prior SAC-only code-TTL and current-contract TTL coalescing attempts were below threshold when scoped to a single SAC retrieval. This hypothesis is broader: it targets all current-contract code-TTL extensions on the router/pair Wasm path as well as SAC, and it should be implemented as a frame-local descriptor lookup rather than as another per-SAC fast path. Correctness requires preserving instance TTL extension itself, code TTL extension for Wasm contracts, no-op behavior for `ContractExecutable::StellarAsset`, and exact storage-error decoration when the frame lacks an instance.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to prior fail-summary entries `006-coalesce-current-contract-instance-ttl-extend.md` and `020-skip-sac-code-ttl-instance-retrieval.md`, but not a duplicate because this variant targets the generic current-frame descriptor for Wasm and SAC frames rather than only SAC/coalescing.
**Failed At**: reviewer

### Trace Summary

The close-ledger path runs Soroban transactions through `LedgerManagerImpl::applySorobanStageClustersInParallel`, where each cluster worker calls `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, constructs an enforcing host, and invokes the host function. Contract entry dispatch in `Host::call_contract_fn` loads the contract instance from storage and stores it in `Frame::ContractVM` or `Frame::StellarAssetContract`. When guest code or SAC builtins call `extend_current_contract_instance_and_code_ttl`, the host extends the instance TTL and then calls `extend_contract_code_ttl_from_contract_id`, which reloads the same instance entry from enforcing storage only to inspect `ContractExecutable`.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — cluster worker loop applies every Soroban transaction on the apply critical path and commits successful effects.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — parallel apply launches cluster workers with `std::async` and waits for all futures, so per-invocation host work contributes to apply time after cluster normalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ invoke-host-function operations enter `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — each operation calls `rust_bridge::invoke_host_function` with host-function, footprint, ledger-entry, TTL-entry, and module-cache inputs.
- `src/rust/src/soroban_invoke.rs:7-38` — the C++ bridge dispatches to the protocol-specific Rust host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:424-481` — enforcing host setup completes and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-170` — both `Frame::ContractVM` and `Frame::StellarAssetContract` carry an `ScContractInstance`, and `Frame::instance` exposes it internally.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` loads the instance from storage before pushing the contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` — current-contract TTL extension builds the current instance key, extends the instance TTL, then delegates code TTL classification to a helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:113-120` — `retrieve_contract_instance_from_storage` performs an enforcing `Storage::get` and clones the `ScContractInstance`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-264` — `extend_contract_code_ttl_from_contract_id` reloads the instance and branches on `ContractExecutable::Wasm` vs `StellarAsset`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2541-2561` — `update_current_contract_wasm` can update the current contract's executable in storage during the frame, so a naive frame-cache lookup would become stale unless the frame descriptor is also updated or guarded.

### Why It Failed

The inefficiency exists, but it does not clear the objective's Medium severity floor. The cited `extend_current_contract_instance_and_code_ttl` and generated-dispatch Tracy totals are inclusive of mandatory host/VM dispatch, current-contract-id lookup, instance key construction, instance TTL extension, and Wasm code TTL extension; the proposed change removes only the second instance-entry storage read used for executable classification. Even optimistically treating the entire cited current-TTL zones as removable yields a sub-3% ceiling after dividing aggregate worker time by the configured cluster parallelism, and the actually removable `Storage::get`/clone subset is materially smaller. Prior quantified fail-summary entries for the narrower SAC/current-contract TTL variants already place one such storage retrieval in the ~0.1-0.5% apply-time range, and expanding the lookup source to the generic frame does not change the per-call cost enough to reach the 3-10% Medium band.

There is also a correctness constraint that the hypothesis does not handle: `update_current_contract_wasm` reloads and rewrites the current instance executable in enforcing storage while the active frame still holds the instance loaded at frame entry. Reusing `Frame::instance` blindly would extend the old executable's code TTL after a self-update, whereas the current code reloads storage and observes the new executable. A correct implementation would need to update or invalidate the frame-local executable descriptor on self-update, further narrowing the simple fast-path and adding review risk for a below-threshold optimization.

### Lesson Learned

Frame-local state can identify redundant host storage lookups, but current-contract executable lookups are not automatically immutable for the full frame lifetime. Before promoting a TTL-extension optimization, isolate the exact removable `Storage::get` self-time rather than inclusive host-function or generated-dispatch zones, divide aggregate worker time by cluster parallelism, and account for self-update semantics that can make frame-entry metadata stale.
