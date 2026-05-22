# H001: Complete Native Soroswap Pool Getter Emulation

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding fresh wasmi instantiation for allowlisted pool getter exports while preserving their frame, TTL, storage, and metering effects
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the allowlisted Soroswap pool code hash used by apply-load, calls to getter exports such as `token_0`, `token_1`, `factory`, `get_reserves`, and `k_last` should produce the same returned `Val`, ledger TTL changes, errors, auth/call-frame behavior, events, and next-protocol budget accounting as running the Wasm export in a fresh `ContractVM` frame. Mutating exports (`swap`, `deposit`, `withdraw`, `sync`, etc.), unrecognized code hashes, and any getter whose decoded behavior does not match the known pool Wasm must continue through normal wasmi execution.

## Mechanism

The previous pool-getter shortcut failed because the getters are not pure reads: `wasm-tools print src/rust/apply-load-wasm/soroswap_pool.wasm` shows the getter exports call helper func 66, which imports `extend_current_contract_instance_and_code_ttl`, before loading instance-storage fields. A corrected next-protocol fast path would emulate the *complete* getter behavior after pushing the same contract frame: perform the instance/code TTL extension with the same thresholds, run the pool initialized check/storage reads, construct the exact returned address/vector/integer values, and charge a replacement metering schedule for the omitted VM instantiation/interpreter work. This removes the expensive fresh wasmi instantiation and getter bytecode execution for read-only pool calls without skipping their observable side effects.

## Trigger

Run the current `scripts/run_apply_load_matrix.py` soroswap case (`soroswap, TX=2000, T=8`) with the accepted next-protocol baseline. The router repeatedly calls the same pool getters around each swap, and the transaction footprint already contains the pool instance/code entries needed to reproduce getter behavior; the fast path should trigger only for the known pool code hash and the exact getter symbols.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:760-784` — `call_contract_fn` currently instantiates a VM and pushes `Frame::ContractVM` for every Wasm call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `instantiate_vm` uses a cached parsed module but still creates a fresh `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a store, checks imports, and calls `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-280` — complete getter emulation must preserve current-contract instance/code TTL extension.
- `src/rust/apply-load-wasm/soroswap_pool.wasm` (`wasm-tools print`: exports at lines 78-87; helper func 66 calls host import 21; getter funcs 109-111 and 118-119 call func 66) — fixed benchmark Wasm behavior to emulate.

## Evidence

The current accepted soroswap trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Unwrap containment against the 71 `applyLedger` windows confirms the target zones are fully inside apply: `Vm::instantiate_wasmi - instantiate` has 20,389 in-apply events totaling 1,317,542,205 ns, `ParsedModule::check_contract_imports_match_host_protocol` has 20,389 events totaling 229,238,299 ns, and `extend_current_contract_instance_and_code_ttl` has 47,428 in-apply events totaling 960,691,858 ns. `wasm-tools print` confirms the pool has a narrow getter set and that each getter performs the TTL helper before reading storage, giving a concrete emulation contract rather than a speculative pure-read shortcut.

## Anti-Evidence

The dynamic getter call count must be confirmed before PoC; if the router mostly avoids these getters, the removable instantiation subset may fall below Medium. The path is benchmark-specific and must be strictly code-hash/function gated, with a safe fallback on any mismatch. Because bypassing wasmi changes protocol-visible fuel, host-function dispatch, object allocation, and budget charge order, this should be a next-protocol metering change rather than a p26-preserving physical shortcut.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; prior `002-soroswap-pool-getter-fast-path.md` rejected only the pure-read shortcut and identified this complete-emulation variant as the refinement path

### Trace Summary

The apply-load transaction invokes the router's `swap_exact_tokens_for_tokens` with a two-token path and includes the router instance/code, pair code, pair instance, token instances, trustlines, and pair SAC balances in the footprint. The router Wasm computes the pair and calls into the pool `get_reserves` path; the pool getter export then calls helper func 66, which imports `extend_current_contract_instance_and_code_ttl`, before checking initialized instance storage and returning reserve data. In the host, every Wasm call currently retrieves the instance, constructs a fresh `Vm`, pushes a `ContractVM` frame, executes the export, and pops/rolls back or persists through `with_frame`. A code-hash/function-gated native path placed after instance retrieval but before `instantiate_vm` can preserve the frame, TTL extension, storage reads, rollback, diagnostics, and fallback behavior while removing the repeated wasmi store/linker/export execution for these fixed getter exports.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3475` — soroswap swap generation always invokes router `swap_exact_tokens_for_tokens`, uses a two-address path, and places the pair instance in the transaction footprint.
- `src/rust/apply-load-wasm/soroswap_router.wasm` (`wasm-tools print`: funcs 60, 61, 54, 58) — the hot router path has one loop iteration for the two-token path and performs a nested pool `get_reserves` contract call through the host `call` import.
- `src/rust/apply-load-wasm/soroswap_pool.wasm` (`wasm-tools print`: exports 78-87; func 66 at 2723-2728; funcs 109-111 at 5173-5187; func 118 at 6998-7031; func 119 at 7032-7045) — all target getter exports call the TTL helper before returning storage-derived values.
- `src/rust/soroban/p26/soroban-env-common/env.json:1399-1415,1524-1537,1715-1720` — confirms the imported ledger functions are `has_contract_data`, `get_contract_data`, `extend_current_contract_instance_and_code_ttl`, and the call module's `call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1119` — `call_n_internal` performs reserved-name checks, reentry handling, diagnostics, and delegates normal Wasm execution to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — `call_contract_fn` retrieves the current instance, charges/copies args, instantiates a VM for `ContractExecutable::Wasm`, pushes `Frame::ContractVM`, and invokes the export.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-598` — `with_frame` supplies rollback, auth frame push/pop, trace hooks, instance-storage persistence/reload, and frame-exit error normalization that the native getter path must retain.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,393-411` — the removable work includes fresh wasmi store construction, instantiation/import validation, argument relative-object translation, and raw export invocation for each fast-pathed getter call.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2265,2320-2334` — instance-storage `has`/`get` and current-contract TTL extension are existing host operations that can be reused or mirrored by native emulation.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:29-72,247-280` — instance-storage initialization and TTL extension route through existing storage semantics and can fail on the same footprint/TTL conditions.

### Findings

The inefficiency is real and on the apply hot path: cached parsed modules do not avoid per-call wasmi `Store` creation, import validation, linker instantiation, export invocation, and pool-internal host-function dispatch. The refined mechanism fixes the correctness issue from the prior failed pure-read hypothesis by preserving the contract frame first and then reproducing the pool getter's required TTL extension and storage reads. The proposed change is viable only as a next-protocol, code-hash/function allowlist path: p26-compatible exact budget preservation would require replaying enough `InvokeVmFunction`, dispatch, fuel, object-allocation, and storage metering to erase much of the gain and would be fragile.

Severity is Medium rather than High. The definitely hot benchmark path is the nested pool `get_reserves` call for the two-token router path; `token_0`, `token_1`, `factory`, and `k_last` are correct to include for the same code-hash-gated emulation surface, but they should not be assumed to dominate the current swap workload without PoC instrumentation. Retained work includes router execution, mutating `swap`, SAC calls, frame push/pop, TTL/storage semantics, and final value construction, so the expected win is a measurable 3-10% apply-time reduction if the in-trace getter instantiation subset is as large as the surrounding VM/TTL counts suggest.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs::call_contract_fn` and supporting helpers in `host/frame.rs` or a new small module under `soroban-env-host/src/host/`; reuse `host.rs`/`data_helper.rs` storage and TTL helpers rather than duplicating storage semantics.
- **Change description**: after retrieving the `ScContractInstance` and before `instantiate_vm`, check the exact vendored Soroswap pool Wasm hash plus allowlisted getter symbol and arity. Push a frame that provides the same current contract ID, auth/rollback/trace behavior, and instance-storage access as `ContractVM`; then perform `extend_current_contract_instance_and_code_ttl(501120, 518400)`, the initialized/missing-key checks, instance-storage reads, and exact return construction for `token_0`, `token_1`, `factory`, `get_reserves`, and `k_last`. Fall back to normal VM execution on any hash, symbol, arity, storage-layout, or type mismatch.
- **Correctness check**: compare native and Wasm execution for the allowlisted getters on the vendored pool instance, including low-TTL entries that must be extended, missing initialized/storage keys, read-only-vs-read-write footprint failures, `try_call`/non-recoverable error behavior, diagnostics, and returned `ScVal` shapes. Existing frame rollback, storage, TTL, and Soroban invocation tests cover the underlying primitives, but the PoC should add focused equivalence tests for this native getter path.
- **Benchmark focus**: instrument fast-path hit counts by export and report non-Tracy `scripts/run_apply_load_matrix.py` soroswap apply-time deltas across multiple runs. The expected improvement should come from reduced `Vm::instantiate_wasmi`, import-validation, `Vm::invoke_function_raw`, and pool-internal host-dispatch time; if confirmed hits are mostly only one `get_reserves` per swap and the measured median delta is below 3%, fail the PoC under this objective's severity floor.
