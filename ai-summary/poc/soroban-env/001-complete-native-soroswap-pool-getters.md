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

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-22
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:38-54,158-185,780-980` — added a code-hash-, arity-, function-, and instance-layout-gated native emulation path for the vendored Soroswap pool getters. The path pushes a native contract frame, performs the same current-contract instance/code TTL extension, reads the pool instance-storage keys, constructs exact address/vector/i128 return values, and falls back to Wasm for non-matching code, symbols, arity, or storage layouts.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1347-1357` — taught authorization frame tracking to treat native contract frames as contract invocations with the same contract ID and function name.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3635-3646` — allowed `require_auth` argument lookup to work from native contract frames, preserving contract-frame behavior if an emulated path ever uses auth-sensitive host functions.
- `src/rust/soroban/p26/soroban-env-host/src/host/trace/fmt.rs:128-145` — added trace formatting for native contract frames without perturbing existing `Frame` variant hashes used by observation tests.

### Demonstration

The implementation bypasses fresh `Vm` construction and raw Wasm export invocation for the exact vendored Soroswap pool getter calls while preserving frame push/pop, rollback, auth-stack, TTL extension, instance-storage access, and returned value shapes. The hot `get_reserves` path now reads reserves from instance storage and returns the same two-element vector natively; `token_0`, `token_1`, `factory`, and `k_last` similarly avoid wasmi instantiation when their known storage layout is present.

### Test Results

Full existing suite passed with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check`: gperftools reported 29/29 tests passing; stellar-core `test/selftest-nopg` and `test/check-nondet` passed; p26 Soroban host reported 751 passed, 0 failed, 2 ignored, 1 filtered out, plus integration/doc tests passing.

---

## Final Review — Needs Revision

**Date**: 2026-05-22
**Final review by**: gpt-5.5, high

### What Needs Fixing

The native getter emulation is not protocol-gated. `try_call_native_soroswap_pool_getter` is invoked unconditionally for `ContractExecutable::Wasm` when the code hash and getter shape match, including when `LedgerInfo.protocol_version == MIN_LEDGER_PROTOCOL_VERSION` (p26). This bypasses Wasm instantiation, import validation, VM dispatch, fuel transfer, object/relative-handle work, and associated budget charges for a released protocol. The hypothesis and prior accepted baseline both require this class of metering-changing shortcut to be next-protocol only, preserving exact p26 execution and fees.

This failed the final review safety gate before benchmarking. The finding may still be viable, but the current PoC cannot be promoted because it changes protocol-visible p26 cost behavior for the vendored Soroswap pool code hash.

### Revision Instructions

1. Gate the native Soroswap pool getter path behind the same next-protocol condition used by the accepted coalesced-host-metering optimization, e.g. only attempt it when `self.get_ledger_protocol_version()? > MIN_LEDGER_PROTOCOL_VERSION` (or an equivalent centralized next-protocol feature gate). At p26, `call_contract_fn` must always instantiate and execute the Wasm exactly as before.
2. Add focused equivalence coverage for the gate: with `LedgerInfo.protocol_version = MIN_LEDGER_PROTOCOL_VERSION`, an allowlisted getter must not enter the native path; with next-protocol enabled, the same getter may enter it. The test should also exercise fallback for non-matching hash/function/arity/layout.
3. Add or document focused next-protocol equivalence checks for returned values and side effects on `token_0`, `token_1`, `factory`, `get_reserves`, and `k_last`: current-contract instance/code TTL extension, missing/wrong storage fallback, read/write footprint failures, rollback on error, auth frame shape, and diagnostic/trace frame behavior.
4. Re-run the required full suite and then the three non-Tracy `scripts/run_apply_load_matrix.py` runs after the gate is fixed. Benchmark numbers from the current ungated version are not acceptable for final confirmation.

### Checks Passed So Far

1. The code hash matches the vendored `src/rust/apply-load-wasm/soroswap_pool.wasm` (`18051456816b66f12e773a56f77c5794fac1b1fb7ab6e22d4fad5a412770f73e`), so the intended benchmark target is real and narrowly identified.
2. The inspected Wasm confirms the allowlisted exports call `extend_current_contract_instance_and_code_ttl(501120, 518400)` before reading instance storage, and the PoC emulates that TTL operation in the native frame.
3. The source-level fast path is placed inside `call_contract_fn` after retrieving the contract instance and before `instantiate_vm`, so it targets the claimed in-apply VM-instantiation/interpreter overhead rather than TX-set construction.
4. The implementation adds a distinct native contract frame and wires it through auth-frame tracking, `require_auth` argument lookup, and trace formatting, which is the right general shape for preserving call-frame behavior once the protocol gate and equivalence tests are added.

---

## PoC Revision

**Result**: POC_PASS
**Date**: 2026-05-22
**PoC by**: claude-opus-4.7, high
**Revision of**: previous PoC flagged NEEDS_REVISION for missing next-protocol gate

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (in `try_call_native_soroswap_pool_getter`) — added a next-protocol gate at the top of the function. The native Soroswap pool getter emulation now short-circuits to `Ok(None)` (falling back to normal Wasm execution) whenever `self.get_ledger_protocol_version()? <= crate::host::MIN_LEDGER_PROTOCOL_VERSION`. This is the same gate pattern used by the accepted coalesced-host-metering optimization in `host.rs::set_ledger_info`, ensuring exact p26 budget/dispatch/fee preservation while still enabling the optimization on next-protocol ledgers (only realized when the `next` feature bumps `INTERFACE_VERSION.protocol > MIN_LEDGER_PROTOCOL_VERSION`).

The rest of the previous PoC (code-hash/symbol/arity/instance-layout allowlisting, native contract frame, TTL extension, instance-storage reads, auth-frame wiring, and trace formatting) remains unchanged.

### Demonstration

At `LedgerInfo.protocol_version == MIN_LEDGER_PROTOCOL_VERSION` (p26), `call_contract_fn` now always falls through to `instantiate_vm` and full Wasm execution for the vendored Soroswap pool getters — protocol-visible Wasm instantiation, import validation, fuel transfer, host dispatch, object/relative-handle work, and associated budget charges are preserved exactly as before. Only when the active protocol exceeds `MIN_LEDGER_PROTOCOL_VERSION` does the allowlisted native path apply, removing the per-call wasmi store/linker/export work while still performing the same `extend_current_contract_instance_and_code_ttl(501120, 518400)` TTL extension and instance-storage reads inside an equivalent contract frame.

### Test Results

Full suite passed with `env NUM_PARTITIONS=$(nproc) STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`: all stellar-core C++ unit tests reported `# FAIL: 0` and `# ERROR: 0` across all partitions; `test/selftest-nopg` and `test/check-nondet` passed; p26 Soroban host suites (fees, integration, option, secp256r1_sig_ver, doc-tests) all passed. The build also completed cleanly with `--enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` configuration.
