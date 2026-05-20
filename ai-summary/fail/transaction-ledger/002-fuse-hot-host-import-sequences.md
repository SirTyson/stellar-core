# H002: Fuse hot wasmi host-import sequences instead of optimizing individual dispatch calls

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban VM host-call execution
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by amortizing wasmi-to-host boundary work across repeated imported host-function sequences in router/pair contract execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap Wasm execution must call the same host functions in the same observable order, produce the same ledger reads/writes/events, preserve the same trap/error points, and charge deterministic resource budgets. On a next-protocol path, if the module translator can prove a short sequence of imported host calls is adjacent and stack-compatible, it should be possible to replace that sequence with one fused host import that performs the same checks and sub-operations in order while paying the VM/host boundary overhead once.

## Mechanism

The current `vm/dispatch.rs` macro crosses the wasmi-to-host boundary for every imported host function: clone the host handle, check protocol bounds, optionally trace args, return fuel to the host, charge dispatch, marshal relative object handles into host values, construct `VmCaller`, run the host function, augment errors, marshal the result back to relative Wasm values, and refill fuel. Prior dispatch hypotheses targeted this per-call wrapper or generic interpreter dispatch individually and were below threshold or regressed. A different redesign would identify frequent bytecode/import sequences in the parsed soroswap router/pair modules, such as storage `has`/`get` pairs or small vector/map construction chains, and install deterministic fused imports that execute the same component host functions internally while reducing the number of full import-boundary round trips.

## Trigger

Run the current soroswap Tracy benchmark from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
The router and pair contracts execute through `Host::invoke_function` under `applyLedger`, repeatedly crossing `vm/dispatch.rs:304` for host imports during every swap.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` - parsed-module construction is the deterministic place to inspect import-call bytecode patterns and attach a fused-call plan to cached modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs@fa1226b3:393-412` - `Vm::invoke_function_raw` prepares Wasm arguments and enters wasmi for every contract function call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs@fa1226b3:205-285` - generated host imports pay the per-import fuel, dispatch, argument-marshalling, `VmCaller`, error-context, result-marshalling, and fuel-refill path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1693-1755` - map host functions are representative small operations that are often called in chains from contract code.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-540` - storage `get`/`has`/`put`/TTL helpers are representative Soroswap-heavy imports where adjacent host-call fusion could amortize boundary work without changing storage semantics.

## Evidence

- Timestamp-filtered current-trace events inside `applyLedger` show `call,soroban-env-host/src/vm/dispatch.rs:304` totaling **9,353,235,883 ns** over **40,605** host-import calls, and `Vm::invoke_function_raw,soroban-env-host/src/vm.rs:400` totaling **12,842,366,133 ns** over **20,313** contract-function calls. These are aggregate worker totals, but the host-import boundary remains one of the few remaining Medium-sized apply descendants after prior storage and SAC optimizations.
- The self-time CSV also reports `call` at **922,554,179 ns self-time**, plus many small imported functions (`vec_new_from_linear_memory`, `has_contract_data`, `get_contract_data`, `bytes_append`, `vec_get`, `storage put`, `contract_event`) that are individually below threshold but share the same import-boundary wrapper.
- The mechanism is intentionally different from rejected low-overhead dispatch trampolines, fuel synchronization, export-handle caching, and wasmi superinstructions. Those kept the same number of host imports and tried to make each crossing cheaper; this proposal reduces the number of crossings for statically recognized host-call sequences while leaving component host functions and deterministic ordering intact.
- The approach does not require audited Soroswap source or native contract precompiles. It operates on parsed Wasm/import metadata already present in the module cache, so opaque vendored Wasm binaries can still be transformed deterministically by all nodes.

## Anti-Evidence

- Prior `wasmi-superinstruction-dispatch` regressed, so a PoC must first add counters for exact fused sequence frequency and avoid adding per-instruction pattern-match overhead to the unfused path.
- Host calls are observable through traps, diagnostics, metering, relative-object translation, and storage side effects. A fused import must preserve intermediate failure behavior and either reproduce or protocol-gate the combined `DispatchHostFunction`, fuel, and argument-conversion charges.
- If hot sequences are not adjacent in the actual translated router/pair bytecode, or if the removable boundary work is dominated by the component host functions themselves, the idea collapses to the already rejected per-call dispatch micro-optimizations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - related dispatch/fuel/superinstruction hypotheses were previously investigated, but this exact host-import sequence-fusion mechanism was not.
**Failed At**: reviewer

### Trace Summary

The apply path reaches Soroban Wasm execution through `LedgerManagerImpl::applyThread`, `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, the C++/Rust `invoke_host_function` bridge, `Host::invoke_function`, `Host::call_n_internal`, and then `Vm::invoke_function_raw`. Every imported host function is linked individually from the module's declared import set to a generated wasmi `func_wrap` trampoline, and each guest import call enters `vm/dispatch.rs` for fuel return, `DispatchHostFunction` charging, relative object conversion, `VmCaller` construction, component host-function execution, result conversion, error escalation, and fuel refill. The inefficiency exists, but the only portion sequence fusion could remove is a subset of the per-import wrapper self-time; the component storage/map/vector work and most semantic checks must still run in the same order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` - parallel Soroban worker applies each transaction in a cluster and commits successful effects.
- `src/transactions/TransactionFrame.cpp:2385-2430` - parallel Soroban transaction dispatches its single operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` - C++ apply helper serializes inputs and calls `rust_bridge::invoke_host_function` with the shared module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1367-1377` - protocol 23+ parallel apply uses `InvokeHostFunctionParallelApplyHelper::apply`.
- `src/rust/src/soroban_proto_any.rs:310-354` - Rust bridge catches host panics and invokes the protocol-specific host implementation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:430-480` - enforcing-mode host is built from footprint/storage inputs and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1147` - `HostFunction::InvokeContract` converts the contract address, function name, and arguments before entering `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-987` - `call_n_internal` enforces reserved-function and reentry rules before dispatching to the contract implementation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` - Wasm contracts instantiate a VM and call `Vm::invoke_function_raw` inside a VM frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` and `393-412` - `invoke_function_raw` converts top-level args and `metered_func_call` supplies/returns fuel around wasmi execution.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:42-80` and `118-150` - linker entries are generated only for host functions the Wasm module already imports.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:212-268` and `289-319` - parsed modules validate and compile Wasm, then create a linker from the module's import symbols; no bytecode rewrite or fused-call plan is represented.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` - each generated import wrapper performs the required boundary, metering, conversion, call, trap, and fuel-refill work.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2265` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-429` - storage `has`/`get` share lower-level storage lookups, but their host-call observability and error behavior remain per-call.

### Why It Failed

The current architecture cannot "install" a fused import from `ParsedModule` alone: wasmi links only the imports declared by the guest module, so reducing guest import-call count would require rewriting Wasm function bodies and function indices or modifying wasmi's interpreter/compiler. That is no longer a local parsed-module/cache attachment; it is a bytecode transformation with the same unfused-path and determinism risks as the previously rejected superinstruction work.

More importantly, the claimed Medium impact is not supported after normalizing to removable work. The hypothesis's own self-time for the generated import wrapper is about 0.923s aggregate across 40,605 calls, or roughly 22.7 microseconds per import before accounting for cluster parallelism and before preserving mandatory work. A correct fused sequence must still perform the component host functions, their storage/object checks, relative-object integrity checks, intermediate failure/trap points, diagnostic behavior, and deterministic metering. Even deleting the entire wrapper self-time, which is impossible, is below the objective's 3% Medium floor after parallel-cluster normalization; deleting only adjacent-call boundary overhead is smaller still.

### Lesson Learned

Inclusive `vm/dispatch.rs` import-call totals should not be treated as removable boundary overhead. Future VM-import hypotheses need exact static/dynamic sequence counters plus critical-path-normalized self-time for operations that can actually be removed while preserving per-host-call traps, diagnostics, object translation, and metering.
