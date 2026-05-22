# H002: Static fast stubs for the hot Soroswap wasmi host-import signatures

**Date**: 2026-05-22
**Subsystem**: transaction-ledger / Soroban VM host imports
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing repeated VM-to-host import-boundary overhead without changing contract semantics
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When router and pair Wasm call Soroban host imports during `closeLedger`, every import should still perform the same fuel settlement, protocol-range validation, relative-object translation, argument validation, host-function body, error decoration, and result conversion as today. The efficient path should avoid only repeated generic dispatch scaffolding that is statically known from the imported function signature and protocol gate.

## Mechanism

The current trace shows the remaining Soroswap worker time is dominated by VM execution and import-heavy host calls, not by transaction-ledger C++ setup. Apply descendants include the generated dispatch macro site `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` across hot imports such as `call` (**1.126 s self / 41,943 calls**), `has_contract_data` (**129.745 ms self / 70,029 calls**), `get_contract_data` (**75.449 ms self / 55,944 calls**), `vec_get` (**83.673 ms self / 76,852 calls**), `bytes_append` (**86.253 ms self / 41,968 calls**), and `serialize_to_bytes` (**69.869 ms self / 41,968 calls**). These events occur under `invoke_host_function`, which timestamp filtering confirmed is fully inside `applyLedger`.

`generate_dispatch_functions!` currently emits one general wrapper shape per host function that repeatedly reconstructs the same dispatch context: protocol-gate checks, fuel drain/refill scaffolding, tuple homogenization, relative-object conversion paths, `VmCaller` setup, and result mapping. A protocol-gated static fast-stub table can be generated for the handful of high-count Soroswap imports with their exact signatures and protocol ranges, selecting the stub at linker construction time so the hot path enters a monomorphic function body with preclassified argument/result handling. This differs from a generic low-overhead trampoline: it is signature-specific, parse/link-time selected, and keeps all mandatory checks for that signature while removing dynamic branches that are only needed by the fully generic macro path.

## Trigger

Run the current soroswap apply-load benchmark from `CURRENT_STATE.md`. The trigger is repeated router/pair Wasm execution during each swap, especially nested contract calls and storage/vector/bytes imports emitted by the vendored Soroswap Wasm.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:18-91` — `HostFuncInfo` binds each imported host function into the wasmi linker; this is the selection point for exact-signature fast stubs.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:125-128` — `HOST_FUNCTIONS` is the static host-function table used both for import validation and linker wrapping.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:148-304` — generated dispatch wrappers currently handle all host functions through the generic macro expansion.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:423-433` — `check_contract_imports_match_host_protocol` already inspects imported functions and can identify the imported hot-function set for a parsed module.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` instantiates modules with the cached linker that would hold the selected fast stubs.

## Evidence

The verified apply-window trace shows all candidate import dispatch happens below `applyLedger` through `parallelApply` and `invoke_host_function`. The aggregate dispatch-site counts are high enough that a fast-stub design does not depend on a single micro call site: the hot imports listed above account for hundreds of thousands of calls across the diagnostic run, and the broader `applySorobanStageClustersInParallel` zone is **3.427 s** of the **5.076 s** total `applyLedger` envelope.

This hypothesis targets a different mechanism than already-failed fuel-only batching or export-handle caching. It does not try to skip fuel settlement, cache a `wasmi::Func`, or fuse guest import sequences; it specializes the generated import wrapper for a small set of statically known signatures so required work remains but generic branches and conversions that are irrelevant for that signature are not re-evaluated on every call.

## Anti-Evidence

Prior dispatch investigations failed when they treated the entire macro-expanded line as removable overhead. A viable PoC must first add narrower Tracy spans or counters inside one or two selected generated stubs to separate mandatory fuel/object/error work from removable generic dispatch scaffolding. If the exact removable subset is only a few nanoseconds per import, the hypothesis falls below Medium; the PoC must demonstrate that monomorphic stubs reduce enough of the import-boundary self-time to survive three non-Tracy soroswap benchmark runs.


---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `001-low-overhead-wasmi-dispatch-trampolines.md`
**Failed At**: reviewer

### Trace Summary

The `closeLedger` path reaches this code through parallel Soroban apply, `InvokeHostFunctionOpFrame::doParallelApply`, the Rust host bridge, `Host::invoke_function`, VM instantiation, and wasmi import calls into the generated dispatch wrappers. The local source already generates one monomorphic Rust function per host import signature and registers that exact function in the wasmi linker through `HostFuncInfo::wrap`. The remaining wrapper body is the mandatory boundary sequence: protocol guardrails, optional tracing, fuel drain/refill, `DispatchHostFunction` budget charge, relative object conversion, `VmCaller` setup, host function invocation, error augmentation, result validation, and result marshalling. This is substantially the same mechanism as the prior failed low-overhead wasmi dispatch trampoline investigation.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:50` — records `001-low-overhead-wasmi-dispatch-trampolines.md`, which rejected hot-host-function dispatch trampolines because correct fast paths still require object validation/translation, dispatch budget charging, fuel synchronization, `VmCaller` setup, error handling, result integrity checks, and narrower measurements.
- `ai-summary/fail/transaction-ledger/summary.md:64` — records that even the structurally redundant per-call protocol bound check in the dispatch shim is far below the objective severity threshold.
- `ai-summary/fail/transaction-ledger/summary.md:72` — records that VM-host fuel synchronization batching is below threshold because mandatory dispatch charging, argument conversion, host body execution, result/trap handling, and object translation remain.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:42-83` — `host_function_info_helper!` stores a linker wrapper that calls `linker.func_wrap($mod_str, $fn_id, dispatch::$func_id)`, so each import is already bound to its specific generated dispatch function.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:92-150` — `HOST_FUNCTIONS` is generated statically from the host-function x-macro and carries each function's module, name, arity, protocol bounds, and exact wrapper.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:148-304` — `generate_dispatch_functions!` emits one Rust function per host function with static argument and result types; the apparent generic body performs required fuel, budget, conversion, error, and result handling.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — `check_contract_imports_match_host_protocol` performs import/protocol validation at instantiation, but the per-call guardrails remain cheap defensive checks already covered by the prior failure.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` checks contract imports and instantiates through the cached linker before guest calls enter the already-generated dispatch functions.

### Why It Failed

This hypothesis is not novel. Its proposed "signature-specific, parse/link-time selected static fast stubs" are substantially equivalent to `001-low-overhead-wasmi-dispatch-trampolines.md`, and the actual code already has the core property claimed as new: per-host-function monomorphic dispatch functions are generated by the x-macro and registered directly in the linker. What remains in the macro-expanded body is mostly required correctness and metering work, not reusable generic dispatch scaffolding. The few visibly redundant pieces, such as protocol guardrails after import validation, were separately recorded as far below the Medium threshold for this objective.

### Lesson Learned

Do not treat `dispatch.rs:304` aggregate self-time as removable generic wrapper overhead. Future host-import dispatch hypotheses need a genuinely new, narrowly measured removable operation that is not part of fuel synchronization, budget charging, object translation, `VmCaller` lifetime, host error propagation, tracing/profiling, or result marshalling, and it must clear the 3% soroswap apply-time floor after cluster normalization.
