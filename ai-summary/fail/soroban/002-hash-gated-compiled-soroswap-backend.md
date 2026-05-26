# H002: Hash-gated compiled backend for hot Soroswap Wasm execution

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: High
**Impact**: Soroswap VM execution inside `closeLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-gated, allowlisted Soroswap Wasm modules with fixed hashes, repeated contract execution during apply should reuse a deterministic compiled execution plan instead of reinterpreting the same hot Wasm blocks and rebuilding per-invocation interpreter state. The ledger effects, traps, host-call ordering, fuel/budget accounting, diagnostic behavior, and event order must remain exactly defined by the new protocol gate.

## Mechanism

The current module cache stores parsed modules and a wasmi linker, but every invocation still constructs a fresh `Vm`, instantiates wasmi state, and executes the router/pool Wasm through `Vm::invoke_function_raw`. In the current soroswap trace, apply-contained totals include **7,231,631,147 ns** in `Vm::invoke_function_raw` (`soroban-env-host/src/vm.rs:400`), **4,937,728,356 ns** in the dispatch `call` wrapper (`soroban-env-host/src/vm/dispatch.rs:304`), and **597,851,754 ns** in `Vm::instantiate_wasmi` (`soroban-env-host/src/vm.rs:160`). A hash-gated compiled backend for the exact Soroswap router/pool modules could keep the existing host ABI but replace interpreter dispatch of hot basic blocks with a prevalidated deterministic plan, reducing aggregate worker CPU enough to move the stage wall time while staying within `NUM_CLUSTERS` parallelism.

## Trigger

Run the current protocol-27 soroswap apply-load scenario. Successful swap transactions repeatedly invoke the same Soroswap router and pair/pool Wasm hashes under `Host::call_contract_fn`; traces show these invocations are descendants of `applyLedger` via `InvokeHostFunctionOpFrame doParallelApply` -> `invokeHostFunction` -> Rust `invoke_host_function`. A PoC should gate the compiled backend on the exact module hash and protocol version, then compare three non-Tracy `scripts/run_apply_load_matrix.py` runs plus one Tracy diagnostic run showing reduced `Vm::invoke_function_raw` or child execution time inside `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `Host::call_contract_fn` dispatches Wasm contracts through `instantiate_vm` and `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1644` — `instantiate_vm` obtains cached parsed modules but still creates a fresh `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:160-400` — wasmi instantiation and `Vm::invoke_function_raw` execution path.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs` — cache extension point for storing a hash-gated compiled plan beside `ParsedModule`.
- `src/rust/src/soroban_module_cache.rs` and `src/rust/src/soroban_proto_any.rs:391-448` — C++/Rust bridge path that passes the shared module cache into every apply invocation.

## Evidence

- Current soroswap diagnostic trace:
  `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`.
- Apply-contained unwrap aggregation confirmed the target zones are under `applyLedger`:
  - `Vm::invoke_function_raw,soroban-env-host/src/vm.rs:400`: 7,231,631,147 ns / 8,034 events.
  - `call,soroban-env-host/src/vm/dispatch.rs:304`: 4,937,728,356 ns / 24,078 events.
  - `Vm::instantiate_wasmi,soroban-env-host/src/vm.rs:160`: 597,851,754 ns / 8,079 events.
  - `Host::invoke_function,soroban-env-host/src/e2e_invoke.rs:701`: 8,237,885,814 ns / 8,018 events.
- These totals are large enough that a partial reduction of interpreter execution, not just instantiation setup, can clear the 3% Medium threshold after 8-way cluster normalization.
- The proposal is protocol-gated and hash-gated, so released p26 execution and metering remain unchanged while the new protocol can define exact compiled-backend accounting.

## Anti-Evidence

- A generic compiled VM backend is a large redesign and cannot be justified by instantiation-only savings; the PoC must reduce `Vm::invoke_function_raw` execution time, not merely `Vm::instantiate_wasmi`.
- Determinism is the central risk. The backend must define exact integer arithmetic, trap order, fuel accounting, memory bounds behavior, and host-call order, and it must not depend on CPU-specific undefined behavior.
- If most `Vm::invoke_function_raw` time is actually host-call work that remains on the same path, compiling guest basic blocks may not move the top-line apply metric. The diagnostic Tracy run must therefore show the child VM/interpreter portion, not only broad parent totals, decreasing.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `002-compiled-soroban-vm-backend.md + 002-protocol-gated-wasmtime-backend.md + 002-protocol-gated-aot-soroswap-wasm-backend.md + 002-apply-path-soroswap-wasm-block-profile-backend.md`
**Failed At**: reviewer

### Trace Summary

The traced apply path still matches the broad mechanism: Soroban parallel apply enters the Rust bridge through `invoke_host_function_or_maybe_panic`, passes the shared per-protocol module cache into `e2e_invoke`, and `Host::call_contract_fn` either uses existing next-protocol native Soroswap pool shortcuts or falls back to `instantiate_vm` followed by `Vm::invoke_function_raw`. `instantiate_vm` reuses cached `ParsedModule` and the cache's `wasmi_linker`, but still constructs a fresh `Vm`, `wasmi::Store`, and `wasmi::Instance`; `invoke_function_raw` then marshals arguments and calls the wasmi function through `metered_func_call`. However, the fail summary already records this same compiled-backend family, including protocol-gated/AOT/hash-gated Soroswap variants, and retained blockers around backend implementation, deterministic fuel/metering, host-call subtraction, and cluster-normalized impact.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` checks existing hash/protocol-gated native Soroswap pool getter/swap paths, otherwise creates a `ContractVM` frame and invokes `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-1528` — existing native Soroswap pool getter/swap shortcuts already bypass selected pool Wasm calls under a post-p26 protocol gate and fixed hash/schema checks, confirming this proposal is not the first hash-gated Soroswap bypass surface.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1644` — `instantiate_vm` looks up `ParsedModule` in `ModuleCache`, verifies the code still exists in storage, and still calls `Vm::from_parsed_module_and_wasmi_linker` to instantiate a fresh VM for the invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-218` — `Vm::instantiate_wasmi` creates a new wasmi store, checks imports, instantiates the module, ensures no start function, and records memory for the new `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` converts host `Val` arguments to relative wasmi values and calls `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:250-304` — generated host import dispatch performs relative-value conversion, host-function invocation, error escalation, and fuel refill at Host↔VM boundaries, so broad dispatch totals include mandatory host ABI semantics a compiled backend would not automatically remove.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-204` — `ModuleCache` stores `Arc<ParsedModule>` plus a shared engine/linker; no compiled backend trait or reusable execution-plan slot exists in the current source.
- `src/rust/src/soroban_module_cache.rs:22-118` and `src/rust/src/soroban_proto_any.rs:391-448` — the C++/Rust bridge selects a protocol-specific cache and passes it into every invocation on the apply path.

### Why It Failed

This is a duplicate, not a novel hypothesis. The retained Soroban fail summary already covers a "Protocol-Gated Compiled Soroban VM Backend for cached modules" family with variants specifically including protocol-gated AOT Soroswap and apply-path Soroswap block-profile backends. The current hypothesis restates the same compiled-backend idea with hash gating, but does not add the missing implementation design, deterministic execution/fuel contract, exact metering schedule, or isolated non-host-call VM-interpreter measurement needed to overcome the prior NEEDS_REFINEMENT finding.

### Lesson Learned

Do not resubmit compiled-backend or hash-gated AOT Soroswap Wasm hypotheses unless they provide materially new evidence: a concrete backend implementation path compatible with the pinned runtime, a protocol-level deterministic metering/fuel specification, and measurements isolating removable guest-interpreter work after subtracting host dispatch/body costs and normalizing parallel-worker totals by the configured cluster count.
