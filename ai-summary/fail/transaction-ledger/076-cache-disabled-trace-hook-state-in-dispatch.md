# H076: Cache Disabled Trace-Hook State in Generated Wasmi Dispatch

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban VM host dispatch
**Severity**: Low
**Impact**: Below objective threshold; removes repeated no-op tracing-state checks around Wasm host imports
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In production apply-load runs without a Soroban trace hook, each generated host-import wrapper should dispatch the host function and return without repeatedly borrowing trace-hook state just to discover that tracing is disabled. The behavior should remain identical when tracing is enabled or when test hooks are installed.

## Mechanism

The generated dispatch wrapper checks `host.tracing_enabled()` before every host call, and `tracing_enabled` attempts to borrow `disable_tracing` and then the trace-hook slot (`src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:255-262`, `src/rust/soroban/p26/soroban-env-host/src/host.rs:935-945`). In the soroswap benchmark this branch is expected to be false for every import, so a cached "tracing definitely disabled" flag on `HostImpl` or in the VM call frame could skip those `RefCell` probes on the hot import path while preserving the existing slow path when a trace hook exists.

## Trigger

Run the current soroswap apply-load scenario. The trigger is any Wasm host import under `applyLedger`, for example router calls into host vector, bytes, crypto, and contract-call functions, all generated from `call_macro_with_all_host_functions!` at `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:253-296` — generated host-import wrapper around every host function call.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:935-945` — `Host::tracing_enabled` checks tracing state through borrowable host fields.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` enters Wasm execution whose imports hit the generated dispatch wrappers.

## Evidence

The current trace confirms this dispatch path is inside the benchmark window: timestamp filtering to `applyLedger` shows 24,078 contained `call` events at `soroban-env-host/src/vm/dispatch.rs:304` totaling 4.938 s inclusive worker time, with child import categories such as `vec_get`, `vec_len`, `bytes_append`, `serialize_to_bytes`, `compute_hash_sha256`, and `get_contract_data`. The source shows the tracing gate runs in the generated wrapper before every host import and is independent of the actual host function body.

## Anti-Evidence

The Tracy `call` zone is inclusive of mandatory argument conversion, budget/fuel settlement, object-table translation, the host function body, error augmentation, result conversion, and the VM fuel refill. The proposed change targets only two no-op tracing-state checks per import. With about 24,078 import calls over 71 apply windows, even an optimistic 1 us saved per import is only about 0.34 ms aggregate per ledger before 8-way critical-path normalization, far below the 3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — narrower than prior dispatch-trampoline and fuel-settlement records; specifically investigates the disabled trace-hook guard

### Why It Failed

The disabled tracing check is real repeated work, but the import count and per-check cost are too small to matter. It is a tiny sub-slice of the broad generated-dispatch zone, and the broad zone itself is dominated by required VM/host boundary semantics and host-function bodies.

### Lesson Learned

Do not use inclusive generated-dispatch Tracy time as evidence for removing a small wrapper guard. Dispatch-wrapper hypotheses need a removable operation whose per-call cost multiplied by the in-apply import count clears the Medium floor after cluster normalization.
