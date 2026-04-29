# H001: Stack-allocate VM call argument buffers

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by removing per-VM-call heap allocation and iterator overhead in the Soroban VM invocation path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban VM function call should marshal its already-validated host `Val` arguments into wasmi `Value`s, call the target function, and translate the return value back without changing argument order, budget determinism, or object-handle isolation. Calls with up to `Vm::MAX_VM_ARGS` arguments should not need heap allocation for the temporary wasmi argument slice.

## Mechanism

`Vm::invoke_function_raw` currently charges and allocates a fresh `Vec<wasmi::Value>` for every guest function call, even though `Vm::MAX_VM_ARGS` is 32 and soroswap calls use small fixed arities. The temporary vector is immediately borrowed as a slice for `metered_func_call` and then dropped. Replacing it with a stack-backed `ArrayVec` / fixed `MaybeUninit` buffer would preserve deterministic argument order while avoiding the heap allocation, zero-capacity growth path, and iterator `collect` overhead on each VM call.

## Trigger

Run the current soroswap apply-load Tracy benchmark (`1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`) and inspect `Vm::invoke_function_raw` inside `applyLedger`. The trace contains 10,003 `Vm::invoke_function_raw` events, all inside `applyLedger`; aggregate self-time is 350,052,506 ns and total time is 10,208,687,303 ns. The direct child VM dispatch `call` zone is also fully inside `applyLedger` with 19,982 events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:132-134` — declares `Vm::MAX_VM_ARGS = 32`, making a bounded stack buffer feasible.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` charges `Vec::<wasmi::Value>::charge_bulk_init_cpy`, collects mapped arguments into a heap `Vec`, and immediately passes `wasm_args.as_slice()` to `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-430` — `absolute_to_relative` is still required per argument and must remain in the same order when filling the stack-backed buffer.

## Evidence

The current trace confirms the zone is within the measured apply path: unwrap-mode analysis found all 10,003 `Vm::invoke_function_raw` events inside the 69 `applyLedger` windows. Its 350 ms self-time is about 6.1% of the 5.774 s traced `applyLedger` envelope, so removing a substantial fraction of the temporary allocation/marshalling overhead is a Medium-tier opportunity. The structural observation is simple and local: the vector exists only to create a `&[wasmi::Value]` for the duration of one call, and the maximum length is a compile-time constant.

## Anti-Evidence

The `absolute_to_relative` translation and the wasmi call itself remain mandatory, so the full `Vm::invoke_function_raw` self-time is not removable. The existing `charge_bulk_init_cpy` may be protocol-visible through reported CPU/memory budget metrics; a PoC must either preserve that charge for compatibility or explicitly gate the resource-accounting change. If most self-time comes from `absolute_to_relative` rather than allocation/collect, the realized win may fall below the 3% Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; prior crypto failures cover bridge buffers, SHA256/syscall dispatch, hashing, and signature verification, not this specific host-to-VM argument buffer
**Failed At**: reviewer

### Trace Summary

The production apply path enters Soroban from `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the C++/Rust bridge, dispatches through the protocol-specific host module, then calls `Host::invoke_function` and `Host::call_contract_fn`. For Wasm contracts, `call_contract_fn` installs a `Frame::ContractVM` and calls `Vm::invoke_function_raw`, which does allocate a temporary `Vec<wasmi::Value>` before `metered_func_call`. However, the self-time attributed to `Vm::invoke_function_raw` also includes mandatory budget charging and `absolute_to_relative` conversion for each argument, and the earlier `call_contract_fn` frame still allocates an `args_vec` for frame state.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply path builds bridge buffers and calls `rust_bridge::invoke_host_function` during Soroban operation application.
- `src/rust/src/soroban_invoke.rs:7-38` — bridge wrapper dispatches to the protocol-specific `invoke_host_function` implementation.
- `src/rust/src/soroban_proto_any.rs:310-354,391-452` — protocol-agnostic Rust wrapper catches panics, creates the budget, and calls `soroban-env-host` invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — host invocation decodes resources/host function/auth, initializes the host, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1193` — `Host::invoke_function` converts XDR args to `Vec<Val>` and enters contract invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — `call_contract_fn` retrieves the contract instance, charges/clones args into `args_vec` for the frame, and invokes the Wasm VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:132-134,393-411` — `MAX_VM_ARGS` bounds args at 32, while `invoke_function_raw` charges and collects into `Vec<wasmi::Value>` before passing a slice to `metered_func_call`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-440` — `absolute_to_relative` must still run per argument and may charge/push relative object handles.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:107-133` — `charge_bulk_init_cpy` accounts for container shallow copy, element heap allocation, and shallow element copy; preserving this charge is required unless a deliberate metering change is made.
- `src/rust/soroban/p26/soroban-env-host/src/host/declared_size.rs:107-109` — `wasmi::Value` is metered as 16 bytes, so each temporary VM arg buffer is at most 512 bytes of element storage.

### Why It Failed

The claimed heap allocation is real, but it is not large enough to clear the optimize-soroswap severity floor. The objective requires at least a Medium projection (3-10% apply-time reduction), which is about 173 ms on the cited 5.774 s `applyLedger` envelope. Stack-allocating this buffer would remove roughly 10,003 short-lived allocations of at most 512 bytes each, plus the small iterator/collect loop overhead; it would not remove `absolute_to_relative`, budget charging, `metered_func_call`, the VM call itself, or the earlier `Vec<Val>`/frame argument allocations. Therefore it can recover only a fraction of the 350 ms `invoke_function_raw` self-time, and the realistic savings are below the Medium threshold required by this objective.

### Lesson Learned

Do not size host-to-VM marshalling optimizations against an entire Tracy self-time block unless the removable work dominates that block. For `Vm::invoke_function_raw`, the temporary `Vec<wasmi::Value>` is a clean local inefficiency, but metering and relative-object conversion are the real semantic work on the path, and the remaining allocation is too small at ~10k calls per trace to justify promotion under the soroswap Medium-or-higher review rule.
