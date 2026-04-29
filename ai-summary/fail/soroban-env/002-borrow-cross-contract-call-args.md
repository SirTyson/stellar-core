# H002: Borrow Cross-Contract Call Arguments Until the Required Frame Copy

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant small-argument allocations/copies from the hot cross-contract call path while preserving dispatch and frame metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every contract `call` and `try_call` from Wasm should pass the same ordered arguments to the callee, push equivalent call frames for diagnostics/auth/rollback, return the same values or errors, and consume the same budget counters as today. The implementation should avoid materializing an intermediate owned `Vec<Val>` solely to pass arguments from the caller's immutable `HostVec` into a path that immediately clones those same arguments again for the callee frame.

## Mechanism

The generated dispatch for the host `call` function converts relative arguments and enters `Host::call` (`src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254`). `Host::call` then calls `call_args_from_obj(args)`, which visits the `VecObject` and clones the entire `HostVec` into a new `Vec<Val>` (`src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2592`; `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194`). A few frames later, `call_contract_fn` charges another bulk copy and clones `args.to_vec()` again into `Frame::ContractVM` or `Frame::StellarAssetContract` (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147,750-785`). For Wasm callees, `Vm::invoke_function_raw` then allocates a third argument vector of `wasmi::Value` even for the common small arities exercised by SAC and router calls (`src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-405`).

The optimization would add an owned/borrowed call-argument path: visit the `VecObject` once, pass the borrowed `HostVec::as_slice()` through `call_n_internal`/`call_contract_fn` until the frame-owned argument vector is actually needed, and explicitly charge the removed logical unpack/copy costs without performing the redundant allocation. For Wasm calls, use a stack-backed fixed buffer for common small arities before falling back to heap `Vec<wasmi::Value>`, while keeping the existing `Vec::<wasmi::Value>::charge_bulk_init_cpy` charge. This preserves deterministic call order, frame contents, rollback behavior, and budget accounting; it only removes temporary allocation/copy work that is not itself consensus-visible.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and inspect the `call` and `Vm::invoke_function_raw` zones under `applyLedger`. A PoC should route `call`/`try_call` through a borrowed-argument helper, preserve exact budget trackers on nested contract-call tests, and show at least a 3% repeated-run median reduction in non-Tracy soroswap apply time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254` — generated dispatch for all host functions, including the hot `call` function.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2592` — `Host::call` immediately clones the `VecObject` arguments before forwarding them.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2603-2630` — `Host::try_call` has the same argument-cloning pattern.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` — `call_args_from_obj` performs the first `HostVec` to `Vec<Val>` clone.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` — frames require owned argument vectors for diagnostics/auth/rollback context.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` performs the second argument clone into the callee frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-405` — Wasm invocation always heap-allocates `Vec<wasmi::Value>` for marshalled arguments.

## Evidence

The current reference soroswap trace reports `call,soroban-env-host/src/vm/dispatch.rs,304,440288012,...,17946,...` in self-time, and timestamp intersection places 17,509 of 17,946 `call` events inside `applyLedger`. It also reports `Vm::invoke_function_raw,soroban-env-host/src/vm.rs,400,334270453,...,8990,...`; 8,769 of 8,990 raw invoke events overlap `applyLedger` windows. The source shows a structural allocation pattern on this exact path: `call_args_from_obj` clones the argument vector, `call_contract_fn` clones it again for the frame, and `Vm::invoke_function_raw` allocates a separate wasm-argument vector even though most Soroban/SAC call arities are small.

## Anti-Evidence

The frame-owned `Vec<Val>` cannot be removed outright because diagnostics, auth matching, rollback, and trace formatting can inspect frame arguments. The removed intermediate clone is likely small per call, so the PoC must include both the borrowed `HostVec` path and the stack-backed wasm-argument path, and it must demonstrate that the saved allocation/copy work is a large enough fraction of the `call`/`Vm::invoke_function_raw` self-time to clear the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; existing soroban-env fail records cover Tracy-only overhead, wasmi instantiation, TTL extension, XDR metering/serialization, parallel-apply setup, budget templates, bridge XDR roundtrips, output-buffer preallocation, and address-object decode caching, not cross-contract argument borrowing
**Failed At**: reviewer

### Trace Summary

The claimed execution path is real: generated dispatch translates the `VecObject` handle for `call`/`try_call`, `Host::call` and `Host::try_call` immediately clone the caller's `HostVec` into an owned `Vec<Val>`, and `call_contract_fn` then clones the same slice again into the frame-owned argument vector. For Wasm callees, `Vm::invoke_function_raw` allocates a separate `Vec<wasmi::Value>` after the frame is pushed, then passes that slice into `metered_func_call`. However, exact-budget behavior requires preserving the same `VisitObject`, `MemCpy`, heap-allocation, and shallow-copy charges, while the frame-owned `Vec<Val>` and relative-object translation still remain mandatory. The cited `call` and `Vm::invoke_function_raw` Tracy zones include much more than the removable physical allocation/copy work, so the trace does not support a Medium 3%+ apply-time projection.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254` — generated host-function dispatch obtains the `Host`, returns VM fuel, charges `DispatchHostFunction`, converts relative object handles to absolute values, and calls `host.call(...)` / `host.try_call(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2600` — `Host::call` constructs invocation-metering metadata in test builds, calls `call_args_from_obj(args)`, then forwards `argvec.as_slice()` into `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2603-2645` — `Host::try_call` has the same `call_args_from_obj` clone before forwarding the slice and then converts recoverable contract errors into `Ok(Error)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:314-316` — `call_args_from_obj` visits the `HostVec` object and returns `hv.to_vec(...)`, which delegates to `Vec<Val>::metered_clone`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:190-255,397-407` — `Vec<C>::metered_clone` first charges the shallow `Vec` copy, heap allocation for elements, shallow element copy, and any element substructure before performing `Clone::clone`; preserving budget counters means these charge operations cannot be removed.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` performs reserved-name and reentry checks, emits call diagnostics in debug mode, then delegates to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147,750-785` — `Frame::ContractVM` and `Frame::StellarAssetContract` own `Vec<Val>` arguments; `call_contract_fn` charges `Vec::<Val>::charge_bulk_init_cpy`, copies `args.to_vec()`, pushes the frame, and invokes either Wasm or SAC code with an argument slice.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:493-497,572-585,829-849,1340-1365` — authorization data structures and current invocation matching depend on owned argument vectors or frame-derived contract/function context, so the frame copy is not optional.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — visiting the argument object charges `VisitObject`, borrows the host object table, validates the handle, extracts the typed `HostVec`, and runs the closure; only the short physical lookup and clone allocation are candidates for removal if equivalent charges are preserved.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-337,393-411` — `invoke_function_raw` charges `Vec::<wasmi::Value>::charge_bulk_init_cpy`, heap-collects marshalled relative arguments into `Vec<wasmi::Value>`, then calls `metered_func_call`, whose work includes export lookup, fuel transfer, and the actual wasmi call.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-440` — `absolute_to_relative` remains necessary for object arguments and mutates the current frame's relative-object table, so a stack-backed wasmi argument buffer would not remove relative-handle bookkeeping.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-26` — `tracy_span!` compiles out without the Tracy feature, so self-time attributed to `call` and `Vm::invoke_function_raw` is a broad profiling envelope rather than directly removable production overhead.

### Why It Failed

The optimization target is real but below the objective's Medium severity threshold. Removing the first owned `Vec<Val>` and stack-allocating common `wasmi::Value` argument arrays would save small heap allocations and shallow copies, but exact Soroban metering requires continuing to execute equivalent budget charges for `VisitObject`, `Vec<Val>` unpacking, frame argument copying, and `Vec<wasmi::Value>` initialization. The mandatory frame-owned `Vec<Val>` remains because frames, diagnostics, rollback, and authorization need stable invocation context, and `absolute_to_relative` still performs per-object relative table updates. Since soroswap call arities are small, the physically removable work is limited to tens of thousands of tiny vector allocations/copies, while the cited Tracy zones also include dispatch conversion, reentry checks, diagnostics gates, storage/instance lookup, frame push/pop, wasmi export lookup, fuel transfer, relative-object translation, and callee execution. Without isolated allocation-growth measurements showing those tiny allocations exceed roughly 3% of apply time, this is at best a Low/sub-threshold cleanup; under the optimize-soroswap objective, Low findings are NOT_VIABLE.

### Lesson Learned

For Soroban call-path allocation hypotheses, separate protocol-visible metering and required frame/relative-object bookkeeping from physical allocation work before projecting impact. Broad `call` or `Vm::invoke_function_raw` Tracy self-time is only an upper bound; if exact-budget preservation leaves the charge calls and frame copy in place, small-arity argument vector allocations are unlikely to clear the Medium floor without dedicated allocator instrumentation.
