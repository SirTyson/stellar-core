# H002: Inline VM and frame argument buffers for small contract calls

**Date**: 2026-04-28
**Subsystem**: transaction-ledger / Soroban VM call dispatch
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding heap allocation and extra copies for per-call argument vectors
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap contract calls pass small argument lists, and the VM layer caps calls at `Vm::MAX_VM_ARGS == 32`. The apply path should own frame arguments and marshal wasmi arguments without allocating heap `Vec`s for the common small-argument case. Frame rollback, authorization, invocation recording, and VM execution should observe the same ordered arguments, and budget trackers should keep the same logical vector-copy charges even if the implementation stores the buffers inline.

## Mechanism

`Host::call_contract_fn` charges a bulk copy and then unconditionally does `args.to_vec()` before dispatching both Wasm and SAC frames. For Wasm calls, `Vm::invoke_function_raw` immediately performs another bulk-copy charge and collects a second heap `Vec<wasmi::Value>` from the same small `&[Val]` slice before calling `metered_func_call`. In the soroswap path this happens for router/pool Wasm calls and SAC frames on every swap. The current trace shows `Vm::invoke_function_raw` self-time at **181.017 ms** over 5,074 calls for the full current trace, and the longest `applyLedger` window contains 4,561 `Vm::invoke_function_raw` events plus 3,042 `SAC transfer` events under the same worker imbalance.

An internal fixed-capacity argument buffer, such as a small inline `FrameArgs`/`VmArgs` backed by `[Val; Vm::MAX_VM_ARGS]` and `[wasmi::Value; Vm::MAX_VM_ARGS]` (or an equivalent no-heap small-vector type), can replace the two per-call heap vectors. The buffer can preserve ownership for `Frame::ContractVM` / `Frame::StellarAssetContract` and expose slices to existing call sites, while the existing `Vec::<Val>::charge_bulk_init_cpy` / `Vec::<wasmi::Value>::charge_bulk_init_cpy` calls remain as deterministic budget accounting rather than forcing actual `Vec` allocation.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=4000, T=8`) with `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. In the longest `applyLedger` interval, inspect the `call`, `Vm::invoke_function_raw`, `SAC transfer`, and allocator/vector-related zones. The trigger is any contract call with `args.len() <= Vm::MAX_VM_ARGS` - effectively all valid VM calls - especially the repeated router/pool/SAC calls in the soroswap workload.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` - `Frame::ContractVM` and `Frame::StellarAssetContract` store `Vec<Val>` arguments.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:756-784` - `call_contract_fn` performs `Vec::<Val>::charge_bulk_init_cpy`, then `args.to_vec()`, then moves that heap vector into the frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-410` - `invoke_function_raw` charges another bulk copy and collects a heap `Vec<wasmi::Value>` for every Wasm call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-326` - `metered_func_call` only needs a borrowed slice of marshaled wasmi values, so it can consume an inline argument slice without owning a heap `Vec`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-229` and `404-562` - frame push/pop and rollback use frame-owned data; the inline representation must remain owned by the frame and hash/clone consistently.

## Evidence

- Tracy scope check: the `Vm::invoke_function_raw` and `SAC transfer` events are descendants of the measured `applyLedger` window through parallel Soroban apply, not benchmark setup.
- Source shows two concrete heap-vector constructions in the hot path: `args.to_vec()` for every contract frame and `collect::<Result<Vec<wasmi::Value>, HostError>>()?` for every Wasm call. Both operate on bounded, usually tiny argument lists.
- The full current trace reports `Vm::invoke_function_raw` self-time of **181.017 ms** over 5,074 calls. That self-time excludes the nested `call` / Wasm execution zone and includes argument bulk-charge, absolute-to-relative conversion, and `Vec<wasmi::Value>` collection. The longest apply interval has 4,561 VM raw-call events, so removing heap allocation/copy overhead from this self-time can plausibly save tens of milliseconds on the critical worker.
- `call_contract_fn` also copies arguments before both Wasm and SAC frames. The longest apply interval has 3,042 `SAC transfer` events and 9,123 generic `call` dispatch events, so frame-argument allocation is not limited to Wasm calls.
- The change is deterministic: it does not reorder calls or alter parallelism, and the same budget charges can be retained even when the physical storage is inline rather than heap allocated.

## Anti-Evidence

- `Vm::invoke_function_raw` self-time includes useful `absolute_to_relative` conversion, not just vector allocation. If allocator/copy work is a small fraction, the standalone win could fall below the 3% Medium threshold.
- `Frame` derives `Clone` and `Hash`, and authorization/invocation tracking may rely on frame arguments being easily cloned/hashed. A custom inline representation must implement identical semantics without making frame operations slower.
- Introducing a new small-buffer type in this Rust crate may add maintenance complexity or a dependency. A no-dependency fixed buffer is safer but must handle initialization/drop correctly for `Val` and `wasmi::Value`.
- The existing budget model charges vector initialization/copy through `Vec::<T>::charge_bulk_init_cpy`. The PoC must preserve those logical charges unless a protocol-gated metering change is explicitly intended; otherwise resource-limit-boundary transactions could change behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS -- no duplicate in `fail/transaction-ledger` summary or argument/invoke-related individual fail files; no `success/transaction-ledger` records found; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: contract calls are hot in the soroswap close-ledger path, `call_contract_fn` copies the call arguments into a frame-owned `Vec<Val>`, and Wasm calls then build another heap `Vec<wasmi::Value>` before `metered_func_call`. The proposed inline representation is plausibly correctness-preserving if it keeps frame ownership, slice access, `Clone`/`Hash` semantics, and the existing deterministic budget charges. However, the hypothesis overstates severity by treating the entire cited `Vm::invoke_function_raw` self-time as mostly removable allocation work. Source tracing shows that the span also contains preserved budget charging, absolute-to-relative object-handle conversion, export lookup, fuel transfer, return conversion, and the actual conversion from `Val` to `wasmi::Value`; after T=8 parallel normalization, removing only tiny per-call heap vectors is below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1495` - `applyLedger` defines the measured close-ledger apply window.
- `src/ledger/LedgerManagerImpl.cpp:2483-2575` - Soroban clusters run on async workers and the apply thread waits on futures, so aggregate worker totals must be converted to critical-path wall time.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` - each Soroban operation calls `rust_bridge::invoke_host_function` with encoded host function data and the shared module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` - parallel Soroban apply enters `InvokeHostFunctionOpFrame doParallelApply` before invoking the Rust host.
- `src/rust/src/soroban_invoke.rs:7-38` - the C++/Rust bridge dispatches to the protocol-specific host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` - each invocation builds enforcing storage, constructs a fresh `Host`, installs auth/module-cache state, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` - top-level `InvokeContract` host functions convert XDR arguments to `Val`s and enter `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2600` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` - nested Wasm `call` host functions already copy the guest `HostVec` into a `Vec<Val>` before `call_contract_fn`, so removing the later frame copy does not remove all argument-vector allocation on nested calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-147` - `Frame::ContractVM` and `Frame::StellarAssetContract` currently own `Vec<Val>` arguments.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-229` and `404-562` - frame push/pop, auth snapshots, trace hooks, and rollback require frame-owned data with stable behavior until frame exit.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` - every contract call charges `Vec::<Val>::charge_bulk_init_cpy`, builds `args.to_vec()`, and stores it in the Wasm or SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-391` - `metered_func_call` consumes a borrowed `&[wasmi::Value]`, but also performs non-removable budget charging, export lookup, fuel transfer, VM call error handling, and return conversion.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` - `invoke_function_raw` charges `Vec::<wasmi::Value>::charge_bulk_init_cpy`, maps every argument through `absolute_to_relative`, collects a heap `Vec<wasmi::Value>`, and passes it as a slice.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-440` - `absolute_to_relative` is required for object arguments and pushes object handles into the frame-relative table; an inline wasmi buffer cannot remove this work.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:107-121` - `charge_bulk_init_cpy` deliberately charges container copy/allocation costs; the hypothesis preserves these charges, so their CPU/memory budget bookkeeping remains in the hot path.
- `src/rust/soroban/p26/soroban-env-host/src/host/trace/fmt.rs:104-135` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3610-3626` - trace formatting and `require_auth` read frame arguments by slice and clone them when needed, so a replacement representation would need identical slice/clone semantics.

### Why It Failed

This is a real micro-optimization, but it does not meet the optimize-soroswap objective's Medium severity floor. The current accepted baseline is 596.381 ms median apply time, so a Medium finding needs roughly 17.9 ms or more of reproducible wall-clock improvement. The strongest evidence cited for Wasm argument marshalling is 181.017 ms of aggregate `Vm::invoke_function_raw` self-time over all workers; in the T=8 soroswap apply path, reaching the Medium floor from this span alone would require removing roughly 143 ms of aggregate worker time, nearly 80% of the entire self-time. The proposed change cannot remove that much because it must preserve budget charges and still performs per-argument `absolute_to_relative` conversion, `Val` to `wasmi::Value` marshalling, export lookup/fuel/return handling, and the actual VM call boundary work.

The frame-argument side has the same problem. `args.to_vec()` in `call_contract_fn` is one tiny heap allocation and a short `Val` copy per Wasm/SAC frame, and nested Wasm `call` already performed an earlier `HostVec::to_vec` copy before entering `call_contract_fn`. Even if an inline frame buffer removes this later allocation for every cited call, the wall-clock saving would have to come from thousands of small allocations costing implausibly many microseconds each after parallel normalization. Without direct allocator evidence showing that these specific tiny vectors dominate the apply critical path, the trace supports a Low/sub-threshold cleanup rather than a Medium soroswap optimization. Under the objective-specific rules, Low-tier findings are rejected instead of accepted with downgraded severity.

### Lesson Learned

Do not equate a hot function's self-time with removable allocation overhead. For parallel Soroban apply, normalize worker-time totals to wall-clock critical-path impact and subtract preserved work such as deterministic budget charges, object-handle translation, fuel transfer, and preexisting argument copies before assigning Medium severity.
