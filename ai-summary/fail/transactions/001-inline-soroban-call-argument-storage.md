# H001: Inline Soroban Call Argument Storage

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by removing repeated small heap allocations and argument-copy work from the per-contract-call hot path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap apply should preserve the same contract-call semantics, metering, diagnostic behavior, return values, storage changes, and authorization checks while avoiding heap-backed argument buffers for the overwhelmingly small argument lists used by SAC transfers and router calls. The host should still charge the same budget units for argument copying and should expose frame arguments to auth/diagnostics in the same order, but the transient storage for `Frame` arguments and Wasmi call arguments should be inline for small arities.

## Mechanism

`Host::call_contract_fn` currently charges and clones every `args: &[Val]` into a heap-backed `Vec<Val>` before every `with_frame`, and `Vm::invoke_function_raw` immediately walks the same slice again to build a heap-backed `Vec<wasmi::Value>` for Wasmi. In the current soroswap trace, `Vm::invoke_function_raw` is a descendant of `applyLedger` and accounts for 181.017 ms of self-time across 8,400 calls, with the enclosing VM/SAC call tree overlapping 4.66s of the 4.33s aggregate `applyLedger` windows; the longest apply window also contains 1.112s of `SAC transfer` worker overlap. Replacing these short-lived `Vec`s with a small inline buffer type, while preserving the existing budget charges and passing slices onward, should reduce allocator traffic and cache misses in the dominant Soroban invocation path without changing deterministic execution order.

## Trigger

Run the current soroswap benchmark shape (`soroswap`, 4000 tx, 8 clusters) and inspect the apply-only Tracy trace from `ai-summary/CURRENT_STATE.md`. The issue triggers on every nested contract/SAC invocation that passes small argument lists through `Host::call_contract_fn` and, for Wasm contracts, through `Vm::invoke_function_raw`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:136-147` — `Frame` stores contract and SAC frame arguments in heap-backed `Vec<Val>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-778` — `call_contract_fn` charges, clones `args` with `args.to_vec()`, and stores the clone in the frame before dispatching the call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-410` — `invoke_function_raw` builds a second heap-backed `Vec<wasmi::Value>` from the same arguments for the Wasmi call.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` — C++ apply enters the Rust bridge for every Soroban transaction in the parallel apply path.

## Evidence

The current trace confirms this path is inside `applyLedger`: `InvokeHostFunctionOpFrame doParallelApply` overlaps 4.656s of aggregate apply time, `Vm::invoke_function_raw` overlaps 4.682s of aggregate apply time, and the `Vm::invoke_function_raw` zone itself has 181.017 ms of self-time at `soroban-env-host/src/vm.rs:400`. Structurally, the code performs two per-call argument materializations (`args.to_vec()` for the host frame and `collect::<Vec<wasmi::Value>>()` for the Wasmi call) even though soroswap's generated swaps use repeated small-arity calls, especially SAC transfers.

## Anti-Evidence

The existing budget charges must not be removed or reordered, because resource metering is consensus-visible. This is also a cross-language Soroban-env data-structure change, so the reviewer should confirm that any inline-buffer type still implements the cloning, hashing, frame inspection, and test-utils behavior currently provided by `Vec<Val>`, and that projected savings survive normalization from aggregate worker-time to wall-clock apply time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The Soroban parallel apply path enters `InvokeHostFunctionOpFrame::doParallelApply`, constructs an `InvokeHostFunctionParallelApplyHelper`, and calls the Rust bridge's `invoke_host_function` for each Soroban transaction. Inside the p26 host, contract calls flow through `Host::call_contract_fn`, which retrieves the instance, charges `Vec::<Val>::charge_bulk_init_cpy`, clones the frame arguments with `args.to_vec()`, then dispatches either to a Wasm VM frame or to the built-in SAC frame. Wasm calls then enter `Vm::invoke_function_raw`, which separately charges `Vec::<wasmi::Value>::charge_bulk_init_cpy`, converts each `Val` through `absolute_to_relative`/`marshal_from_self`, and collects those values into a second `Vec` before calling `metered_func_call`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `InvokeHostFunctionApplyHelper::invokeHostFunction` serializes apply inputs and crosses the C++/Rust bridge for each Soroban invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` confirms the invocation is on the protocol-23+ parallel apply path relevant to soroswap.
- `src/rust/src/soroban_invoke.rs:7-60` — Rust dispatch selects the protocol-specific host module and calls the p26 Soroban host implementation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:136-147` — `Frame` stores VM and SAC arguments in `Vec<Val>` and derives `Clone`/`Hash`, so any replacement must preserve those traits and slice access.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` performs the first argument materialization with `args.to_vec()` after preserving the consensus-visible bulk-copy budget charge.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-410` — `invoke_function_raw` performs the second materialization into `Vec<wasmi::Value>`, but the surrounding budget charge and absolute-to-relative object conversion must remain.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-337` — `metered_func_call` requires a slice of `wasmi::Value` and performs export lookup, VM fuel transfer, and the actual Wasmi call.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3626` — `require_auth` reads the current frame arguments and metered-clones them, so the frame must continue to own stable arguments for the duration of the call.
- `src/rust/soroban/p26/soroban-env-host/src/host/trace/fmt.rs:104-135` — trace formatting also borrows frame arguments as slices, so an inline buffer would need transparent slice semantics.

### Why It Failed

The inefficiency exists, but the recoverable portion is below the optimize-soroswap objective's Medium threshold. The cited 181.017 ms `Vm::invoke_function_raw` self-time is an upper bound over aggregate worker time for the entire function, not for the removable heap allocation alone: the budget charge, `absolute_to_relative` handle translation, `marshal_from_self`, error handling setup, and Wasmi call handoff all remain mandatory. With a current best soroswap median apply time of about 596 ms, a Medium result needs at least about 18 ms wall-clock improvement, which is roughly 144 ms of aggregate work at 8-way parallelism; the proposed change would have to remove most of the entire `invoke_function_raw` self-time, but it only removes small-arity `Vec` allocations/copies and leaves the dominant per-argument conversion work in place. SAC calls only benefit from the first `Vec<Val>` frame allocation and do not hit the Wasm-argument `Vec`, further reducing the normalized wall-clock gain.

### Lesson Learned

For parallel Soroban apply, a Tracy self-time inside a hot call path must be normalized to wall-clock apply time and reduced to the actually removable work. Small inline-buffer substitutions can be correct and locally cleaner, but they should not be promoted for this objective unless allocation-only measurements show a reproducible 3%+ apply-time reduction.
