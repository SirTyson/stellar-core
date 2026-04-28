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
