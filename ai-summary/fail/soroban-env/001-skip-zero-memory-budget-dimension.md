# H001: Skip zero-memory budget-dimension work for zero-memory cost types

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing protocol-invisible memory-dimension evaluation from millions of hot budget charges
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every `Budget::charge` call should preserve the current protocol-visible charge count, CPU totals, memory totals, tracker-visible totals, and budget-limit behavior. For cost types whose memory cost model is exactly zero (`const_term == 0 && lin_term == 0`), charging should still update CPU accounting and report `mem == 0`, but it should not physically look up, evaluate, or add a zero-valued memory cost on every call.

## Mechanism

`BudgetImpl::charge` always calls both `self.cpu_insns.charge(...)` and `self.mem_bytes.charge(...)` for every cost type. In p26, many of the hottest soroswap cost types have a zero memory model, including `WasmInsnExec`, `DispatchHostFunction`, `VisitObject`, `MemCpy`, and `MemCmp`, so the memory half of those charges repeatedly performs array lookup, model evaluation, saturating addition of zero, and tracker update for no resource-accounting effect. A precomputed zero-memory-cost bitset or per-cost flag in `BudgetImpl` could set `mem_charged = 0` directly for these cost types, optionally keeping the cheap memory-limit check to preserve edge-case behavior, while leaving CPU charging and public totals identical.

## Trigger

Run the current soroswap diagnostic trace from `ai-summary/CURRENT_STATE.md` and export self-time with `lib/tracy/csvexport/build/unix/csvexport-release -e`. The trace reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 2,043.955 ms self-time over 18,721,841 calls. Sampled exact `charge` events from unwrap mode fall inside `applyLedger` windows, and the source call path is the Soroban apply path (`applyLedger` -> `InvokeHostFunctionOpFrame::invokeHostFunction` -> Rust `invoke_host_function` -> `Host::invoke_function` -> host budget charges).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` always evaluates both CPU and memory dimensions for every charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` performs the cost-model lookup/evaluation and updates total counts even when the amount is zero.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:697-722` — examples of zero memory models for `WasmInsnExec`, `DispatchHostFunction`, and `VisitObject`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:707-710` — `MemCpy` has zero memory cost despite being one of the most common metering cost types.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — linear cost-model evaluation still runs even when both coefficients are zero.

## Evidence

- Tracy scope check: the target `charge` zone appears during sampled `applyLedger` intervals; the Rust host budget is charged from `Host::invoke_function` and SAC/VM execution beneath close-ledger apply, not TX-set construction.
- The trace reports `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` with 5,774.332 ms total time across 69 events, while `charge` alone contributes 2,043.955 ms self-time across 18.7 million events in the same run. This is large enough that shaving even a modest fraction of physical charge overhead can clear the 3% Medium floor.
- The proposed change does not reduce the number of `Budget::charge` calls, so it avoids the prior failed pattern where changing `ValSer`/`MemCpy` charge counts altered exact `cpu_insns`/`mem_bytes`.
- Zero-memory cost types dominate several hot paths visible in the same trace: `VisitObject` is charged inside `visit host object` (2,689,616 calls), `DispatchHostFunction` is charged once per Wasm host call, and `MemCpy` backs map binary-search access, conversion/allocation helpers, and many storage/event paths while contributing no memory total.
- The optimization is deterministic and local: cost models are fixed when the `Budget` is constructed, and the zero-memory predicate is a pure property of that budget's memory cost table.

## Anti-Evidence

- The whole 2.044 s `charge` zone is an upper bound: CPU-dimension evaluation, `RefCell` borrowing in `Budget::charge`, tracker updates, and Tracy instrumentation remain unless separately optimized.
- If any code can lower the memory limit below the already-consumed total and then rely on a later zero-memory charge to report `ExceededLimit`, the fast path must retain `mem_bytes.check_budget_limit(...)` even when it skips `mem_bytes.charge(...)`.
- Network configuration can technically set nonzero memory parameters for any cost type. The fast path must be data-driven from the actual `BudgetImpl.mem_bytes.cost_models`, not hard-coded to today's default table.
- This overlaps with, but is not a duplicate of, prior budget failures: those rejected reducing charge counts or caching budget construction; this preserves charge counts and skips only zero-valued physical memory-dimension evaluation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The Soroban apply path reaches this budget code through `InvokeHostFunctionOpFrame::invokeHostFunction`, the Rust bridge, `e2e_invoke::invoke_host_function`, and then either VM dispatch/fuel accounting or host-object/memory helper charges under `Host::invoke_function`. The source-level inefficiency is real: `BudgetImpl::charge` updates the tracker, charges CPU, checks the CPU limit, charges memory, updates memory tracker fields, and checks the memory limit even when the selected memory cost model evaluates to zero. However, the performance evidence used to justify Medium severity is not evidence for this removable production work: the cited `dimension.rs:176` `charge` zone is `#[cfg(feature = "tracy")]`, is emitted only for the CPU dimension, and is absent from non-Tracy benchmark builds. After subtracting Tracy-only instrumentation and mandatory CPU/tracker/limit work, skipping a zero memory lookup/evaluate/add is a micro-optimization with no credible path to the objective's 3% apply-time floor.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — Soroban transaction application crosses from C++ into `rust_bridge::invoke_host_function` during ledger apply.
- `src/rust/src/soroban_proto_any.rs:391-448` — the Rust bridge constructs a `Budget` from CPU and memory cost params and calls the protocol-specific p26 host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — enforcing-mode invocation builds storage, constructs the `Host`, installs ledger/auth/module-cache state, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `InvokeContract` enters the contract-call path; returned values are converted back to XDR after invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-410` and `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — VM execution returns consumed wasmi fuel through `bulk_charge(WasmInsnExec, fuel, None)`, one of the zero-memory hot charge types.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — each Wasm host-function boundary charges `WasmInsnExec` and `DispatchHostFunction` before/after invoking the actual host function.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-517` — host object visits charge `VisitObject`, another hot default-zero-memory type.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:55-73` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:98-145` — metered copies and comparisons charge `MemCpy` / `MemCmp`; their default memory models are zero but their CPU charges and tracker inputs remain protocol-visible.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` always performs both dimension charges and both limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:143-188` — `BudgetDimension::charge` evaluates a cost model, emits the Tracy `charge` span only for `_is_cpu.0`, and updates the relevant total; the memory call never emits the cited span.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — zero `const_term` and zero `lin_term` evaluate to zero cheaply, with the linear multiply path already skipped when `lin_term.is_zero()`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:692-722` — default p26 memory parameters for `WasmInsnExec`, `MemCpy`, `MemCmp`, `DispatchHostFunction`, and `VisitObject` are zero, confirming the mechanism exists for current default configs.
- `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs:440-455` — exact budget debug output expects zero memory totals for these cost types but still observes iterations/inputs/cpu totals, constraining any safe change to preserve reporting.
- `ai-summary/fail/soroban-env/summary.md:9-18,22-33` and `ai-summary/fail/soroban-env/011-eliminate-is-clean-fuel-check.md:100-124` — no duplicate finding; prior failures establish that Tracy-only self-time and tiny per-dispatch budget-boundary savings do not meet this objective's severity threshold.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:44-53,88-97` — a broader non-Tracy storage-map optimization measured only a 2.17% median soroswap improvement, making this narrower per-charge micro-optimization implausible as Medium without direct non-Tracy evidence.

### Why It Failed

The proposed fast path is probably correctness-preserving if it is data-driven from the actual memory cost table, still validates the expected `input` shape, leaves tracker iterations/inputs/cpu accounting untouched, sets `tracker.mem += 0`, and retains the memory limit check. But the objective is not "any technically valid micro-optimization"; it requires a credible 3-10% apply-time reduction.

The cited 2.044 s `charge` self-time cannot support that projection. In the source, the `charge` Tracy span starts at `dimension.rs:176` inside `#[cfg(all(not(target_family = "wasm"), feature = "tracy"))] if _is_cpu.0`, so it measures Tracy instrumentation on CPU-dimension charges in diagnostic builds, not memory-dimension work in production. The memory dimension's removable work for zero-cost models is only an array lookup, a zero cost-model evaluation, a saturating add of zero to the memory total, a zero add to `tracker.mem`, and the non-Tracy function-call/control-flow around those operations. CPU charging, RefCell borrow, tracker meter count, tracker iterations/inputs, CPU limit check, and memory limit check all remain. With the linear multiply path already skipped for zero `lin_term`, there is no basis to project this remaining production subset above the optimize-soroswap Medium floor; it is rejected as below the objective severity threshold.

### Lesson Learned

For Soroban budget hypotheses, a Tracy `charge` zone at `BudgetDimension::charge` is especially easy to misread: in p26 it is compiled only with Tracy and only around CPU-dimension instrumentation, while memory-dimension charges do not emit that span at all. Future zero-cost metering optimizations need either non-Tracy benchmark evidence or focused instrumentation that isolates production memory-dimension overhead after subtracting mandatory CPU/tracker/limit work.
