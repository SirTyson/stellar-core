# H002: Compile-time basic-block dispatch for hot wasmi straight-line code

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban VM execution
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing interpreter dispatch overhead in router and pair Wasm execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban Wasm execution should preserve wasmi's deterministic instruction semantics, fuel accounting, traps, stack behavior, and host-call boundaries while avoiding avoidable interpreter overhead for straight-line blocks that contain no host call or branch target. For soroswap router/pair contracts, long runs of ordinary Wasm arithmetic, local access, comparisons, and memory operations should execute with fewer top-level `match` dispatches while charging the same `ConsumeFuel` amounts and producing identical guest-visible results.

## Mechanism

The pinned soroban-wasmi executor runs every internal bytecode instruction through a single large `match *self.ip.get()` loop in `Executor::execute`. The bytecode already contains a few compile-time peepholes such as `LocalGet2`, `LocalGetI32Add`, and `LocalGetI64Add`, but most straight-line instruction sequences still advance through one enum dispatch, stack-pointer operation, and instruction-pointer update per instruction.

A compile-time basic-block instruction emitted by the wasmi translator for closed, straight-line spans can execute several existing bytecode operations in one specialized helper, stopping before branches, calls, traps, memory growth, and any instruction with externally visible side effects. This differs from a runtime superinstruction pattern-match: the translator would build the block once in the module's existing deterministic bytecode, reuse existing `ConsumeFuel` block fuel, and let the executor fall back to the current instruction-by-instruction loop for unsupported or rare patterns.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Inside `applyLedger`, `Vm::invoke_function_raw` accounts for 12,842.366 ms across 20,313 calls, `call` from the wasmi dispatch boundary accounts for 9,353.236 ms across 40,605 host imports, and `Host::invoke_function` accounts for 9,824.197 ms across 6,776 invocations. After current SAC/storage-map optimizations, the remaining Medium-sized soroswap opportunity is the VM execution envelope rather than C++ prefetch, bucket writes, or per-entry storage-map glue.

## Target Code

- `src/rust/soroban/p26/Cargo.toml:46-50` — pins the soroban-wasmi fork and revision that would receive the executor/translator change.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/bytecode/mod.rs:37-45` — current internal bytecode already includes limited compile-time fused opcodes (`LocalGet2`, `LocalGetI32Add`, `LocalGetI64Add`, etc.), showing the interpreter accepts deterministic fused instructions.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/executor.rs:224-451` — `Executor::execute` performs a large per-instruction enum dispatch and calls small helpers for each ordinary instruction.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/executor.rs:504-560` — generic unary/binary helpers update the value stack and instruction pointer one instruction at a time.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/func_builder/translator.rs:209-240` — translator infrastructure already manages `ConsumeFuel` instructions during compilation, so a block opcode can preserve fuel accounting at translation time.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — every router/pair Wasm function call enters the wasmi executor through `Vm::invoke_function_raw`.

## Evidence

- Tracy scope check: the cited VM zones are descendants of `applyLedger` through `InvokeHostFunctionOpFrame doParallelApply` and `e2e_invoke::invoke_function`; they are not TX-set construction zones.
- The current trace's in-apply aggregation shows `Vm::invoke_function_raw` at 12.842 s of aggregate worker time. Normalized by 8 soroswap clusters and 71 apply windows, the whole VM-call envelope is roughly 22.6 ms per ledger on the critical path, so a redesign that removes about one third of interpreter dispatch/stack-step overhead can reach the 3-10% Medium band on the 272 ms soroswap baseline.
- Source inspection shows wasmi already uses deterministic internal bytecode and compile-time fusion for a small set of local-get arithmetic patterns. Extending that idea to basic-block helpers avoids the prior runtime-superinstruction trap of adding a pattern check to every instruction dispatch.
- The proposal does not exceed `NUM_CLUSTERS`, does not change transaction ordering, and does not introduce native CPU-dependent code generation; it remains an interpreter change over deterministic bytecode.

## Anti-Evidence

- Previous VM-dispatch ideas failed when they targeted reusable instances, AOT/native compilation, generic host-call trampolines, or runtime superinstructions. This hypothesis is only viable if the PoC proves the fused blocks are emitted at translation time with no per-instruction runtime pattern matching and with a measured reduction in the wasmi executor portion of `Vm::invoke_function_raw`.
- Inclusive VM Tracy zones include mandatory host calls, fuel settlement, argument conversion, storage operations, and guest logic. The PoC must add narrower counters or spans around straight-line executor dispatch to avoid attributing non-removable host work to the block executor.
- Any fused helper must preserve exact trap points that are consensus-visible through transaction success/failure and budget use. Blocks should initially exclude fallible memory/table growth, host calls, indirect calls, branches, and operations with non-trivial trap behavior until equivalence is proven.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior transaction-ledger fail/success records include related wasmi dispatch attempts, but not this exact compile-time basic-block opcode design
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this code through parallel Soroban apply: `InvokeHostFunctionOpFrame::doParallelApply` calls the Rust bridge, the p26 host invokes `Host::invoke_function`, and user Wasm calls enter `Vm::invoke_function_raw` before `wasmi::Func::call` runs the interpreter. The claimed per-instruction dispatch loop exists, and the pinned wasmi fork already performs compile-time pair fusion in `InstBuilder::fuse_superinstructions`. However, the hypothesis's own Tracy numbers show that most of the broad VM envelope is imported host-call work, not removable straight-line interpreter dispatch. Even an unrealistically perfect removal of all non-import time in `Vm::invoke_function_raw` falls below the objective's Medium floor.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — serializes Soroban operation inputs and calls `rust_bridge::invoke_host_function` during apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol-23+ Soroban operations execute this path from `doParallelApply`.
- `src/rust/src/soroban_invoke.rs:7-38` — dispatches the C++ bridge call to the protocol-specific host module.
- `src/rust/src/soroban_proto_any.rs:310-354,391-448` — wraps p26 invocation, creates the budget, and calls the host's `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — builds enforcing host state and enters `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1148` — `HostFunction::InvokeContract` converts invoke args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — Wasm contract frames instantiate the VM and call `Vm::invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-337,393-411` — `invoke_function_raw` converts arguments, then `metered_func_call` performs export lookup, fuel transfer, and `wasmi::Func::call`.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/mod.rs:723-771` — wasmi repeatedly executes Wasm until a return or imported host call, then services host calls outside the straight-line executor loop.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/executor.rs:224-451,624-651` — `Executor::execute` does one enum dispatch per bytecode instruction; imported host functions exit through `WasmOutcome::Call`, which a basic-block helper cannot eliminate.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/bytecode/mod.rs:37-45` and `func_builder/inst_builder.rs:199-235` — existing deterministic compile-time fusion already emits `LocalGet2` and local-get arithmetic opcodes.
- `/home/garand/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/func_builder/translator.rs:204-245,491-674` — instruction translation already accumulates block fuel through `ConsumeFuel`, so any broader block opcode would need to preserve those existing fuel totals.

### Why It Failed

The optimization target is real, but its projected impact is below the objective's accepted severity threshold. Using the hypothesis's own in-apply aggregate numbers, `Vm::invoke_function_raw` totals 12,842.366 ms while imported host `call` work totals 9,353.236 ms. Since wasmi host imports are reached from `Func::call` but execute outside the removable straight-line bytecode loop, an optimistic upper bound for everything left in the VM envelope is about 3,489 ms aggregate, or roughly 6.1 ms per ledger after dividing by 8 clusters and 71 apply windows. On the stated 272 ms soroswap baseline that is about 2.3%, and a real basic-block implementation would recover only a fraction of that after preserving export lookup, fuel transfer, argument/result conversion, interpreter work that cannot be fused, existing pair fusion, and exact trap/fuel semantics.

Under the optimize-soroswap objective, Low-severity findings are rejected even when technically correct. This hypothesis therefore does not clear the 3-10% Medium apply-time floor, and the broad VM/import Tracy scopes are not sufficient evidence for a Medium-sized straight-line dispatch opportunity.

### Lesson Learned

For VM-dispatch hypotheses, decompose `Vm::invoke_function_raw` into imported host-call time, VM boundary overhead, and pure executor self-time before projecting apply-time impact. Compile-time fusion avoids the prior runtime-pattern-match problem, but it still cannot claim inclusive host-import and host-execution time as removable interpreter dispatch overhead.
