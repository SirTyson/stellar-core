# H001: Add deterministic wasmi superinstructions for hot soroswap bytecode sequences

**Date**: 2026-05-03
**Subsystem**: transaction-ledger / Soroban VM apply
**Severity**: High
**Impact**: Soroswap apply-time reduction by restructuring a dominant `Host::invoke_function` / wasmi interpreter phase
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroswap router and pair Wasm execution should run the same translated bytecode with identical stack, memory, trap, and fuel semantics, but the interpreter should avoid paying one large `match` dispatch and one helper call for every tiny straight-line instruction when common instruction sequences are known after module translation. A correct optimized path would fuse only deterministic, side-effect-equivalent instruction sequences and leave `ConsumeFuel`, traps, host imports, and observable call boundaries in the same relative order.

## Mechanism

The pinned `soroban-wasmi` executor still interprets one `Instruction` at a time in `Executor::execute`, dispatching through a very large `match` and per-op `visit_*` helper calls for each Wasm instruction. Prior quickening investigations failed when they targeted `ModuleCache` as if it still held raw Wasm, but the remaining opportunity is lower in the stack: add fused bytecode variants during wasmi translation for high-frequency straight-line sequences and execute each fused variant with one dispatch while performing the same primitive stack operations internally.

This would not change determinism because the fused instruction stream is derived deterministically from already-validated wasmi bytecode, and it would not change metering if block-level `ConsumeFuel` instructions remain in place and no host-call or trap boundary is crossed by a fusion. The improvement theory is that soroswap spends a dominant amount of apply time in repeated guest-code execution; reducing interpreter dispatch overhead on the router/pair hot loops should reduce the critical worker time without changing ledger output.

## Trigger

Run the current soroswap apply-load matrix with the Tracy trace recorded in `ai-summary/CURRENT_STATE.md`, then add a temporary counter in the pinned wasmi translator or executor to report the most frequent adjacent instruction pairs/triples executed under `Host::invoke_function`. Implement fused `Instruction` variants for the top straight-line sequences that do not include `ConsumeFuel`, calls, branches, memory growth, or traps, and compare three non-Tracy `soroswap, TX=2000, T=8` runs against the current 270-276 ms median range.

## Target Code

- `src/rust/soroban/p26/Cargo.lock:1756-1758` — pins `soroban-wasmi` to `0.31.1-soroban.20.0.1`; a PoC would need a forked/patched dependency, not a local `ModuleCache` artifact.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/executor.rs:224-430` — `Executor::execute` dispatches one internal `Instruction` at a time through a large match loop.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/bytecode/mod.rs:37-145,207-260` — internal `Instruction` enum already differs from raw Wasm and is the place to add deterministic fused variants.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/engine/func_builder/inst_builder.rs:129-202` — `InstructionsBuilder` currently pushes one instruction at a time and finalizes the translated function body; this is the natural fusion point after branch offsets are resolved.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — Soroban calls into wasmi through `Vm::invoke_function_raw`, which marshals args and then enters the interpreter.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-480` — each apply-path host invocation reaches `Host::invoke_function` after enforcing storage setup.

## Evidence

- Current Tracy validation from the recorded soroswap trace shows all target zones inside `applyLedger` windows: `Host::invoke_function` totals **9,824,196,894 ns** over 6,776 calls; `Vm::invoke_function_raw` totals **12,842,366,133 ns** over 20,313 calls; and the wasmi/host-call `call` zone totals **9,353,235,883 ns** over 40,605 calls. These are descendants of `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply`.
- The executor source has a structural interpreter-dispatch pattern: every instruction hits one match arm and a helper such as `visit_local_get`, `visit_i32_add`, `visit_i64_load`, or `visit_call_internal`. Soroswap repeats the same router/pair Wasm many times, so a small set of bytecode sequences should dominate instruction execution.
- This is different from the failed `deterministic-wasmi-bytecode-quickening` investigation: that failure established that `ParsedModule` already contains translated wasmi bytecode, while this hypothesis works inside the pinned wasmi translator/executor where that bytecode is produced and executed.
- The hypothesis targets a dominant phase rather than a micro-zone. Even a low double-digit reduction in guest interpreter dispatch inside the `Host::invoke_function` envelope is plausibly Medium on soroswap; a broader executor redesign qualifies as High if it materially restructures this dominant phase.

## Anti-Evidence

- The cited `Host::invoke_function` and `Vm::invoke_function_raw` totals are inclusive; a PoC must add an opcode or bytecode-sequence histogram to isolate interpreter dispatch from mandatory contract logic, host calls, memory accesses, and budget/fuel work.
- Fusion must not cross `ConsumeFuel`, branch, call, host-import, memory-growth, or trap boundaries. Crossing any of these could change trap timing, fuel exhaustion timing, or host-visible behavior.
- Adding many fused variants can bloat the bytecode enum and instruction cache. The first PoC should be limited to the top few measured sequences from the soroswap trace and should be gated by deterministic translation logic, not workload-specific contract hashes.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger soroswap benchmark builds the transaction set outside the measured interval and times `closeLedger`, which applies Soroban transactions through the parallel apply path and waits for the cluster workers. Each invoke-host operation crosses the Rust bridge into `e2e_invoke::invoke_host_function`, constructs enforcing host state, then calls `Host::invoke_function`; Wasm contracts dispatch through `Host::call_contract_fn`, `Vm::invoke_function_raw`, `wasmi::Func::call`, and finally `EngineExecutor::execute_wasm_func` / `Executor::execute`. The pinned wasmi executor is a true bytecode interpreter with one large `match` per internal `Instruction`, and the current baseline records soroswap medians around 270-276 ms, so eliminating repeated dispatch inside the VM envelope is plausibly Medium if the PoC first proves a concentrated hot sequence set.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:50,67` — prior wasmi failures cover host-function dispatch trampolines and a wrong `ModuleCache` quickening target; the quickening failure explicitly says future VM-dispatch work must target the pinned wasmi translator/executor, so this hypothesis is adjacent but not a duplicate.
- `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md:57-74` and `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:57-74` — existing confirmed transaction-ledger findings target host storage setup / SAC conversion, not wasmi interpreter superinstructions.
- `ai-summary/CURRENT_STATE.md:41-54,71-84` — the accepted current baseline is three non-Tracy soroswap `TX=2000, T=8` medians of 272.250 / 275.886 / 270.551 ms, with Tracy used only for attribution.
- `scripts/run_apply_load_matrix.py:417-429` — the matrix sets `APPLY_LOAD_MAX_SOROBAN_TX_COUNT` and `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` for the measured soroswap scenario.
- `src/simulation/ApplyLoad.cpp:2261-2308` — model transaction vectors are generated before the sampled `closeLedger` call, keeping contract execution and ledger apply inside the measured interval while excluding tx construction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:439-481` — each Rust apply invocation builds storage/host state, installs auth/ledger/module context, and reaches the `Host::invoke_function` Tracy span.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts invoke arguments and calls `call_n_internal`, with returned host values converted back to `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — Wasm contract calls instantiate or retrieve a VM, push a `Frame::ContractVM`, and invoke `vm.invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-390` — `metered_func_call` resolves the exported wasmi function, synchronizes host budget/fuel to the VM, calls `func.call`, returns remaining fuel to the host, and translates traps/results.
- `src/rust/soroban/p26/Cargo.lock:1756-1758` — Stellar pins `soroban-wasmi` to git revision `0ed3f3dee30dc41ebe21972399e0a73a41944aa0`, so a PoC must patch the forked dependency and update the lock/submodule state rather than adding a local Stellar-side artifact.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/func/mod.rs:392-406` — `wasmi::Func::call` verifies inputs/outputs and delegates to `Engine::execute_func`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/mod.rs:723-815` — `EngineExecutor::execute_wasm_func` loops over `execute_wasm`, dispatches host calls when encountered, and otherwise continues executing guest bytecode.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:100-112,224-446` — `execute_wasm` constructs an `Executor`, and `Executor::execute` loops over one `Instruction` at a time through a large match until return, trap, or host call.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/executor.rs:845-850,961-965,1023-1030,1373-1405,1565-1590` — `ConsumeFuel`, local access, calls, loads, and arithmetic are implemented as small visit methods; these are `#[inline(always)]`, so the reliable removable cost is dispatch / instruction-pointer stepping rather than guaranteed Rust function-call overhead.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/bytecode/mod.rs:37-145,207-360` — the internal `Instruction` enum already contains wasmi-specific bytecode variants and compact constant forms; fused variants belong here if measurement identifies stable hot sequences.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/func_builder/inst_builder.rs:129-202` and `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/code_map.rs:170-187` — `InstructionsBuilder` pushes translated instructions, resolves branch offsets in `finish`, and drains them into the engine code map, giving a deterministic translation-time hook for measured fusion.

### Findings

The inefficiency exists: the wasmi hot path is a pure interpreter loop that fetches an internal instruction word, dispatches through a large match, performs a small primitive stack/memory/global operation, then advances the instruction pointer. Existing optimizations mitigate other costs — block fuel is represented by explicit `ConsumeFuel` instructions, internal calls use `CallInternal`, and constants have compact variants — but there is no existing superinstruction or adjacent-instruction fusion layer in the pinned executor.

The path is hot for this objective. Soroswap router/pair Wasm execution is under `Host::invoke_function` inside `closeLedger`, and the benchmark's tx construction is outside the measured `closeLedger` interval. The cited VM/host timing is inclusive, so the review does not accept the original High severity as proven, but the source trace shows a broad dominant VM execution envelope and no architectural blocker to a deterministic translator/executor fusion. A Medium finding is justified if the PoC first adds counters showing that a small number of straight-line pairs/triples account for enough executed instructions to move the 270-276 ms median by at least 3%.

The proposed fix can preserve correctness, but only with stricter constraints than the hypothesis states. Fusion must not cross `ConsumeFuel`, branch, call, host import, memory growth, memory/table bulk operation with traps, `Unreachable`, fallible numeric operation, or any instruction where trap timing or resource-limiter interaction could change. It also must not make a branch target land inside a fused sequence; the lowest-risk representation is to replace the first instruction word with a fused variant that skips the remaining original words as payload, preserving instruction indices and branch offsets, and to fuse only when no interior word is a branch target. Because visit helpers are marked `#[inline(always)]`, the PoC should frame the win as reducing interpreter dispatch and instruction-pointer traffic, not as removing guaranteed non-inlined helper calls.

### PoC Guidance

- **Target code**: patch the pinned `soroban-wasmi` fork at `crates/wasmi/src/engine/bytecode/mod.rs`, `crates/wasmi/src/engine/executor.rs`, and `crates/wasmi/src/engine/func_builder/inst_builder.rs`; update `src/rust/soroban/p26/Cargo.lock` to the patched git revision.
- **Change description**: first add temporary deterministic counters for adjacent instruction pairs/triples executed under soroswap, excluding `ConsumeFuel`, control-flow, calls/imports, fallible traps, and memory/table resource-limiter operations. Then add only the top measured fused variants, preferably encoded as first-word fused instructions that skip preserved payload words so branch offsets and function instruction references remain stable.
- **Correctness check**: existing Soroban VM / host tests should continue to cover traps, fuel exhaustion, host imports, and invoke-host behavior; add wasmi-level tests in the patched dependency for branch targets at fusion boundaries, fuel-before/after fused runs, and trap timing for excluded instructions.
- **Benchmark focus**: compare three non-Tracy `soroswap, TX=2000, T=8` runs against the `ai-summary/CURRENT_STATE.md` baseline medians of 272.250 / 275.886 / 270.551 ms. The PoC must show at least a reproducible 3% top-line apply-time reduction and should report the instruction histogram plus the percentage of executed guest bytecode covered by each fused variant.
