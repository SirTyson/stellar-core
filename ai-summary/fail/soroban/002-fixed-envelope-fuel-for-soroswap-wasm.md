# H002: Fixed-Envelope Fuel Mode for Allowlisted Soroswap Wasm

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing per-basic-block wasmi fuel bookkeeping for fixed router/pool modules while keeping Wasm semantics and host-call ordering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-next ledgers, successful executions of the vendored Soroswap router and pool modules should produce the same ledger state, events, return values, auth consumption, host-call order, and Wasm trap behavior as the current wasmi backend. The optimization should only change CPU metering for exact allowlisted module hashes: instead of eager wasmi fuel consumption inside the interpreter, the host charges a deterministic fixed CPU envelope for a matched export before entering Wasm and still charges every host import normally. If the hash, export, protocol, or declared resource envelope does not match, execution should use the existing fuel-metered wasmi path.

## Mechanism

The current p26 host builds its shared wasmi engine with `consume_fuel(true)` and `FuelConsumptionMode::Eager`, supplies remaining budget as fuel before each VM run or host-return boundary, drains consumed fuel on every VM -> host import, and refills fuel after every host import. That preserves p26 instruction metering but leaves fuel checks in the interpreter loop for every successful router/pool invocation. For the fixed Soroswap modules, a protocol-next `ModuleCache` sidecar can store a second no-fuel `wasmi::Engine`/`Module` plus a per-export deterministic CPU envelope measured from the current fuel schedule; invocation would pre-charge that envelope once, execute the same Wasm code without internal fuel metering, and continue to use the existing dispatch wrappers for all host functions.

## Trigger

Run the current soroswap apply-load benchmark with a protocol-next build that enables no-fuel execution only for:

1. router hash `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`, export `swap_exact_tokens_for_tokens`;
2. pool hash `18051456816b66f12e773a56f77c5794fac1b1fb7ab6e22d4fad5a412770f73e`, export `swap`; and
3. optional getter exports already covered by native getter work for A/B isolation.

The PoC should force fallback for comparison, byte-compare outputs/meta, and show lower `Vm::invoke_function_raw` residual time while `call` host-dispatch counts remain comparable.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` — current global wasmi config enables eager fuel metering.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` and `85-95` — module cache owns the shared engine/linker and can grow a protocol-next no-fuel sidecar for exact hashes.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — VM construction can select the no-fuel module/engine for allowlisted parsed modules.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — function invocation keeps the same argument conversion and Wasm entry point.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — fuel return/refill becomes a no-op for the no-fuel VM while the fixed envelope has already been charged.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — host-call dispatch should still charge `DispatchHostFunction`, marshal args/results, execute the host function, and preserve host-call ordering.

## Evidence

The current trace puts the VM work under `applyLedger`: `Vm::invoke_function_raw` totals **12,652,494,561 ns** over **13,983** calls, `call` host-dispatch totals **9,356,083,872 ns**, and `Vm::instantiate_wasmi - instantiate` contributes **827,245,199 ns**. Subtracting mandatory host-dispatch time leaves roughly **3.3s aggregate VM-side residual** in the trace, before considering eager fuel checks embedded in interpreted basic blocks. The source confirms fuel is active globally (`consume_fuel(true)`, `FuelConsumptionMode::Eager`) and is synchronized at every VM/host boundary via `FuelRefillable`, so an allowlisted no-fuel backend attacks a concrete VM execution cost rather than TX-set construction.

This differs from prior lazy fuel-sync micro-optimizations: the proposal does not merely skip a few boundary counter reads. It removes eager interpreter fuel bookkeeping for exact fixed Wasm hashes while preserving the same host imports and ledger semantics, and it is protocol-next only. If most of the non-host-call VM residual is fuel bookkeeping, the normalized saving is in the Medium range for the current ~250 ms soroswap median.

## Anti-Evidence

This changes CPU metering semantics and is only acceptable behind a new protocol gate with p26 unchanged. It must prove that out-of-fuel behavior is not user-observable in a way the fixed-envelope charge would reorder: if a contract can catch or depend on a mid-function fuel trap, this is not viable. The measured residual also includes ordinary interpreter dispatch and Wasm arithmetic, not only fuel checks; if instrumentation shows fuel bookkeeping is a small fraction of the 3.3s residual, this falls below Medium and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prior records cover lazy fuel synchronization, wasmi fuel coalescing, and compiled/native backends, but not this exact fixed-envelope no-fuel sidecar
**Failed At**: reviewer

### Trace Summary

The Soroswap apply path reaches Wasm execution through `LedgerManagerImpl::applyLedger -> applyTransactions -> InvokeHostFunctionOpFrame::doParallelApply -> rust_bridge::invoke_host_function -> e2e_invoke -> Host::call_contract_fn -> Vm::invoke_function_raw`. The p26 host does enable wasmi fuel and drains/refills it at every VM/host boundary, but the pinned wasmi translator already coalesces normal instruction fuel into `Instruction::ConsumeFuel(BlockFuel)` entries at function/control-flow block boundaries rather than charging every interpreter opcode individually. A no-fuel sidecar would therefore remove only those `ConsumeFuel` bytecodes/checks plus associated store fuel accounting; it would not remove host dispatch, host-function bodies, argument/result marshalling, ordinary interpreter dispatch, arithmetic, memory operations, or VM instantiation.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1461-1688` — ledger close enters the timed apply path and calls `applyTransactions`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` and `982-1017` — Soroban operation apply calls the Rust bridge and records returned host output.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — parallel Soroban apply uses the same host invocation helper under `closeLedger`.
- `src/rust/src/soroban_proto_any.rs:391-466` — bridge constructs a per-invocation budget, calls protocol-specific host invocation, and reads final CPU/memory totals.
- `src/rust/src/soroban_proto_any.rs:700-736` — protocol module cache only caches parsed modules in the current wasmi engine.
- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:117-137` — the p26 engine config enables fuel metering with `FuelConsumptionMode::Eager`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` and `787-900` — contract calls instantiate a fresh `Vm` from the cached `ParsedModule`, push a contract frame, and invoke the export.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:271-345` and `393-412` — invocation converts args, charges `InvokeVmFunction`, supplies fuel, calls wasmi, and drains consumed fuel back into the host budget.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — fuel transfer converts remaining budget to wasmi fuel and bulk-charges consumed fuel as `WasmInsnExec`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every host import still drains fuel, charges dispatch, marshals args/results, executes the host function, and refills fuel.
- `src/rust/soroban/p26/Cargo.toml:46-50` and `soroban-wasmi@0ed3f3d:engine/func_builder/translator.rs:149-245,491-533,1216-1312` — the pinned wasmi translator creates and bumps block-level `ConsumeFuel` instructions.
- `soroban-wasmi@0ed3f3d:engine/executor.rs:241,703-785,845-849` — the interpreter executes `ConsumeFuel` bytecodes and eager bulk-operation fuel charges.
- `src/rust/soroban/p26/soroban-env-host/src/host/error.rs:144-166` and `src/rust/soroban/p26/soroban-env-host/src/test/invocation.rs:380-438` — budget-limit errors are non-recoverable, so contracts cannot gracefully catch out-of-fuel through `try_call`.
- `ai-summary/fail/soroban/summary.md:85,111,130` — nearby prior failures show lazy boundary fuel synchronization is below Medium, compiled/native VM backends require a concrete deterministic backend and isolated measurements, and wasmi already coalesces normal instruction fuel by block.

### Why It Failed

The inefficiency exists, but its objective impact is below the Medium threshold. The hypothesis's own upper bound subtracts mandatory host-dispatch time from `Vm::invoke_function_raw`, leaving about 3.3s aggregate worker time; normalized by 8 Soroswap clusters over 71 apply windows, that is only about 5.8ms per ledger. That is below the 3% Medium floor even against the older ~250ms median, and it is only an upper bound: a no-fuel engine can remove only `ConsumeFuel` bytecodes/checks, while ordinary interpreter dispatch and Wasm computation remain. The prior summary also records that the pinned wasmi translator already coalesces instruction fuel per block, so there is no per-opcode fuel charge stream large enough to plausibly recover the missing percentage.

Fixed-envelope precharging also has correctness caveats for failure cases: current execution charges Wasm fuel incrementally before host calls and after returns, while precharging the full export envelope can move a budget failure earlier than the current path. Budget failures are non-recoverable, so this is not catchable by guest `try_call`, but it can still change failed-call diagnostic/order behavior and would require a new protocol metering specification. Given the sub-Medium performance ceiling, those protocol-risk costs are not justified for this objective.

### Lesson Learned

Do not size no-fuel or fuel-metering proposals from broad `Vm::invoke_function_raw` totals. First subtract mandatory host dispatch, normalize aggregate worker time by cluster count and ledger count, then isolate the actual `ConsumeFuel` subset; with the current pinned wasmi, block-level fuel checks alone are below the optimize-soroswap review threshold.
