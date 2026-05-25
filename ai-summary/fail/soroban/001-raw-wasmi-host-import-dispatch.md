# H001: Raw wasmi Host-Import Dispatch for Soroswap Hot Calls

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce Soroswap apply time by replacing the generic `Func::wrap` host-import trampoline with a compact protocol-gated raw dispatch ABI
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When Soroswap router Wasm calls Soroban host functions during `closeLedger`, the VM should execute exactly the same host functions, in the same order, with the same argument validation, relative/absolute object translation, fuel transfer, budget charges, traps, and return values. The import boundary should not need to pay the full generic wasmi `Func::wrap` tuple-adaptation path for every hot host call once the module has already been validated against the fixed Soroban host-function table.

## Mechanism

`Host::make_*_wasmi_linker` currently registers every import through `HostFuncInfo::wrap`, which calls `linker.func_wrap($mod_str, $fn_id, dispatch::$func_id)`. Every guest import call then re-enters a generated wrapper at `vm/dispatch.rs:216-304` that performs wasmi ABI adaptation, constructs a `VmCaller`, converts each `i64` through typed wrapper helpers, calls the host method, converts the result, and refills VM fuel. A next-protocol raw import ABI could resolve imports to compact `HostFuncId`s during module validation and route all imports through one raw `(&mut Store<Host>, HostFuncId, &[i64]) -> Result<i64, Trap>` dispatcher, preserving the same semantic steps while removing the per-function `Func::wrap` tuple/trampoline layer and generated wrapper duplication.

## Trigger

Run the accepted soroswap apply-load scenario from `ai-summary/CURRENT_STATE.md` (`TX=2000, T=8`) with the diagnostic trace `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`. Successful router invocations repeatedly cross the Wasm host-import boundary for object, bytes, auth, storage, crypto, and contract-call host functions while applying Soroswap swaps.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:42-80` — every host import is currently registered with `linker.func_wrap(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:216-304` — generated host-function wrapper body that performs typed argument/result conversion, error escalation, and fuel refill per import call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:265-268` — per-module linker construction from imported symbols.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:85-95` — maximal shared linker construction used by the module cache.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-390` — VM call/fuel boundary that must remain semantically equivalent.

## Evidence

- Current soroswap Tracy self-time from `csvexport-release -e`: `call` at `soroban-env-host/src/vm/dispatch.rs:304` is 1,303,110,709 ns self over 26,145 calls, and `Vm::invoke_function_raw` is 553,650,053 ns self over 8,722 calls.
- Apply-window containment confirms the target is inside `applyLedger`: `call` accounts for 5,428,387,766 ns over 26,079 events whose start timestamps fall inside the 71 `applyLedger` windows, while `Vm::invoke_function_raw` accounts for 7,951,061,258 ns over 8,704 events.
- Prior rejected dispatch micro-optimizations targeted cheap sub-pieces such as fuel counter synchronization, a few `RefCell` borrows, or argument buffer allocation. This hypothesis targets the broader host-import ABI layer itself, which is the remaining multi-second apply-contained boundary after native pool and metering coalescing successes.

## Anti-Evidence

- The host-function bodies, budget charges, relative-object conversion, error escalation, and fuel transfer still have to happen; a raw ABI only helps if the wasmi `Func::wrap` trampoline/tuple adaptation is a large fraction of the `call` zone. A PoC must instrument wrapper overhead separately from host-function body time before claiming success.
- This requires either extending/pinning the local wasmi integration or adding a new host-import registration path. It must remain protocol-gated and deterministic: no parallelism, no hardware-dependent dispatch order, and no change to p26 metering or trap behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` row `035-host-dispatch-call-trampoline-overhead.md`
**Failed At**: reviewer

### Trace Summary

The claimed path is real: Soroban invoke-host-function operations enter the C++ apply/parallel-apply helpers, cross the Rust bridge into `e2e_invoke`, instantiate a `Host`, and call contract Wasm through `Host::call_contract_fn` and `Vm::invoke_function_raw`. Wasm imports are registered through `HostFuncInfo::wrap -> linker.func_wrap(...)`, and guest host-function calls enter the generated `vm/dispatch.rs` wrapper that performs protocol checks, optional tracing, fuel return/refill, `DispatchHostFunction` charging, relative/absolute argument conversion, host method invocation, error escalation, and result conversion. This is the same dispatch trampoline surface already summarized as `035-host-dispatch-call-trampoline-overhead.md`, which rejected the optimization as below the 3% Medium threshold after normalizing per-call overhead by Soroban worker parallelism and ledger count.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2484-2510` — parallel Soroban worker threads call `txBundle.getTx()->parallelApply(...)` during `closeLedger`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — invoke-host apply helper calls `rust_bridge::invoke_host_function` with the module cache, ledger info, footprint entries, auth, and PRNG seed.
- `src/rust/src/soroban_invoke.rs:7-39` and `src/rust/src/soroban_proto_any.rs:391-448` — Rust selects the protocol host module, builds the budget, and enters the protocol-specific host invocation path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:523-552` — creates `Host::with_storage_and_budget`, installs ledger/auth/module-cache state, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-825` — Wasm contracts instantiate a `Vm`, push `Frame::ContractVM`, and execute `vm.invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:42-80` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — every imported host function is registered through `linker.func_wrap(...)` in minimal or maximal linkers.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-304` — generated per-host-function wrapper performs the mandatory semantic boundary work before and after calling `host.$fn_id`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-411` — exported Wasm invocation resolves the export, transfers fuel into wasmi, calls `Func::call`, transfers residual fuel back, and converts the return value to an absolute host `Val`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/func/mod.rs:308-361` and `.../linker.rs:503-554` — the public dynamic `Func::new`/`Linker::func_new` path is explicitly documented as having per-invocation runtime overhead that typed `Func::wrap` avoids; bypassing typed trampolines would require wasmi-internal changes, not just a safer public API swap.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/stack/mod.rs:174-217` — every host import call still adjusts the wasmi value stack, resolves/clones the trampoline, creates a `Caller`, and invokes the trampoline; a single raw dispatcher would not remove the Soroban host's mandatory boundary semantics.

### Why It Failed

This is not novel. The fail summary already records `035-host-dispatch-call-trampoline-overhead.md` as "Reduce per-host-call dispatch trampoline overhead in `call` (`vm/dispatch.rs:304`)" and rejects it because the realistic removable per-host-call trampoline shell is about 1.6 ms/ledger, roughly 0.6% of the benchmark, far below the objective's 3% Medium threshold. The current hypothesis reframes the same `dispatch.rs:304` host-import boundary as a raw ABI redesign, but the trace shows that most work in the wrapper is required semantic work: fuel synchronization, budget charging, object handle translation, typed argument/result checks, error augmentation/escalation, and the host function body itself. The pinned wasmi public alternative (`func_new`/`Func::new`) is documented as slower than `Func::wrap`, so a PoC would need invasive wasmi-internal trampoline changes while still being bounded by the same previously rejected removable slice.

### Lesson Learned

Do not size Soroban host-import dispatch ideas from the aggregate `dispatch.rs:304` or `Vm::invoke_function_raw` Tracy zones. First subtract mandatory host boundary semantics and host-function body time, then normalize by parallel Soroban workers and ledger count; the residual generic trampoline overhead for soroswap has already been reviewed and is below the Medium objective threshold.
