# H001: Generate low-overhead wasmi dispatch trampolines for hot host functions

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban VM dispatch
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic marshalling glue from the hot VM-to-host boundary
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban host-function call made by guest Wasm should continue to charge exactly one `DispatchHostFunction` event, synchronize Wasm fuel with the host budget at the same semantic boundary, validate arguments and return values identically, preserve trace hooks and diagnostic/error ordering, and return the same `Val`/object results. The optimized dispatch path should only remove implementation overhead in the generated Rust trampoline when the host-function ABI is a known simple i64/`Val`-payload shape.

## Mechanism

`generate_dispatch_functions` currently routes every generated host-function wrapper through the same generic path: clone the `Host`, optionally trace, return fuel, charge dispatch, build a `VmCaller`, convert every raw i64 through `wasmi::Value::I64` plus `RelativeObjectConversion::try_marshal_from_relative_value`, run `CheckedEnvArg`, then convert the successful return through `marshal_relative_from_self` and match it back to `Value::I64`. Most hot soroswap env calls use object/`Val`-like handles whose ABI is already one raw i64 payload, so a generated fast trampoline for safe signatures can perform direct payload validation/relative-object translation without constructing `wasmi::Value` intermediates or re-entering the fully generic conversion helpers. This is broader than removing the protocol guard only: the current trace shows all `vm/dispatch.rs:304` host-call wrappers totaling `1,808,024,779 ns` self-time over `648,894` calls, so shaving a meaningful fraction of the common trampoline overhead can plausibly clear the Medium floor.

## Trigger

Run the current soroswap apply-load Tracy trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`

Export self-times with:

`./lib/tracy/csvexport/build/unix/csvexport-release -e <trace>`

Filter rows where `src_file == soroban-env-host/src/vm/dispatch.rs` and `src_line == 304`. Hot rows include `call` (`632,325,205 ns` self / `30,534` calls), `vec_new_from_linear_memory` (`154,780,911 ns` / `56,308`), `extend_current_contract_instance_and_code_ttl` (`123,973,812 ns` / `15,374`), `has_contract_data` (`119,930,675 ns` / `61,293`), `map_new_from_linear_memory` (`98,102,195 ns` / `15,220`), `obj_cmp` (`83,722,731 ns` / `71,450`), `vec_len` (`77,637,555 ns` / `81,605`), and `vec_get` (`71,828,079 ns` / `56,109`). Timestamp filtering of representative generated dispatch zones confirms they run inside `applyLedger` worker windows under parallel Soroban apply, not TX-set construction.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:19-39` — `RelativeObjectConversion` converts through generic `wasmi::Value` helpers and relative/absolute object translation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-function trampolines perform the generic conversion, dispatch charge, `VmCaller` setup, success conversion, and fuel return/refill on every VM-to-host call.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — fuel synchronization semantics that the fast trampoline must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/env.json` / generated host-function macro inputs — host-function signatures can be classified so only safe raw-i64 payload signatures use the specialized path.

## Evidence

- The current accepted trace shows generated dispatch wrappers as a large aggregate self-time family inside the apply path: `1.808 s` self-time across the full soroswap trace, before counting nested host-function bodies.
- The hottest rows are not one niche function; they cover cross-contract `call`, storage, vector/map, bytes, comparison, TTL, and event functions that are exercised repeatedly by the router/pair/SAC soroswap execution path.
- The source comments at `dispatch.rs:244-252` explain that `wasmi::Value` is used as a universal switching point because some host functions receive or return non-`Val` i64/u64 values. That implies the all-generic path is not inherently required for signatures that are already known to be object/`Val` payloads or other simple cases.
- Prior failure `021-eliminate-redundant-protocol-check-in-dispatch.md` rejected only the tiny protocol-bound guard removal. This hypothesis targets the larger common trampoline shape: generic value construction, trait dispatch, redundant checked conversion layers, and success-result remarshal for safe signatures.

## Anti-Evidence

- The `call` zone is inclusive when viewed in unwrap mode; only `csvexport -e` self-time should be used for the removable dispatch-wrapper estimate.
- `CheckedEnvArg`, relative-object translation, fuel synchronization, dispatch budget charging, and error augmentation are semantic boundaries. The fast path must preserve them or be protocol-gated with explicit budget/observation updates.
- Tracy instrumentation inflates each wrapper with a span; a PoC must demonstrate a non-Tracy `scripts/run_apply_load_matrix.py` improvement, not just lower Tracy self-time.
- Some generated functions have plain i64/u64 arguments or special object-relative behavior and should remain on the generic path until a type-specific fast validator is proven equivalent.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

Parallel Soroban apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge through `rust_bridge::invoke_host_function`, constructs a p26 `Host`, and invokes guest Wasm through `Vm::invoke_function_raw` / `Vm::metered_func_call`. Each guest import is linked to a generated dispatch shim from `generate_dispatch_functions`, where the host call returns fuel to the host budget, charges `DispatchHostFunction`, translates relative object handles to absolute handles, runs `CheckedEnvArg`, calls the host method, validates/remarshals the return value, and refills VM fuel. The claimed wrapper family is real and hot, but the proposed removable portion is much smaller than the measured aggregate self-time.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1358-1377` — parallel apply invokes `rust_bridge::invoke_host_function` from `InvokeHostFunctionOpFrame doParallelApply`, so Rust host/VM work is inside `closeLedger`.
- `src/rust/src/soroban_invoke.rs:7-38` — the bridge selects the p26 host module and calls its `invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — builds enforcing storage, budget, auth, ledger info, module cache, and then calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `InvokeContract` converts invoke arguments to host `Val`s and enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-780,923-955` — Wasm contract calls push a `Frame::ContractVM` with a relative-object table and then invoke the `Vm`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345,388-405` — `metered_func_call` transfers budget to wasmi fuel, calls the guest function, returns fuel to the host, and converts the guest return; `invoke_function_raw` also performs host-to-guest absolute/relative conversion for inputs.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:42-80,118-128` — every host import is registered with wasmi via `linker.func_wrap(..., dispatch::$func_id)`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:19-39,206-296,303-304` — generated dispatch shims perform the `wasmi::Value::I64` conversion, relative-object translation, integrity checks, host call, error augmentation, return conversion, and fuel handoff under the line-304 macro expansion.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — `add_fuel_to_vm` and `return_fuel_to_host` are required boundary semantics, not optional marshalling overhead.
- `src/rust/soroban/p26/soroban-env-common/src/env.rs:40-56,239-294` — `CheckedEnvArg` validates `Val`/wrapper integrity through `check_val_integrity`; object wrappers therefore still need object-integrity checking.
- `src/rust/soroban/p26/soroban-env-common/src/val.rs:417-470` and `src/rust/soroban/p26/soroban-env-common/src/wrapper_macros.rs:88-107,193-209` — `WasmiMarshal` for `Val`, `i64`, `u64`, enum wrappers, and Val wrappers is monomorphic and reduces to an `I64` match plus bit/tag validation.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:362-440` — relative/absolute object translation validates relative handles against the frame table and appends returned absolute objects to the relative table.
- `src/rust/soroban/p26/soroban-env-common/env.json:33-45,1033-1050,1110-1151,1338-1351,1400-1412,1524-1536,1719-1736` — the hottest cited functions use mixed signatures (`Val`, object wrappers, `U32Val`, `Bool`, `Void`, plain `i64`) and still need the same type/integrity semantics after any specialization.
- `ai-summary/fail/transaction-ledger/021-eliminate-redundant-protocol-check-in-dispatch.md` and `ai-summary/fail/transaction-ledger/001-specialize-sac-external-call-dispatch.md` — adjacent investigations cover protocol guard removal and SAC call specialization, but not this generic trampoline-marshalling claim.

### Why It Failed

The local generic shape exists, but the hypothesis overstates what can be removed. For object/`Val` signatures, a correct fast path must still perform raw-payload validity checks, relative-to-absolute object translation, object-integrity checks, dispatch budget charging, fuel synchronization, `VmCaller` setup, host error augmentation, result integrity validation, absolute-to-relative return translation, and fuel refill. The `wasmi::Value::I64` construction/match and monomorphic `WasmiMarshal` wrapper calls are small enum/bit-test glue that Rust can inline; they are not allocations and do not explain the 1.808 s aggregate wrapper self-time.

The objective threshold is also not met. The accepted baseline is about 278.7 ms median apply time per soroswap ledger, so a Medium finding needs roughly 8+ ms per ledger. The cited dispatch-wrapper total is 1.808 s over the full trace, or about 25.8 ms aggregate worker self-time per ledger; with 8 parallel apply workers, deleting all dispatch-wrapper self-time would be only about 3.2 ms/ledger if balanced, and this proposal can remove only a small fraction of that because the expensive semantic boundary work remains. Therefore the realistic impact is below the optimize-soroswap Medium floor even before accounting for Tracy span overhead.

### Lesson Learned

Generated dispatch-line self-time should not be treated as generic-marshalling waste. The line-304 macro expansion aggregates required VM/host boundary costs, object-table translation, budget/fuel synchronization, error handling, and profiler spans; a viable dispatch optimization needs narrower measurements that isolate a removable operation large enough to clear the 3% apply-time floor, not just a syntactic specialization of already-inlineable `Value::I64` marshalling.
