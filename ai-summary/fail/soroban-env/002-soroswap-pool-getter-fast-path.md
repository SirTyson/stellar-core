# H002: Fast-Path Pure Soroswap Pool Getter Calls Before VM Instantiation

**Date**: 2026-05-21
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by bypassing generic wasmi instantiation/invocation for allowlisted read-only pool getter exports
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the allowlisted Soroswap pool code hash, calls to pure getter exports such as `token_0`, `token_1`, `get_reserves`, and `k_last` should return exactly the same `Val` values, storage errors, traps, and next-protocol budget results as executing the Wasm getter in a fresh VM. Calls to mutating exports such as `swap`, `deposit`, `withdraw`, or any unrecognized code hash/function must continue through the normal `instantiate_vm` and `Vm::invoke_function_raw` path.

## Mechanism

`Host::call_contract_fn` currently treats every `ContractExecutable::Wasm` function uniformly: it retrieves the instance, instantiates a fresh wasmi VM from the cached module, pushes a `ContractVM` frame, and invokes the export. The Soroswap router repeatedly calls read-only pool getters whose results are already represented in the pair instance storage that is in the transaction footprint. A code-hash/function gated getter path can answer these specific exports directly from the pool instance storage without allocating a `Store`, resolving imports, creating a relative-object table, or entering the wasmi interpreter. This is significant because the current Soroswap trace has roughly three VM instantiations per transaction; removing even the pure-getter subset attacks both the 20,389-call instantiation path and a meaningful slice of the 20,313-call VM invocation path without replacing the mutating `swap` semantics.

## Trigger

Run the current soroswap apply-load benchmark. `ApplyLoad::generateSoroswapSwaps` always invokes router function `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, path=[token_in, token_out], to=source, deadline=u64::MAX)`, includes the pair code as read-only and pair instance as read-write, and uses the vendored pool Wasm at `src/rust/apply-load-wasm/soroswap_pool.wasm`. `wasm-tools print` shows the pool exports `token_0`, `token_1`, `factory`, `swap`, `get_reserves`, and `k_last`; the fast path should trigger only for the pure getter exports and the known pool code hash.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:746-775` — `call_contract_fn` dispatches every Wasm contract call through VM instantiation and a `ContractVM` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:779-801` — `instantiate_vm` fetches a cached parsed module but still constructs a fresh VM.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a new store, runs import/protocol checks, and calls `wasmi_linker.instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` marshals args and calls the wasmi export.
- `src/simulation/ApplyLoad.cpp:3381-3463` — fixed two-token Soroswap workload shape and footprint that make the getter trigger reproducible.

## Evidence

Current accepted trace: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Unwrap containment verified all candidate VM zones are inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` has 20,389 inside events / 0 outside and 1,317,542,205 ns total; `Vm::invoke_function_raw` has 20,313 inside events / 0 outside and 12,842,366,133 ns total; generated host-function `call` wrappers have 40,605 inside events / 0 outside and 9,353,235,883 ns total. The static export list confirms a pure-getter subset exists in the pool Wasm, and the transaction generator confirms the pair code/instance are always present in the footprint for this benchmark.

This is deliberately narrower than a full native Soroswap router/pair precompile: the mutating pool `swap` export and SAC transfer behavior stay in the existing generic paths. The proposed branch only covers read-only getters whose output should be derivable from the already-loaded pool instance, making the equivalence surface smaller and easier to test.

## Anti-Evidence

The pure-getter call count must be confirmed dynamically; if the router inlines or avoids these exports on the hot path, the instantiation/invocation subset will fall below Medium. The pool instance-storage schema and exact return encoding must be specified before PoC, and any getter that can emit diagnostics, depend on transient VM memory/global state, or observe traps not captured by storage reads must be excluded. This must be next-protocol-gated or exactly metered: bypassing wasmi changes `InvokeVmFunction`, `DispatchHostFunction`, fuel transfer, frame/auth snapshot, and conversion charges unless an explicit replacement schedule is defined.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The central "pure getter" premise is wrong for the vendored Soroswap pool Wasm. `wasm-tools print src/rust/apply-load-wasm/soroswap_pool.wasm` shows `token_0`, `token_1`, `factory`, `get_reserves`, and `k_last` all call helper func 66 before reading instance-storage fields; func 66 imports ledger function `l`/`8`, which `env.json` identifies as `extend_current_contract_instance_and_code_ttl`, with threshold/extend-to `U32Val`s 501120 and 518400. That host function is protocol-visible: it obtains the current contract ID from the active frame, extends the contract instance TTL and Wasm code TTL via storage, can fail on footprint/TTL conditions, and contributes host-function dispatch/storage/budget effects.

A fast path that answers these exports directly from `ScContractInstance.storage` before constructing a `ContractVM` frame would therefore skip observable TTL-extension side effects and the frame context required by `get_current_contract_id_internal`. It would not be equivalent to the Wasm getter even if the returned `Val` happened to match on the current benchmark ledger, so the proposed storage-only branch would break correctness.

### Alternative Angle

The broader idea of avoiding a fresh wasmi instantiation for the one Soroswap `get_reserves` subcall per swap may still have merit, but it needs to be reframed as a native emulation of the complete getter behavior, not a pure read-only shortcut. A refined hypothesis would need to push an equivalent contract frame or otherwise provide the current pool contract ID, reproduce `extend_current_contract_instance_and_code_ttl(501120, 518400)`, perform the pool's initialized check, read the correct instance-storage keys, construct the exact returned `Vec`/address/object values, and define exact replacement metering or a next-protocol metering schedule.

### Additional Code Paths

- `src/rust/apply-load-wasm/soroswap_pool.wasm` (`wasm-tools print`: funcs 109-111, 118-119, 66) — every alleged getter calls the TTL-extension helper before returning storage-derived values.
- `src/rust/soroban/p26/soroban-env-common/env.json:1524-1537` — import `l`/`8` is `extend_current_contract_instance_and_code_ttl(threshold, extend_to)`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` — TTL extension depends on `get_current_contract_id_internal`, extends instance TTL, then extends code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-280` — code/instance TTL extension routes through storage and can produce ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:404-598` — `with_frame` supplies the context, rollback, authorization frame, trace hooks, and persistence/rollback behavior that a pre-frame shortcut would bypass.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — current Wasm contract calls retrieve the instance, instantiate the VM, push `Frame::ContractVM`, and invoke the export.
