# H002: Native-Pool Fast Path Inside the `call` Host Function

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce Soroswap router-to-pool contract-call overhead without bypassing the router Wasm or SAC semantics
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the Soroswap router Wasm calls an allowlisted pool contract with `swap` or a fixed getter shape, the host should produce exactly the same frame stack, auth observations, storage writes, events, traps, and budget behavior as the existing protocol-gated native pool path. The router should not need to pay the full generic `call` host-function unpacking and `call_n_internal` contract-dispatch shell before reaching the already-existing native pool matcher.

## Mechanism

The current native pool optimization begins only after the generic `call` host function has converted the `VecObject` arguments into a Rust `Vec<Val>`, converted the callee address object into a `ContractId`, entered `call_n_internal`, performed generic reserved-name/reentry/diagnostic work, loaded the contract instance, and finally matched `match_native_soroswap_pool_getter` or `match_native_soroswap_pool_swap`. A next-protocol branch in `Host::call` can first recognize the fixed native-pool call shape from `(contract_address, func, args)` and dispatch directly to the existing native pool frame construction, while falling back to `call_n_internal` for every nonmatching address/function/argument layout. This keeps the router Wasm intact and reuses the accepted native pool helper semantics, but removes the generic contract-call shell for the hottest router-to-pool calls.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each successful router swap invokes pool getters and pool `swap` through the Soroban `call` host function; once inside `call_contract_fn`, the current source already recognizes the allowlisted pool Wasm and executes `Frame::NativeContract`. The proposed trigger is the same fixed pool function names and argument shapes already accepted by `match_native_soroswap_pool_getter` and `match_native_soroswap_pool_swap`, but recognized one layer earlier in `Host::call`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2591-2625` — `Host::call` unpacks a `VecObject`, converts the address, and always enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1864` — `call_n_internal` performs generic checks and dispatch before reaching contract-specific execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` loads the instance, matches native pool getter/swap shapes, and constructs `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — existing native pool `swap` matcher whose validation logic should be reused rather than duplicated.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — accepted native pool `swap` implementation whose behavior must remain unchanged.

## Evidence

- Current soroswap Tracy self-time from `csvexport-release -e`: `call` at `soroban-env-host/src/vm/dispatch.rs:304` is 1,303,110,709 ns self over 26,145 calls, one of the largest remaining Soroban VM/host-boundary zones.
- Apply-window containment confirms the target is under `applyLedger`: `call` totals 5,428,387,766 ns over 26,079 events inside the 71 `applyLedger` windows. `SAC transfer` remains 2,910,469,315 ns over 17,333 apply-contained events, but prior direct-SAC-transfer work is sub-threshold; this hypothesis instead targets the router-to-pool `call` shell that is still paid before the accepted native pool helper runs.
- Source inspection shows the accepted native pool path starts at `call_contract_fn`, after `Host::call` and `call_n_internal` have already done generic work. Moving only the native-pool recognition to `Host::call` is a narrower code path than full router-native execution and does not require interpreting router logic or changing SAC transfer semantics.

## Anti-Evidence

- The fast path must not skip required auth-tree frame observations, reentry rejection, diagnostics, or budget charges that are consensus-visible in the next-protocol metering schedule. If those generic checks are semantically required for native pool calls, the removable slice may fall below Medium.
- Prior native Soroswap bypass variants were rejected when they attempted to replace router/pool semantics wholesale. This hypothesis is viable only if it remains a local `call`-host-function dispatch optimization that reuses the already accepted native pool matcher and falls back to `call_n_internal` for all other calls.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not an exact duplicate; adjacent fail-summary rows cover host-import trampoline overhead, native pool state caching, and SAC subcall fusion, but not this specific `Host::call`-to-native-pool pre-dispatch shortcut
**Failed At**: reviewer

### Trace Summary

The traced path is real: Wasm router calls enter the generated `vm/dispatch.rs` `call` host-function wrapper, which performs fuel/budget/object-boundary work and then calls `Host::call`. `Host::call` clones the `VecObject` into a `Vec<Val>`, extracts a `ContractId` from the callee address object, and calls `call_n_internal`; `call_n_internal` performs external-call reserved-name, reentry, and diagnostic handling before `call_contract_fn` loads the contract instance and selects the existing `Frame::NativeContract` pool getter/swap path. However, a correct earlier fast path cannot remove the VM import wrapper, fuel transfers, dispatch charge, relative-to-absolute object conversion, argument `HostVec` clone, address extraction, instance load, native matcher validation, native frame push/pop/auth snapshot, or the native pool body. The only plausibly removable work is a small `call_n_internal` shell, and preserving reentry/diagnostic semantics either requires keeping or duplicating much of that shell.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-294` — every Wasm host import, including `call`, still crosses the generated dispatch wrapper for fuel return/refill, `DispatchHostFunction` charge, relative/absolute argument conversion, error augmentation/escalation, and result conversion.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2591-2625` — `Host::call` unconditionally clones the argument `VecObject` and converts the address object before calling `call_n_internal`; this work is still needed to recognize the native pool shape safely.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:314-316` — `call_args_from_obj` visits the host vector and metered-clones it into a Rust `Vec<Val>`; the existing native matchers require this slice shape.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:540-546` — `contract_id_from_address` visits the address object and metered-clones the `ScAddress`; this remains necessary to load the contract instance and construct a native frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1864` — `call_n_internal` rejects reserved external names, enforces prohibited reentry, emits call/return diagnostics, and then dispatches to `call_contract_fn`; the test-contract branch is not relevant to production, but the reentry/diagnostic pieces are semantic.
- `src/rust/soroban/p26/soroban-env-host/src/events/diagnostic.rs:108-144` — `fn_call_diagnostics` must run before opening the callee frame so the calling contract is inferred correctly, and `fn_return_diagnostics` records successful callee returns.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` loads the `ScContractInstance`, clones the args for the frame, matches native pool getter/swap, and pushes `Frame::NativeContract`; the instance load and native frame are still required.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:222-270` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1365` — `with_frame`/`push_context` snapshots storage/events/auth and pushes an authorization stack frame for `Frame::NativeContract`; the proposed shortcut cannot remove this without changing auth and rollback semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-899` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native getter/swap recognition is gated to post-p26, checks the allowlisted Wasm hash, validates function/argument shape, and verifies the raw pool storage layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — successful native swaps still do TTL extension, output validation, SAC transfer/balance work, reserve update, event construction, and return handling.
- `ai-summary/fail/soroban/summary.md:106,165-166,209` — prior records bound adjacent surfaces: broad host-import dispatch trampoline overhead is about 0.6%, native SAC frame fusion is about 2.0%, and native pool call-state caching is sub-Low after 8-way Soroban parallelism normalization.

### Why It Failed

The hypothesis sizes the opportunity from the broad `call` Tracy zone, but that zone includes mandatory VM-host import boundary work and the called host-function body, not just the `Host::call -> call_n_internal -> call_contract_fn` shell. After tracing the actual path, the fast path would still pay the dispatch wrapper, fuel synchronization, `DispatchHostFunction` charge, relative-object conversion for the address and args, the `HostVec` clone, contract-id extraction, contract-instance retrieval, native matcher checks, native frame push/pop with auth/storage rollback snapshots, and all native getter/swap/SAC/event work.

The proposed implementation also cannot simply skip `call_n_internal`: external-call reentry enforcement and diagnostic ordering are part of the contract-call semantics. Re-implementing those checks in `Host::call` would leave only a tiny control-flow/branching shell and perhaps one extra `args.to_vec()` copy as the removable slice. Existing fail-summary bounds for the broader host-import trampoline (~0.6%), the native SAC subcall frame (~2.0%), and native pool call-state caching (sub-Low) make this narrower router-to-pool pre-dispatch shortcut unable to plausibly reach the objective's 3% Medium floor, so it is not viable for this review stage.

### Lesson Learned

Do not size native-pool residual optimizations from the aggregate `call` host-function Tracy zone. First subtract the VM import wrapper, object conversion, frame/auth rollback semantics, native matcher/body work, and prior accepted native-pool raw-storage changes; the remaining generic `call_n_internal` shell is a small residual path and must be normalized by Soroban parallel apply before promotion.
