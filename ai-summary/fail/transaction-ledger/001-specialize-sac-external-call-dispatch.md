# H001: Specialize external SAC call dispatch to avoid generic argument and contracttype conversion

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host SAC dispatch
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing generic `Host::call` argument unpacking, duplicated frame-argument copies, and generated contracttype dispatch overhead for hot Stellar Asset Contract calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When guest Wasm calls a Stellar Asset Contract function such as `transfer`, the host should preserve the same external call semantics: the caller still supplies `(contract_address, function, args)` through the `call` host function, reentry checks and diagnostics still occur, the SAC frame is still pushed, authorization and balance logic produce the same errors and ledger effects, and metered CPU/memory totals remain equivalent or are protocol-gated. The efficient path should not unpack the guest `VecObject` into a temporary `Vec<Val>`, copy that vector again into the frame, then route through the generated generic `StellarAssetContract.call` contracttype dispatcher when the target executable is already known to be the built-in SAC and the function signature is fixed.

## Mechanism

`Host::call` always calls `call_args_from_obj(args)` before it knows whether the target is Wasm or SAC, and `call_contract_fn` then charges/copies the resulting `&[Val]` into another `Vec<Val>` for the frame before dispatching `ContractExecutable::StellarAsset` through the generated `BuiltinContract` adapter. For soroswap, the router/pair Wasm calls SAC token contracts repeatedly through this path, paying generic vector unpacking, host-object visits, `Val` -> typed Rust conversion, and duplicated argument storage before entering `SAC transfer`. A SAC-specific external-call helper can resolve the target instance, run the existing `call_n_internal` front-door checks, borrow/unpack the `VecObject` once for known SAC signatures, push the same `Frame::StellarAssetContract`, and call the typed SAC functions directly.

## Trigger

Run the current soroswap apply-load trace from `ai-summary/CURRENT_STATE.md` (`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`). The `applyLedger` windows contain 19,982 generated `call` dispatch events at `soroban-env-host/src/vm/dispatch.rs:304`, totaling 7,730.070 ms aggregate and 1,114.477 ms summed per-window critical-worker time (19.3% of `applyLedger`). The same windows contain 6,656 `SAC transfer` events totaling 2,406.469 ms aggregate and 346.175 ms critical-worker time, reached from those external calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2601` - `Host::call` always materializes `argvec` with `call_args_from_obj` before dispatching.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192` - `call_args_from_obj` converts the guest `VecObject` into a host `Vec<Val>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-986` - `call_n_internal` performs reserved-function checks, reentry checks, diagnostics, then delegates to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` - `call_contract_fn` retrieves the instance, copies `args` into `args_vec`, pushes a SAC frame, and calls the generic `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-248` - hot typed SAC `transfer` / `transfer_from` targets that can be called after one checked typed argument decode.

## Evidence

- Tracy scope check: the cited `call` and `SAC transfer` events start inside `applyLedger` windows and share the parallel-apply worker threads under `Host::invoke_function`, so this is apply-path work, not TX-set construction.
- The source has a structural double materialization: `Host::call` creates an owned `Vec<Val>`, then `call_contract_fn` charges and copies the same slice into `args_vec` for the frame. The generated SAC dispatcher then converts those `Val`s to `Address`, `MuxedAddress`, and `i128` before calling the typed function.
- Current apply windows also show Vec-related zones (`vec_get`, `vec_len`, `vec_new`, `vec_new_from_linear_memory`, `new vec`, `vec_push_back`) totaling 826.458 ms aggregate and 123.283 ms critical-worker time. A direct SAC path would not remove all Vec work, but the external-call argument pipeline is one concrete high-frequency source.
- This is distinct from the reviewed SAC balance-storage hypotheses: those begin after typed `transfer` arguments have already been decoded and target balance reads/writes. This hypothesis targets the external-call dispatch and argument conversion boundary before the SAC body.

## Anti-Evidence

- `call` total time includes the nested callee body, including actual SAC balance mutation and Wasm router/pair execution, so the removable dispatch portion must be isolated with narrower spans before claiming the whole zone.
- Generated contracttype conversion and host-object visiting are protocol-metered. A PoC must preserve equivalent budget totals or explicitly gate the metering change; silently skipping argument conversion charges could change resource-limit outcomes.
- Reentry checks, reserved function rejection, diagnostic hooks, lifecycle hooks, and SAC frame rollback behavior must remain identical. The safe shape is a narrow fast path for `ContractExecutable::StellarAsset` after the same front-door checks, not a bypass of `call_n_internal` semantics.
- The reviewed `batch-host-object-visit-charges` hypothesis may reduce part of the same conversion family. This hypothesis should demonstrate incremental value from removing the duplicated argument materialization and generated SAC dispatch, not merely the generic visit-object overhead already queued.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The external Wasm `call` host function converts the guest `VecObject` into a `Vec<Val>`, resolves the contract address, and enters `call_n_internal`, which still must run reserved-function checks, reentry checks, and diagnostics before dispatch. For SAC targets, `call_contract_fn` retrieves the contract instance, copies the argument slice into the `Frame::StellarAssetContract` vector, and invokes the generated `BuiltinContract` dispatcher. The generated dispatcher does real but small work: a linear symbol-name match plus fixed `Val`-to-`Address`/`MuxedAddress`/`i128` conversions before calling `SAC transfer`; the SAC body, auth, storage, events, frame push/pop, and at least one frame argument vector remain required.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2567-2601` — `Host::call` always performs `call_args_from_obj(args)` before resolving the target and calling `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:314-316` — `call_args_from_obj` visits the host vector and metered-clones it into an owned `Vec<Val>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-986` — `call_n_internal` performs reserved-function, reentry, and diagnostic front-door behavior that a fast path cannot skip.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` retrieves the instance, charges/copies `args` into `args_vec`, pushes the SAC frame, and calls `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_fn.rs:29-63` — the generated `BuiltinContract` implementation matches the function name through `symbol_index_in_strs`, checks arity, converts each `Val` to its typed Rust argument, and converts the return value.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3610-3626` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:572-585` — `require_auth` reads the current frame's argument vector and passes it into authorization matching, so removing all frame argument storage would break semantics.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-248` — `transfer` and `transfer_from` then run auth, TTL extension, balance mutation, and event emission, which are nested under the inclusive `call` scope but are not removable dispatch overhead.

### Why It Failed

The inefficiency exists, but the hypothesis overstates the removable portion of the measured `call` scope. A correct SAC specialization still has to keep the external-call checks, diagnostics, frame push/pop and rollback, authorization-visible arguments, one owned argument vector for the frame, typed argument validation, and the SAC transfer body. The most plausible savings are one small `Vec<Val>` copy/allocation per SAC call plus generated symbol dispatch and trivial wrapper conversions; the cited 123.283 ms critical-worker Vec total is for all Vec activity, not just this SAC argument pipeline, and even deleting that entire broader family would be about 2.1% of the 5,774.332 ms apply window seen in the current related trace notes. Therefore the realistic impact is below the optimize-soroswap objective's Medium threshold, so this is not accepted even though the local inefficiency is real.

### Lesson Learned

Inclusive host-function Tracy scopes must not be treated as removable dispatch overhead: they include nested Wasm/SAC execution and required frame/auth semantics. Future SAC dispatch hypotheses need either narrower self-time measurements for the exact argument-copy and generated-dispatch operations, or a broader frame/context redesign that safely removes enough required bookkeeping to clear the 3% apply-time threshold.
