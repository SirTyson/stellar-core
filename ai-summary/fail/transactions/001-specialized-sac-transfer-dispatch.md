# H001: Specialized SAC Transfer Native Dispatch

**Date**: 2026-05-22
**Subsystem**: transactions / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing generic native-contract dispatch, argument conversion, and event construction overhead from the transfer-heavy SAC path.
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroswap transaction that invokes Stellar Asset Contract `transfer`, the host should produce the same ledger writes, auth checks, events, return value, and failure codes as the current native SAC contract path. In protocol 27+ benchmarking, the implementation may use a cheaper specialized path as long as it remains deterministic, preserves the observable call-frame/auth behavior, and updates budget numbers consistently with the protocol-gated cost change.

## Mechanism

`Host::call_contract_fn` dispatches `ContractExecutable::StellarAsset` through the generic `StellarAssetContract.call(func, self, args)` macro-generated path after cloning the `args` vector. For the Soroswap workload this is dominated by `transfer`: the current trace shows `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 616.3 ms self-time across 13,976 calls, plus large adjacent conversion zones (`ScVal to Val` 471.1 ms, `Val to ScVal` 280.0 ms total across both lines) that are descendants of `applyLedger`. A protocol-gated direct `transfer` dispatch in `host/frame.rs` can match the `transfer` symbol, decode the fixed `(Address, MuxedAddress, i128)` shape with a narrow typed helper, avoid the macro-dispatch/generic `TryFromVal` path for the hot case, and leave other SAC functions unchanged.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) on protocol 27+ with the accepted native-pool-getter baseline. The trigger is any swap route that performs SAC `transfer` calls for input/output token movement; the diagnostic trace counted 13,976 `SAC transfer` events inside `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — generic contract call dispatch; `ContractExecutable::StellarAsset` currently clones args and calls the macro-generated SAC dispatcher.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — hot `StellarAssetContract::transfer` implementation.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — generic `Val <-> ScVal` conversion zones that the fixed-shape SAC transfer path should reduce.

## Evidence

The current trace in `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/2ff900fcd176-20260522-031343/logs/2ff900fcd176-20260522-031343-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `SAC transfer` self-time of 616,339,357 ns at `contract.rs:212`, `ScVal to Val` self-time of 471,110,683 ns at `conversion.rs:436`, and `Val to ScVal` self-time of 265,225,138 ns at `conversion.rs:411`. An apply-window overlap check confirmed the transfer and conversion events occur inside the `applyLedger` windows; after dividing worker aggregate time by T=8, the combined hot path is in the Medium range if a fixed-shape transfer dispatch removes a substantial fraction rather than a micro-slice.

## Anti-Evidence

Prior SAC-address and SAC-metadata hypotheses failed because they targeted narrow subpaths. This one must avoid becoming another sub-threshold micro-optimization: the PoC should time the direct dispatch as a whole and preserve `require_auth`, TTL extension, balance mutation, issuer handling, muxed-address event semantics, and exact failure behavior. If the specialized path only removes symbol matching or one address decode, it is below the objective threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The apply path converts top-level `InvokeContract` XDR args to host `Val`s before contract dispatch, then `call_contract_fn` loads the SAC instance, clones the arg slice into the SAC frame, and invokes the macro-generated `StellarAssetContract.call`. The SAC frame must retain the cloned `Vec<Val>` because `Address::require_auth()` reconstructs the current invocation args from the frame for auth matching. The proposed direct dispatch can only remove the macro's symbol table scan and a few cheap `TryFromVal<Val>` wrapper conversions; it does not remove the cited `ScVal to Val` input conversion, `Val to ScVal` result/auth conversion, or the body of `StellarAssetContract::transfer`.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` unconditionally charges and clones `args` before matching the executable, and the SAC branch stores that clone in `Frame::StellarAssetContract` before calling the built-in dispatcher.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` — top-level `HostFunction::InvokeContract` performs `scvals_to_val_vec` before `call_n_internal`, and `invoke_function` converts the returned `Val` to `ScVal` after dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:216-220,407-443` — the cited `ScVal to Val` zone is input XDR-to-host conversion, and the cited `Val to ScVal` zone is generic host-to-XDR conversion; neither is part of the SAC macro dispatcher.
- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_fn.rs:29-63` — the generated dispatcher scans method names with `symbol_index_in_strs`, checks arity, converts each `Val` argument with `try_into_val`, and converts the return value.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:322-433,475-497` — `Address` and `MuxedAddress` conversions from `Val` are wrapper/tag checks around existing host object handles; muxed address extraction is still needed by `transfer`.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:214-227` — `i128` conversion is a small-tag fast path unless the amount is an `I128Object`; this is not the large conversion zone cited by the hypothesis.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-849` — `require_auth()` clones the current frame args to build the authorized invocation, so the SAC frame args cannot simply be skipped while preserving auth behavior.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — the `SAC transfer` span covers the actual transfer body: nonnegative check, muxed-address handling, auth, TTL extension, balance mutation, and event emission.

### Why It Failed

The projected Medium impact depends on treating the whole `SAC transfer` span plus nearby `ScVal` conversion zones as removable by direct native dispatch, but the traced code shows those costs are either mandatory transfer body work or outside the macro dispatcher. A correct direct dispatch must still create a SAC frame with copied args for auth semantics and still execute `StellarAssetContract::transfer`; the remaining removable work is only symbol scanning, arity checking, return conversion of `Void`, and cheap typed wrapper conversions. That is a narrow micro-optimization and falls below the objective's Medium severity threshold.

### Lesson Learned

SAC `transfer` aggregate time is a useful hotspot, but dispatch-layer hypotheses must separate macro dispatch overhead from mandatory frame/auth, XDR boundary conversion, and transfer-body work. The `ScVal to Val` / `Val to ScVal` zones around `InvokeContract` are not evidence that specializing a built-in contract function will remove generic conversion cost.
