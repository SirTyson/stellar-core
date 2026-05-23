# H001: Consume Loaded Native Soroswap Instances Instead of Cloning

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing full `ScContractInstance` clones on accepted native Soroswap pool getter/swap frames
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol native Soroswap pool getter and pair `swap` calls, the host should execute the same native frame, current-contract identity, instance-storage rollback, TTL extension, SAC subcalls, reserve updates, events, result values, and fallback behavior as today. Once a call has matched the exact Soroswap Wasm hash, symbol, argument shape, and instance layout, constructing the native frame should reuse the already-loaded `ScContractInstance` value instead of metered-cloning the full instance storage map again.

## Mechanism

At accepted p26 commit `fbbea0d9`, `call_contract_fn` loads the contract instance once, then `try_call_native_soroswap_pool_getter` and `try_call_native_soroswap_pool_swap` both construct `Frame::NativeContract(..., instance.metered_clone(self)?)` after validating the instance. For the native pair shape this clone includes the pool instance `ScMap`, even though the loaded instance is no longer needed for Wasm fallback after the native match succeeds. A move/consume path (or a helper that returns a prepared native-frame descriptor and consumes the loaded instance only after all fallback checks pass) should preserve deterministic behavior while removing the same class of full-instance clone overhead that the accepted direct SAC balance optimization already showed can move the soroswap benchmark.

## Trigger

Run the current accepted next-protocol soroswap apply-load benchmark (`soroswap-tx-2000-t-8`). Every matching native pool getter and pair `swap` call enters `call_contract_fn`, loads the pool instance from storage, validates the native path, and then metered-clones the instance to push a `Frame::NativeContract`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:783-837` — `call_contract_fn` loads `instance`, builds `args_vec`, tries native getter/swap, then falls back to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:840-872` — native getter validation ends by cloning `instance` into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1013-1074` — native pair `swap` validation ends by cloning `instance` into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1196-1279` — instance storage is initialized from the frame instance and persisted on frame pop; this behavior must remain identical after consuming the already-loaded instance.

## Evidence

The diagnostic soroswap Tracy trace is confirmed under `applyLedger` (`applyLedger`, `ledger/LedgerManagerImpl.cpp:1484`, 4,475,605,676 ns / 71 calls). The native pair path was accepted specifically because removing fixed Soroswap Wasm work produced an 8.17% soroswap median win, and the follow-up direct SAC balance path produced a 5.18% win by avoiding full SAC instance clone/frame overhead for two read-only balance subcalls. The current trace still has large apply-contained conversion/object/map zones (`ScVal to Val` 1,144,488,055 ns, `add host object` 373,380,488 ns, `new map` 461,915,256 ns, `map lookup` 1,223,514,982 ns inside apply windows), so eliminating a repeated full pool-instance `ScMap` clone on every accepted native getter/swap has a plausible Medium ceiling.

## Anti-Evidence

The native frame owns rollback-visible instance storage, so this cannot simply borrow `instance` by reference across `with_frame`. The implementation must only consume the loaded instance after all native gate checks have succeeded and must preserve Wasm fallback for non-matching calls. Budget accounting changes are protocol-visible; the optimization should remain behind the existing next-protocol native Soroswap gate or intentionally charge an equivalent amount.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/follow-on of `ai-summary/fail/ledger/summary.md` entries `001-skip-output-side-sac-balance-read.md`, `002-raw-native-pair-instance-storage.md`, and the native-Soroswap-path-absent meta-pattern
**Failed At**: reviewer

### Trace Summary

The checked-out p26 host does load a contract instance in `Host::call_contract_fn`, but production dispatch only matches `ContractExecutable::Wasm` and `ContractExecutable::StellarAsset`. There is no `Frame::NativeContract`, no `try_call_native_soroswap_pool_getter`, no `try_call_native_soroswap_pool_swap`, and no repository hit for native Soroswap helpers in the p26 host source. Instance storage is still owned by the active contract frame and lazily materialized/persisted through `maybe_init_instance_storage` and `persist_instance_storage`, but the alleged redundant native-frame clone does not occur on any actual apply path in this checkout.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:71,74-75` — prior retained failures already reject native Soroswap follow-on optimizations because the reviewed checkout has no native router/pool/pair implementation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:137-149` — `Frame` variants are `ContractVM`, `HostFunction`, `StellarAssetContract`, and test-only `TestContract`; there is no production native-contract frame variant.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` retrieves the instance once, charges/copies arguments, then dispatches Wasm contracts through `instantiate_vm`/`vm.invoke_function_raw` or SAC contracts through `StellarAssetContract.call`; no Soroswap hash gate or native getter/swap branch exists.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` handles test-only native Rust contracts behind `testutils`, then calls `call_contract_fn`; production contract calls still enter the Wasm/SAC dispatch above.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1279` — instance storage is initialized from the frame-owned `ScContractInstance` and persisted on frame pop, confirming why real frame ownership matters but not establishing the claimed native clone.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:113-120` — `retrieve_contract_instance_from_storage` returns the loaded `ScContractInstance`; this value is moved into the Wasm or SAC frame in the current production path.

### Why It Failed

The optimization target does not exist in the reviewed source. The hypothesis depends on accepted native Soroswap getter/swap dispatch that clones `ScContractInstance` into `Frame::NativeContract`, but the actual p26 host has neither the native Soroswap dispatch nor the native frame variant. This is also a duplicate of the retained ledger failure pattern for native Soroswap follow-on optimizations: before optimizing instance handling inside a native Soroswap path, that native path must be present in the source under review.

### Lesson Learned

Do not project Soroswap apply wins from accepted-branch native-path descriptions without verifying the checked-out p26 host contains the native path and the exact clone to remove. Current-review hypotheses should target actual Wasm/SAC host execution, storage ingress/output, parallel apply, or commit code unless a production native Soroswap implementation has landed.
