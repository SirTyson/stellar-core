# H001: Move Loaded Native Soroswap Instance into Native Frame

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated full `ScContractInstance` clones on accepted native Soroswap pool getter/swap frames
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol native Soroswap pool getter and pair `swap` calls, the host should preserve the exact current behavior: same hash/symbol/arity/layout gates, same fallback to Wasm for unsupported calls, same native contract frame identity, same instance-storage rollback and persistence, same TTL extension side effects, same SAC subcalls, and same emitted events/results. Once a call has matched the native path, constructing the `Frame::NativeContract` should consume the already-loaded `ScContractInstance` instead of metered-cloning the full instance storage map.

## Mechanism

`Host::call_contract_fn` loads the contract instance before trying the native Soroswap hooks, then both accepted hooks build `Frame::NativeContract(..., instance.metered_clone(self)?)`. For native matches, the original `instance` is no longer needed for Wasm fallback, but the current API passes it by reference and pays a full clone of the pool instance map on every native getter/swap frame. Restructuring the hook checks so that they return a prepared native-call descriptor and move the loaded instance only after all gates pass should remove repeated clone/allocation/conversion work while leaving frame-owned rollback semantics intact.

## Trigger

Run the current accepted next-protocol soroswap apply-load benchmark (`soroswap-tx-2000-t-8`) on p26 `fbbea0d9`. Every matching pool getter and pair `swap` enters `Host::call_contract_fn`, loads the pool `ScContractInstance`, validates the native path, then clones that instance into `Frame::NativeContract` before executing the native helper.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-815` — `call_contract_fn` loads `instance`, eagerly builds/clones `args_vec`, and calls native getter/swap probes by reference before Wasm fallback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` — `try_call_native_soroswap_pool_getter` validates the native getter path and clones `instance` into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1070` — `try_call_native_soroswap_pool_swap` validates the native swap path and clones `instance` into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1279` — native frame instance storage is materialized and persisted through normal frame mechanics; this ownership behavior must remain identical after moving instead of cloning.

## Evidence

The diagnostic soroswap trace is confirmed under `applyLedger` (`ledger/LedgerManagerImpl.cpp:1484`, 4,475,605,676 ns across 71 calls). The current p26 submodule is `fbbea0d9`, and the native Soroswap hooks are present in this checkout, so the older "native path absent" blocker no longer applies. The same trace still shows apply-contained clone/allocation/conversion envelopes large enough to matter if a fixed native-frame clone is removed: `new map` at `soroban-env-host/src/host/metered_map.rs:148` has 350,833,562 ns self-time / 181,114 in-apply events, `ScVal to Val` at `soroban-env-host/src/host/conversion.rs:436` has 493,872,860 ns self-time / 800,217 in-apply events, and `add host object` at `soroban-env-host/src/host_object.rs:450` has 286,504,185 ns self-time / 1,002,406 calls. This target is not TX-set construction: the native hooks execute below `InvokeHostFunctionOpFrame::doParallelApply` inside Soroban worker apply.

## Anti-Evidence

The frame must own its `ScContractInstance` so instance-storage mutations roll back or persist through `with_frame` exactly as today; this cannot become a borrowed frame. The implementation must also preserve Wasm fallback for non-matching calls, so the move can only happen after all native gates succeed. The broad Tracy zones include work outside this clone, so a reviewer should isolate clone-specific allocations or benchmark a PoC before assigning final severity.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior same-angle failure `ai-summary/fail/ledger/001-consume-native-soroswap-instance.md` was based on a now-stale "native path absent" source premise; this review traces the current native hook implementation and fails on impact, not absence
**Failed At**: reviewer

### Trace Summary

The current p26 host does contain the native Soroswap pool getter and swap hooks. `call_contract_fn` loads a `ScContractInstance`, probes native getter/swap by reference, and the accepted native hooks clone that instance into `Frame::NativeContract`, so a move-after-match refactor would remove a real redundant clone on the native path. However, the clone being removed is only the extra XDR `ScContractInstance` clone performed after the initial storage load; the later frame push, rollback snapshot, instance-storage XDR-to-host materialization, `ScVal` conversions, host object creation, storage lookups, TTL side effects, swap reserve mutation, persistence, and SAC subcalls would still execute. The projected saving is therefore below the objective's Medium threshold.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:1-42` and `ai-summary/fail/ledger/001-consume-native-soroswap-instance.md:1-65` — checked retained prior failures; the closest prior file is the same optimization angle but rejected because native hooks were absent in its reviewed source, which is not true in this checkout.
- `ai-summary/success/ledger/002-cache-old-entry-xdr-sizes.md:1-96` — confirmed the only ledger success is a different host ledger-change XDR-size cache, not this native-frame instance movement.
- `src/ledger/LedgerManagerImpl.cpp:2531-2558,2623-2704,3028-3029` — Soroban stages run through parallel worker clusters during `closeLedger`, so native Soroswap contract calls are in the apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — `InvokeHostFunctionOpFrame::doParallelApply` is the worker-side Soroban invocation path beneath apply.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:90-119` — loading a contract instance from storage already performs one metered `ScContractInstance` clone from the ledger entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` loads `instance`, clones/copies args, tries native getter and swap for Wasm contracts, and otherwise moves `instance` into the Wasm frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872,1013-1074` — accepted native getter/swap branches validate hash, symbol, arity, argument/layout gates, then clone `instance` into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:251-255,397-405,489-510,554-559` — `ScContractInstance::metered_clone` charges/copies the shallow instance and recursively clones its optional storage `ScMap` vector and entries.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-70` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` — native helpers still lazily materialize frame instance storage from XDR into the host `InstanceStorageMap`; moving instead of cloning the instance does not remove this conversion path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:437-595,1866-1882` — `with_frame` still pushes a rollback snapshot and persists modified instance storage on successful frame exit.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:931-1003,1076-1366` — native getters and swap still perform TTL extension, instance-storage reads, reserve updates, event construction, and SAC transfer/balance interactions after the proposed move.

### Why It Failed

The optimization target is real but too narrow for this objective. The proposed change can remove one extra `ScContractInstance` XDR clone per accepted native pool getter/swap, but the claimed 3-10% projection attributes broad `new map`, `ScVal to Val`, and `add host object` envelopes to the clone. Those envelopes are primarily from instance-storage materialization and host-value conversion that still happen when the frame owns the moved instance. The initial storage-load clone also remains, and if exact budget behavior is preserved by charging an equivalent clone cost, the runtime-only allocation/copy saving becomes smaller still. This is a Low/sub-1% to Low-tier cleanup rather than a reproducible Medium (3-10%) apply-time optimization, so it is below the optimize-soroswap review threshold.

### Lesson Learned

For native Soroswap frame optimizations, separate the XDR instance clone from the larger frame-storage materialization and host-object conversion costs. A Medium-tier hypothesis needs to eliminate or amortize the materialization/conversion path itself, reduce the number of native frames/subcalls, or remove a dominant worker-stage cost rather than moving ownership of an already-loaded small XDR instance.
