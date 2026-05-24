# H002: Metering-Preserving Host Object Interning for Repeated Immutable Values

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding duplicate physical host-object allocation/conversion while preserving budget charges
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated conversions of identical immutable `ScVal` objects during one host invocation should return semantically equivalent host values and preserve all required budget charges, depth-limit checks, ordering, and deterministic guest-visible behavior, without allocating a fresh `HostObject` every time the same address, symbol, bytes, vec, or map value is materialized.

## Mechanism

The host object table is append-only and immutable, and `to_host_val` / `add_host_object` currently allocate physical host objects for repeated values loaded from ledger entries, instance storage, SAC calls, and event construction. A protocol-gated interning layer keyed by small immutable `ScVal` object payloads, with explicit charge replay for allocation/conversion costs, could reuse existing absolute handles for repeated values inside a host while still charging the same metered costs; this attacks both the hot `ScVal to Val` conversion zone and the `add host object` allocation zone without depending on unsafe cross-transaction state.

## Trigger

Run the current protocol-27 soroswap apply-load benchmark. Soroswap pool/native SAC execution repeatedly materializes the same token addresses, pair contract address, event symbols, storage keys, and storage values while applying each swap transaction, producing high call counts in `ScVal to Val` and `add host object` under the `applyLedger` windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` - `Host::to_host_val` recursively converts `ScVal` into host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` - `Host::add_host_object` always appends a new immutable object and charges heap allocation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` - instance storage materialization converts every stored key/value pair into fresh host values.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` - native pool swap event construction repeatedly creates the same event-topic symbols and map-shape objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1365` - native pool SAC transfer/balance helpers repeatedly construct function symbols and address/amount arguments.

## Evidence

The current soroswap trace reports `ScVal to Val` at `host/conversion.rs:436` with 493.9ms self-time and 804,622 calls, and `add host object` at `host_object.rs:450` with 286.5ms self-time and 1,002,406 calls. Unwrapped events confirm the target work occurs under `applyLedger`: `ScVal to Val` contributes 1.144s total duration inside apply windows, and `add host object` contributes 373ms. The values being converted on this workload are highly repetitive by structure: pool instance storage contains stable token/factory addresses and reserves, SAC calls repeat `transfer`/`balance` symbols and pair/token addresses, and swap events repeat the same topic symbols and field-name keys.

## Anti-Evidence

Object-handle identity and metering are the hard parts. Reusing an absolute object handle must not make a distinct object identity observable through relative-handle translation, event encoding, comparison behavior, or debug/trace hooks, and charge replay must preserve the resource schedule unless the change is explicitly next-protocol-only. Prior narrow pre-interning of native-pair event symbols was below threshold; this hypothesis is only viable if the implementation covers the broader immutable value-conversion surface measured by `ScVal to Val` plus `add host object`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL - duplicate of `ai-summary/fail/soroban/summary.md` entry `005-scval-val-conversion-coalescing-below-threshold.md`
**Failed At**: reviewer

### Trace Summary

The claimed code path is real: Soroban parallel apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, constructs a `Host`, invokes the host function, and then materializes instance storage, SAC-call arguments, events, and returned values through `ScVal`/`Val` conversion and `Host::add_host_object`. However, this is substantially the same investigation already retained in the fail summary as "Coalesce repeated `ScVal`->`Val` / `Val`->`ScVal` conversions within a host invocation to avoid redundant host object allocation." That prior record concluded the idea is architecturally valid but below the objective threshold after accounting for metering, recursive conversion work, and parallel-worker normalization, so this hypothesis is not novel.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2868-2903` and `src/ledger/LedgerManagerImpl.cpp:2967-3029` - `applyTransactions` dispatches parallel Soroban phases and `applyParallelPhase` builds `TxBundle`s before calling `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2484-2507` - each apply worker calls `txBundle.getTx()->parallelApply(...)` inside the `closeLedger` apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` - Soroban invoke operations use `InvokeHostFunctionParallelApplyHelper` in protocol-v23+ parallel apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` - the helper calls `rust_bridge::invoke_host_function` with host function XDR, resources, ledger entries, TTL entries, ledger info, PRNG seed, rent config, and the module cache.
- `src/rust/src/soroban_proto_any.rs:310-354` and `src/rust/src/soroban_proto_any.rs:391-448` - the Rust bridge catches panics, constructs the per-invocation `Budget`, and calls the protocol-specific `e2e_invoke` entry point.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` - `e2e_invoke::invoke_host_function` decodes resources and ledger state, creates `Host::with_storage_and_budget`, sets ledger/auth/source/module-cache state, then calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` - instance storage is lazily materialized through `InstanceStorageMap::from_instance_xdr` on first access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` - instance storage conversion maps every stored key and value through `host.to_valid_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-443` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-628` - `to_host_val` enforces conversion depth and `to_host_obj` recursively converts `ScVal` object variants before calling `add_host_object`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-457` - `add_host_object` appends to `HostImpl.objects`, charges `charge_heap_alloc::<HostObject>`, and returns a new absolute handle.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1365` - native pool swap events and SAC transfer/balance helper calls still construct some symbols, maps, and argument values on this path.

### Why It Failed

This is a duplicate of the retained fail-summary investigation `005-scval-val-conversion-coalescing-below-threshold.md`, which already covered broad in-host `ScVal`/`Val` conversion coalescing to avoid redundant host-object allocation. The current interning phrasing changes the proposed data structure, but the optimization surface is the same: repeated immutable object materialization inside one host invocation with metering replay. The prior assessment found the removable subset below the optimize-soroswap Medium floor; adjacent retained records also bound host-object arena/capacity savings and native-pair event-symbol interning as sub-threshold.

### Lesson Learned

For Soroban host-object materialization hypotheses, novelty requires a new measured surface beyond broad conversion coalescing or isolated event-symbol/object allocation. Reframing the cache as "interning" is not enough when the same removable conversion/allocation work and objective-threshold analysis are already recorded.
