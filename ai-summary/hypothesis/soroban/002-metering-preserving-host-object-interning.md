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
