# H002: Build native Soroswap pair swap event without transient host map objects

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing fixed-shape native pair swap event host-object construction with a direct event-XDR builder
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The protocol-gated native Soroswap pair `swap` path should emit the same contract event as the Wasm pair contract: topics `[Symbol("SoroswapPair"), Symbol("swap")]` and a data map containing `amount_0_in`, `amount_0_out`, `amount_1_in`, `amount_1_out`, and `to` in the canonical contracttype order. Because the native executor already has these typed Rust values, it should not need to allocate a host vector and host map only for later event externalization.

## Mechanism

`call_native_soroswap_pool_swap` currently converts the four amounts to `Val`, creates two topic symbols, builds a host vector with `vec_new_from_slice`, builds a host map with `map_new_from_slices`, and passes the resulting `Val` objects to `record_contract_event`. For this fixed event shape, a protocol-gated internal helper can construct the `ContractEvent` payload directly as XDR (or through a typed event builder that avoids `MeteredOrdMap`/host-object insertion) while applying the same intentional protocol-gated budget accounting as the rest of the native pair path. This removes transient `new vec`, `new map`, symbol/map comparison, host-object table, and later host-object-to-XDR traversal work for every native pair swap.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Every successful native pair swap reaches the event block at `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` after reserve updates.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` - fixed native pair swap event construction using host vector/map objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` - `new map` path used by host-map construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:100-116` - `new vec` path used by topic construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443,543-566` - host `Val`/`ScVal` conversion path avoided by a direct typed event builder.

## Evidence

The current source now contains a native pair swap event site, so this is not the earlier absent-call-site investigation recorded in the transaction-ledger failure summary. In the current soroswap trace, the apply-window descendants include `new map` at **461.915 ms self** over **181,114** events, `new vec` in the SAC trace at **188.846 ms self** over **252,060** events, `Val to ScVal` at **249.343 ms self**, `write xdr` at **160.255 ms self**, and `add host object` at **286.504 ms self**. The native pair event is fixed-shape and emitted once per successful native pair swap, so it is a better candidate for direct typed construction than generic SAC event building.

The change preserves determinism: event field order is static, symbol bytes are fixed, amount values are already computed in native code, and the recipient address is the same `AddressObject` accepted by the native pair gate. No parallelism or worker ordering changes are involved.

## Anti-Evidence

Broad `new map`, `new vec`, conversion, and XDR zones include many non-pair-event call sites, and prior SAC event direct-XDR work failed when it attributed broad SAC transfer time to event construction. A viable PoC needs a narrow Tracy span or counter around the native pair event block to show this exact fixed event accounts for a Medium-sized share after T=8 cluster normalization. The event is protocol-visible metadata, so the direct builder must produce byte-for-byte equivalent event XDR and must be protocol-gated if budget/resource accounting changes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The native pair swap hook is real and every successful native pair swap reaches the fixed event block after output transfers, balance reads, K-invariant validation, and reserve updates. That block does allocate transient host objects: two topic symbols, one topics vector, a five-entry data map, and the current contract-id bytes object recorded with the event; later `try_finish` externalizes the buffered internal event back into `ContractEvent` XDR. However, the fixed pair swap event is only one event per native pair swap, while the cited `new map`, `new vec`, `Val to ScVal`, `add host object`, and `write xdr` totals cover many other host objects, storage maps, SAC events, result serialization, and mandatory final event encoding.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — `try_call_native_soroswap_pool_swap` is protocol/hash/function/argument gated and pushes a `Frame::NativeContract` before executing the native swap.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native swap performs SAC output transfers, reads pair balances, computes inputs, checks K, updates reserves, then emits the fixed pair swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1268-1302` — event construction creates amount `Val`s, two symbol objects, a host vector for topics, a host map for data, and calls `record_contract_event`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1021-1066,1109-1118` — `symbol_new_from_slice`, `map_new_from_slices`, and `vec_new_from_slice` validate inputs, charge budget, construct `HostMap`/`HostVec`, and add host objects.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:103-118` — `HostMap`/`HostVec` construction records the `new map` / `new vec` spans and charges deep-clone/allocation costs.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:15-39,173-249` — events are buffered as `InternalContractEvent { topics: VecObject, data: Val }` and externalized by converting those host objects into `ContractEvent` XDR.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:197-213,223-233,266-273,407-419,463-478` — externalization visits the topics vector/data map and recursively converts host `Val`s to `ScVal`s; contract-id recording also allocates a `BytesObject`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:771-777` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-584,954-970` — Soroban invocation finish externalizes events and still writes every successful contract event to XDR bytes for the Core bridge.

### Why It Failed

The optimization target is real but below the objective severity threshold. A direct typed builder could avoid this event's transient topics/data host objects and the corresponding host-object-to-`ScVal` traversal, but it would not remove the final `write xdr` work required to return encoded contract events to Core unless the event buffer were redesigned to store pre-encoded bytes. Even with such a redesign, the saving is bounded to one fixed pair event per swap: one topics vector, one five-entry map, two explicit topic symbols, a handful of `Val` conversions, and one contract-id object.

The hypothesis's Medium estimate is derived from broad Tracy zones. The cited `new map` total spans 181,114 map constructions while the pair event accounts for roughly one map per successful native pair swap; `new vec`, `add host object`, `Val to ScVal`, and `write xdr` are similarly shared by storage, SAC events, return/result encoding, diagnostics, and other host activity. After T=8 cluster normalization, the removable pair-event subset is far below the 3% apply-time floor required by this objective. This should only be revisited with narrow measurements proving that the native pair event block itself, not aggregate event/storage serialization, reaches Medium impact.

### Lesson Learned

Fixed-shape native event construction is a valid micro-optimization target, but broad host-object and XDR spans cannot be attributed to one contract event site. For this objective, native-event builder hypotheses need a narrow per-site span or counter and must separate avoidable host-object traversal from mandatory final event XDR encoding before claiming Medium impact.
