# H002: Compact native Soroswap pool frame avoids full instance-map materialization

**Date**: 2026-05-25
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by avoiding repeated ScMap/host-object materialization for native pool calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Protocol-gated native Soroswap pool getter and swap calls should observe the same contract id, function name, arguments, instance-storage values, TTL side effects, reserve updates, and events as the current `Frame::NativeContract` path, but they should not have to clone and carry a full `ScContractInstance` storage map when the native implementation only needs the fixed pool fields `token0`, `token1`, `reserve0`, `reserve1`, `factory`, and `k_last`.

## Mechanism

`Host::call_contract_fn` loads a full contract instance, copies arguments into `args_vec`, and constructs `Frame::NativeContract` before native Soroswap matching and execution. The native pool helpers then repeatedly inspect the instance `ScMap`, convert entries back into host values, and rebuild an `ScMap` when reserves change. A compact `Frame::NativeSoroswapPool` carrying typed pool fields plus a deterministic writeback routine could keep the same observable frame semantics while eliminating full instance-map cloning/materialization for native pool getter and swap calls.

## Trigger

Run the current soroswap apply-load benchmark with next-protocol enabled. Router execution repeatedly calls Soroswap pool getters and pool `swap`; each call enters `Host::call_contract_fn`, matches `SOROSWAP_POOL_WASM_HASH`, creates `Frame::NativeContract`, and then reads typed fields from the frame's `ScContractInstance` storage map.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-812` — `call_contract_fn` retrieves a full `ScContractInstance`, copies args, and wraps native pool calls in `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-919` — native pool getter matching and storage-shape checks scan the instance `ScMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:957-1118` — native getter helpers repeatedly extract typed values from the instance storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1378-1448` — reserve updates clone the map entries and rebuild `ScMap` with two changed fields.

## Evidence

The latest soroswap trace shows the relevant native-host materialization zones are in the `applyLedger` subtree. Aggregate self-time includes `ScVal to Val` at 411,018,768 ns, `Val to ScVal` at 233,730,988 ns, `new map` at 393,666,531 ns, `add host object` at 308,563,937 ns, `storage get` at 266,675,391 ns, and `map lookup indexed` at 532,467,330 ns. Timeline aggregation inside `applyLedger` also shows `Host::invoke_function` at 9,046,718,940 ns total and `SAC transfer` / native pool-adjacent calls on the critical worker path, so removing per-call pool instance-map churn has a plausible multi-percent soroswap wall-time ceiling after T=8 normalization.

## Anti-Evidence

Several adjacent native-pool ideas have already been too small when they only moved ownership or cached a single view. This hypothesis requires a more structural frame representation: the compact frame must replace the full native pool `ScContractInstance` representation for all getter/swap uses in the optimized path and write reserves back deterministically, while preserving fallback to the existing Wasm/native-contract frame for any layout, function, protocol, or argument shape mismatch. If implementation only removes one clone or one lookup, it will fall below the objective's Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The native Soroswap pool fast path is present in this checkout: `call_contract_fn` loads the contract instance, matches the pool WASM hash and function, pushes `Frame::NativeContract`, and executes native getter/swap helpers. The specific inefficiency is real but much narrower than the hypothesis projects: the current native helpers already avoid lazy `InstanceStorageMap::from_instance_xdr` materialization for normal pool reads, convert numeric reserves directly from raw `ScVal::I128`, and only materialize address host objects needed for SAC calls and event outputs. A compact frame could remove small linear `ScMap` scans, some six-entry `ScContractInstance`/`ScMap` clones, and a duplicate instance load for code-TTL extension, but it would still need the storage entry, frame/auth rollback, TTL work, SAC transfer/balance calls, reserve writeback as canonical `ScMap`, event construction, and final `store_contract_instance` ledger-entry clone/write.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-812` — `call_contract_fn` retrieves the instance, matches native pool getter/swap, copies args, and constructs `Frame::NativeContract`; the full instance clone exists, but it is a small fixed-shape pair instance and is not the dominant host execution path.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:90-120` — `retrieve_contract_instance_from_storage` gets an `Rc<LedgerEntry>` from enforcing storage and then `metered_clone`s the `ScContractInstance`; a compact extractor could avoid this clone, but not the storage lookup or footprint enforcement.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-919` and `1127-1176` — native matcher checks the fixed pool layout with repeated linear scans over the instance `ScMap`; this is wasted work but only over a handful of entries per native call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:957-1118` and `1212-1232` — native getters and swap use raw `ScVal` extraction for i128 reserves and `ScAddress` clones for token addresses; the broad `ScVal to Val` / `add host object` trace zones are not fully removable because SAC calls and return/event values still require host values.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-304` with `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:930-934` and `1191-1195` — code TTL extension reloads and clones the contract instance to recover the WASM hash; carrying the hash in a compact frame would remove this duplicate clone but not the TTL extension itself.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1378-1448` and `2001-2025` — reserve update rebuilds the six-entry instance `ScMap`, then `persist_instance_storage` clones it again and `store_contract_instance` writes the canonical updated instance entry; a compact frame can reduce one intermediate clone but still must materialize the final XDR storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-630`, `1178-1375`, and `1465-1501` — the remaining native swap path includes frame push/pop, auth snapshots, rollback storage snapshots, TTL extension, SAC transfer/balance calls, arithmetic checks, and event creation; these costs are unaffected by a compact pool frame.
- `ai-summary/fail/ledger/summary.md:79-80` — adjacent native-pool frame/storage optimizations were already benchmarked or reviewed as sub-threshold: moving the native instance into the frame was Low/sub-1%, and fusing the two reserve-storage map updates benchmarked at only 0.56%.

### Why It Failed

The hypothesis over-attributes broad host trace zones to pool instance-map materialization. On the actual code path, most cited `ScVal to Val`, `Val to ScVal`, `new map`, `add host object`, `storage get`, and indexed map-lookup time belongs to mandatory SAC calls, host frame/accounting, TTL/storage enforcement, event construction, and final ledger-change/writeback work, not to the removable pool-frame representation. The removable subset is a combination of fixed-size ScMap scans and small instance/storage clones, plus one duplicate instance load for code TTL; prior adjacent measurements show these classes of native-pool storage/frame changes are well below the objective's 3% Medium floor.

### Lesson Learned

For native Soroswap pool hypotheses, distinguish raw `ScContractInstance` clone/scan overhead from the much larger semantic work required by the frame: auth/rollback isolation, SAC calls, TTL extension, event output, and canonical ledger-entry writeback. A Medium candidate needs to remove or amortize one of those larger semantic phases, not just compact the six-field pool instance representation.
