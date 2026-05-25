# H001: Router-to-native-pool call import fast path

**Date**: 2026-05-25
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-7% soroswap apply-time reduction by bypassing generic cross-contract call import setup for known router-to-pool calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When the Soroswap router Wasm calls the known Soroswap pool contract's getter or `swap` entrypoints in the benchmark shape, the apply path should preserve the same call-frame, auth, storage, TTL, event, result, and rollback semantics as the current native pool callee path, but it should avoid generic Wasm host-import argument decoding and `Host::call_contract_fn` setup that only rediscover the already protocol-gated native pool dispatch.

## Mechanism

The current optimized stack recognizes native pool getters and swaps only after the router crosses the generic `call` host import and reaches `Host::call_contract_fn`, where Core loads the callee instance, copies arguments into `args_vec`, matches `SOROSWAP_POOL_WASM_HASH`, then invokes the native pool helper. A router-aware call-import fast path in the host dispatch layer could identify the exact router-to-pool callee/function/argument shape, then enter the existing native pool helper directly with deterministic frame construction. This would keep the router Wasm execution model intact while removing repeated generic call-import scaffolding from the hottest cross-contract calls.

## Trigger

Run the current soroswap apply-load benchmark with next-protocol enabled. Each router swap invokes pool getters and pool `swap`; those calls enter the Rust VM dispatch `call` import before falling through to `Host::call_contract_fn` and the native pool matcher.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — Tracy `call` host-import dispatch zone where router cross-contract calls enter the host.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-812` — generic `call_contract_fn` setup loads the callee instance, copies args, and only then routes to native pool getters/swap.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-919` — native pool getter matching currently happens after generic call setup.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native pool `swap` matching currently happens after generic call setup.

## Evidence

The latest soroswap trace shows the `call` zone at `soroban-env-host/src/vm/dispatch.rs:304` is an `applyLedger` descendant and has 1,303,110,709 ns self-time over 26,145 calls. Timeline aggregation contained inside `applyLedger` shows the same zone at 5,428,387,766 ns total over 26,079 in-window calls, while `Host::invoke_function` accounts for 9,046,718,940 ns total. The source confirms that native pool dispatch exists but sits behind the generic call path, so the hypothesis targets a concrete remaining layer above the already-successful native pool getter/swap helpers rather than reimplementing the full router.

## Anti-Evidence

This is not viable if it degenerates into a full native router replacement or skips required call-frame semantics. It must be a narrow import fast path that only fires when the current contract/function/callee/argument shape exactly matches the current native pool path and otherwise falls back to `call_contract_fn`. The measured `call` zone also includes non-pool calls, so a PoC must instrument the router-to-pool subset before claiming the full aggregate self-time as removable.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

Router cross-contract calls enter the generated `call` import in `vm/dispatch.rs`, which must convert VM-relative object handles to host objects, return/refill fuel, charge dispatch, and marshal the result back to the router VM. The host then copies the argument vector from the `VecObject`, converts the callee address to a `ContractId`, runs `call_n_internal` reentry/reserved-function/diagnostic logic, and only then reaches `call_contract_fn`, where the existing native pool matcher loads the callee instance and constructs the `Frame::NativeContract` required by the native helpers. A fast path below or inside the import can only skip a narrow wrapper layer; it cannot skip object-handle conversion, argument access, callee-id derivation, reentry checks, frame push/pop rollback semantics, storage/TTL effects, result relativization, or the native helper's required frame context.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254` — generated host-import dispatch creates the `call` Tracy span, clones the host, converts relative VM object handles to absolute host values, returns fuel to the host budget, charges `DispatchHostFunction`, and invokes `host.call`; these steps are mandatory for any router Wasm import path.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:270-296` — after the host call, dispatch checks the returned `Val`, converts absolute object references back to router-VM-relative handles, escalates host errors to traps, and refills VM fuel; a direct native pool call would still need this boundary work.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2592-2624` — `Host::call` copies arguments out of the guest `VecObject` via `call_args_from_obj`, derives the callee `ContractId` from the address object, calls `call_n_internal`, and logs errors; a shape-matching fast path must inspect the same address/function/args before it can prove eligibility.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:192-194` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:540-546` — argument extraction and address-to-contract-id conversion are small, metered copies/visits that are also required to identify the router-to-pool call and pass typed values to the native helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1729` — `call_n_internal` enforces reserved-function and reentry rules before contract dispatch; bypassing this would change call semantics, while reproducing it eliminates much of the claimed shortcut.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` already performs the native pool dispatch before VM instantiation, but still has to retrieve the callee instance, copy args into the frame, construct `Frame::NativeContract`, and execute through `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-859` and `1127-1176` — native pool getter/swap matching is protocol-gated and validates hash, function, argument shape, and fixed storage layout after loading the instance; moving these checks earlier does not remove the need to load/validate the instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-630` and `150-178` — frames are sub-transaction boundaries; `Frame::NativeContract` carries the callee id/function/args/instance and `with_frame` handles push/pop, instance-storage persistence, reload, lifecycle hooks, and rollback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:919-955`, `1178-1375`, `1378-1448`, and `1997-2025` — the native pool helpers rely on the current native frame for contract id, raw instance storage, reserve updates, event emission, TTL extension, SAC transfer/balance calls, and final instance writeback; these dominate the semantic work and remain on any correct fast path.
- `ai-summary/fail/ledger/summary.md` and `ai-summary/fail/ledger/002-compact-native-soroswap-pool-frame.md` — adjacent native-pool frame/storage optimizations were already reviewed or benchmarked below the objective floor; compacting the native pool frame itself was rejected because the removable subset is small relative to required SAC/storage/frame work.

### Why It Failed

The claimed inefficiency exists only as a thin wrapper around mandatory VM/host and contract-frame semantics. The `call` zone's total time includes the native helper and its child work, and its self-time cannot be treated as fully removable: most of the boundary conversion, eligibility inspection, reentry enforcement, frame construction, storage/TTL handling, and result conversion must still happen for deterministic correctness. The remaining avoidable work is limited to small Vec/ContractId/frame setup duplication and moving matcher checks earlier; after parallel-apply normalization and the prior adjacent native-pool findings, this projects below the objective's Medium threshold, so Low/sub-1% style savings are not accepted.

### Lesson Learned

For router-to-pool import optimizations, separate the unavoidable Wasm import boundary and frame semantics from the small generic dispatch scaffolding above the existing native pool path. A Medium candidate needs to remove or redesign a larger semantic phase, not just inline the path from `Host::call`/`call_n_internal` to the already-native pool matcher.
