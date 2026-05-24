# H002: Native Pool Call State Cache Across Getter and Swap Calls

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-6% soroswap apply-time reduction by avoiding repeated native-pool instance loading, layout scans, TTL extension, and frame cloning across the router's repeated calls to the same pair
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one Soroswap router transaction, repeated calls to the same allowlisted pair contract (`token_0`, `token_1`, `get_reserves`, then `swap`) should share a typed native-pool state snapshot. The host should validate the Wasm hash and instance layout once for that pair in the current top-level invocation, reuse the typed token/reserve/factory values for native getter calls, and invalidate/update the snapshot when native `swap` mutates reserves.

## Mechanism

`Host::call_contract_fn` retrieves the full contract instance before every contract call, builds `args_vec`, then probes the native getter and native swap paths independently. Each successful native getter constructs a `Frame::NativeContract`, clones the full `ScContractInstance`, extends instance/code TTL, and performs linear `ScMap` layout scans via `soroswap_pool_scmap_get`; the later native `swap` repeats the same validation and instance-storage lookups. A small per-host-invocation cache keyed by pair `ContractId` and guarded by the existing next-protocol/Wasm-hash checks can reuse a typed `SoroswapPoolState { token_0, token_1, factory, reserve_0, reserve_1, k_last }` across those calls, while preserving deterministic fallback for any shape mismatch and updating the cached reserves after `swap`.

## Trigger

Run the current soroswap apply-load benchmark from `CURRENT_STATE.md`. The Soroswap router Wasm repeatedly calls the same pair contract during each swap path; in the current native path, every getter and the final swap re-enters `call_contract_fn` and repeats pair-instance preparation. A PoC should add tracing around native getter/swap hits and show that per-tx pair calls collapse to one instance-layout load plus cheap cached getter returns, with identical emitted events and ledger changes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-835` — `call_contract_fn`, which retrieves the full instance and probes native getter/swap paths on every contract call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-871` — `try_call_native_soroswap_pool_getter`, where repeated getter calls clone `args_vec`/instance and build a native frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-929` — `soroswap_pool_instance_matches_getter` and `soroswap_pool_scmap_get`, repeated linear layout checks over the same pair instance storage.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` — `soroswap_pool_instance_storage_get` and required-value helpers, repeated map lookups for token/reserve keys already read during getter validation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — `try_call_native_soroswap_pool_swap` / `call_native_soroswap_pool_swap`, which should consume and update the cached typed state after validating the same pair.

## Evidence

The current apply-contained Tracy aggregation from the `CURRENT_STATE.md` soroswap trace shows the remaining per-transaction router invocation path is dominant: `Vm::invoke_function_raw` has 7.27s across 7,867 calls, `call` dispatch has 5.13s across 23,569 calls, and `Host::invoke_function` has 8.24s across 7,851 calls inside `applyLedger` worker windows. The accepted native pair getter/swap fast paths have removed pair Wasm execution, but the source still performs per-call instance retrieval, layout validation, frame construction, and TTL extension for every native getter and swap. Those repeated native-pair calls are all descendants of the measured router invocation and are not TX-set construction.

The proposed cache is more specific than the previously rejected generic contract-instance/cache-plan ideas: it does not cache arbitrary contract calls, does not try to reuse Wasm VMs, and does not bypass the router. It is limited to the existing next-protocol native Soroswap pair path, keyed by the allowlisted pair hash and pair contract id, with cache invalidation on the same native `swap` code that mutates reserves.

## Anti-Evidence

The broad `Vm::invoke_function_raw` and `call` zones include mandatory router Wasm execution, dispatch accounting, auth, and storage work that this cache cannot remove. The Medium case depends on native getter/swap preparation being a multi-call repeated subset large enough to move the top-line benchmark; if instrumentation shows the repeated instance/layout/TTL work is only a sub-millisecond slice per ledger, this should be rejected. Correctness also requires careful rollback behavior: cached state must be scoped to the host invocation/frame rollback boundary and must not survive failed native calls or cross into unrelated pair contracts.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prior records cover broad native Soroswap precompile variants, direct SAC transfer/balance work, and TTL/probe dedup, but not this exact post-native-pair per-pair typed-state cache in the current source
**Failed At**: reviewer

### Trace Summary

The repeated work exists: `call_n_internal` enters `call_contract_fn` for each router-to-pair call, `call_contract_fn` reloads and clones the pair `ScContractInstance`, then independently probes the native getter and swap paths. Successful native getters and swaps push `Frame::NativeContract`, extend pair instance/code TTL, lazily convert instance storage into an `InstanceStorageMap`, and read the same token/reserve keys again. However, a correct cache can only remove small local preparation work; the broad `call`/VM totals include router execution and mandatory contract-call semantics, while swap still needs a native frame for current-contract identity, authorization stack shape, event emission, rollback, and instance-storage persistence.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` — `call_n_internal` performs reentry checks and then dispatches each contract call through `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` rebuilds the instance ledger key, retrieves/clones the full instance, copies args, probes native Soroswap getter/swap, and otherwise falls back to VM or SAC frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-871` — native getter path is next-protocol/hash/arity/symbol gated, scans the `ScMap` for the requested layout, clones id/args/instance into `Frame::NativeContract`, and calls the getter inside `with_frame`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-1003` — getter validation and value reads are linear scans over small instance `ScMap` entries plus in-frame `InstanceStorageMap` lookups.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — native swap repeats pair layout checks, pushes a native frame, extends TTL, re-reads token/reserve keys, performs SAC transfer/balance work, mutates reserve keys, and emits the pair swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:437-631` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1886` — `with_frame` supplies rollback and persistence semantics; modified instance storage is stored on successful frame exit and rolled back on error.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-320` — pair instance/code TTL extension does storage-map probes and `extend_ttl`; previously sized TTL/probe variants are sub-threshold.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370`, `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` — authorization call-stack frames and `require_auth` derive contract/function/args from the current frame, constraining any attempt to skip frames around mutating native calls.

### Why It Failed

The inefficiency is real but below the optimize-soroswap objective's Medium threshold. Prior retained sizing already bounds the main components this cache would remove: generic per-tx TTL dedup had an ideal wall-clock ceiling of about 0.49% after parallel normalization, redundant `extend_contract_code_ttl_from_contract_id` instance reads were about 0.06%, and even the much larger residual `SAC transfer` subcall boundary was only about 2.0% of the current 218.31 ms soroswap baseline before discounting mandatory semantic work. This cache targets a smaller slice than those zones: tiny `ScMap` layout scans, a handful of per-call instance-storage lookups/conversions, and possibly some no-op TTL/probe repetition.

Crediting the full 5.13s aggregate `call` dispatch or 7.27s `Vm::invoke_function_raw` totals would be incorrect because those zones include mandatory router Wasm execution, host-call dispatch, authorization/storage/accounting, and frame semantics that the cache would not remove. Swap must still run in a native contract frame to preserve current-contract identity for event emission, authorization stack shape, rollback, and `persist_instance_storage`; a cache not integrated with frame rollback would also risk stale reserves after a failed nested call. Therefore the realistic removable portion is sub-Low to Low at best and does not clear the 3% Medium floor required by this objective.

### Lesson Learned

After native getter/swap and direct SAC balance successes, remaining per-pair preparation cleanups must be sized from isolated subzones, not from broad router/host-call aggregates. Small per-call instance, TTL, and layout-cache wins are structurally deflated by Soroban parallel apply and by mandatory native-frame semantics, so they should not be promoted without instrumentation showing an isolated >3% apply-time slice.
