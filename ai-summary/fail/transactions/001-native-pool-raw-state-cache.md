# H001: Per-Host Native Soroswap Pool Raw-State Cache

**Date**: 2026-05-24
**Subsystem**: transactions / Soroban native pool apply path
**Severity**: Medium
**Impact**: soroswap apply-time reduction in repeated native pool getter/swap storage handling
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-27 native Soroswap pool calls, repeated getter and swap calls for the same pool within one top-level router invocation should return the same token addresses, factory address, reserves, `k_last`, TTL side effects, events, ledger-entry writes, rent inputs, and resource-limit behavior as the current path. Non-matching Wasm hashes, unexpected instance layouts, older protocols, and any mutation not performed by the native pool helper should continue through the existing storage/frame path unchanged.

## Mechanism

`Host::call_contract_fn` retrieves the pool contract instance from enforcing storage for every native pool getter and swap call, then the native helpers repeatedly scan the raw `ScContractInstance.storage` `ScMap` for fixed integer keys. The current accepted raw-instance baseline avoids generic instance-map materialization, but it still parses the same fixed pool fields repeatedly across the router's burst of getter/swap calls; a per-`Host` cache keyed by pool `ContractId` could store the validated raw `ScAddress`/`i128` fields after the first native match, update the cached reserves when `soroswap_pool_update_reserves` runs, and serve later native getters/swap validation from the cache while preserving the existing cluster order and worker count. This does not introduce new parallelism and is deterministic because the cache is local to one host invocation and invalidated/updated only by the same ordered storage mutations that the host already applies.

## Trigger

Run the current protocol-27 `soroswap, TX=2000, T=8` apply-load workload. The router repeatedly calls the allowlisted Soroswap pool getter exports and the native pool `swap` export for the same pool contracts during `InvokeHostFunctionOpFrame::doParallelApply`; the cache should activate only after `match_native_soroswap_pool_getter` or `match_native_soroswap_pool_swap` validates the exact pool Wasm hash and raw instance layout.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835` — retrieves a contract instance and dispatches every pool getter/swap call through the native gates before VM fallback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-918` — validates getter shape by rescanning fixed `ScMap` keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:919-1088` — native getters re-read and convert fixed token/reserve fields from the frame instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native swap gate validates the same raw instance layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1448` — native swap rereads token/reserve fields and rewrites reserves; cache updates must happen here on success.

## Evidence

The current trace path from `ai-summary/CURRENT_STATE.md` was not present on this host, but the existing transactions records derived from that same current trace timestamp-filtered these zones inside `applyLedger`: 72 apply windows totaling 4,802,199,603 ns, `storage get` totaling 707,240,794 ns, `map lookup indexed` totaling 612,594,844 ns, `new map` totaling 449,333,084 ns, and `storage put` totaling 145,311,950 ns. Those are broad worker aggregates and must be divided by T=8, but they identify the remaining storage/map family as one of the few Medium-sized upper bounds after the accepted native pool and SAC fast paths. The source shows a concrete repeated-read pattern: layout validation, getter return construction, and swap execution all scan the same fixed raw pool instance keys for the same contract during one host invocation.

## Anti-Evidence

The broad storage/map zones include SAC balance storage, enforcing footprint setup, TTL extension, and non-pool host work, so a PoC must add narrow counters or Tracy spans for native pool cache hits before claiming the full bound. TTL extension side effects must not be skipped: every getter/swap still needs the same instance/code TTL behavior or explicit next-protocol metering semantics. Prior generic instance-storage cache ideas were too broad and sub-threshold; this hypothesis is only viable if the current soroswap call burst is dominated by repeated allowlisted pool raw-state reads rather than unrelated storage work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transactions fail/success records; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The soroswap apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, bridges into Rust `invoke_host_function`, creates one `Host`, and executes the top-level router through `Host::invoke_function`. Router cross-contract calls enter `call_n_internal` and then `call_contract_fn`, where the current native pool hooks retrieve the target instance, check the allowlisted pool Wasm hash and raw fixed-key layout, push a `Frame::NativeContract`, extend instance/code TTL, and perform native getter or swap logic. The repeated raw `ScMap` scans are real, but they are tiny fixed-schema in-memory scans and a correct cache cannot remove the mandatory TTL side effects, SAC balance/storage work, reserve persistence, event construction, or most of the broad storage/map Tracy families cited by the hypothesis.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — serializes Soroban host inputs and calls `rust_bridge::invoke_host_function` from the apply helper.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — v23+ Soroban apply reaches `InvokeHostFunctionParallelApplyHelper` from `doParallelApply`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — builds enforcing storage, constructs the `Host`, and invokes `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1857` and `1868-1890` — top-level and router-originated calls enter `call_n_internal`, enforce reentry/auth diagnostics, and dispatch to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835` — every pool getter/swap call retrieves the contract instance and enters the native getter/swap gates before VM fallback.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:881-917`, `1005-1087`, and `1127-1176` — native getter/swap validation and field extraction repeatedly scan the raw `ScContractInstance.storage` `ScMap` for keys 0, 1, 2, 3, 4, and 5.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:919-955` and `1178-1375` — native getters and swaps still perform TTL extension, host-object/value creation, SAC transfer/balance calls, K-invariant checks, reserve updates, and event construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1378-1448` and `1997-2025` — reserve updates rebuild the raw storage map and persist modified instance storage on successful native swap frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-304` and `307-320` — each native getter/swap still needs instance and code TTL extension; code TTL currently performs an additional instance retrieval to discover the Wasm hash.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352` and `480-489` — broad `storage get`/`storage put` spans cover enforcing-footprint access and map update paths that are mostly mandatory or unrelated to raw pool field parsing.
- `ai-summary/fail/transactions/001-single-pass-native-pool-instance-fields.md` and `ai-summary/fail/transactions/summary.md:71-74` — prior records already rejected stale/broad map-cache projections when the recoverable subset was either covered by the raw-instance baseline or below the Medium threshold.

### Why It Failed

The inefficiency exists, but the projected impact is below the objective's Medium floor. After T=8 normalization, the entire cited `storage get` family is only about 88 ms over 4,802 ms of apply-window time (~1.8%), and the proposed raw-state cache can only address a subset of those gets: pool-instance retrieval and fixed-key raw `ScMap` parsing. It does not remove SAC balance storage, TTL extension, reserve persistence, event/meta output, host-object creation for getter return values, or unrelated enforcing-storage work; the fixed pool `ScMap` itself is only a handful of entries, so repeated scans are a micro-cost. Even a broader correct implementation would need rollback-aware invalidation for failed frames and unknown non-native calls, which adds complexity around a sub-threshold residual path rather than producing a plausible 3-10% apply-time reduction.

### Lesson Learned

Post-raw-instance native pool hypotheses must isolate the exact remaining native-pool subzone instead of projecting from broad `storage get`, `map lookup`, `new map`, and `storage put` aggregates. Once the accepted raw-instance baseline removed generic instance-map materialization, remaining fixed-key pool field scans and per-call instance reuse are too small and too entangled with mandatory TTL/storage semantics to satisfy the optimize-soroswap Medium threshold.
