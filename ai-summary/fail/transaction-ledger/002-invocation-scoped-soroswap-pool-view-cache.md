# H002: Invocation-scoped native Soroswap pool view cache

**Date**: 2026-05-22
**Subsystem**: transaction-ledger / Soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reusing validated pair instance metadata across native pool getter and swap subcalls within one router invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During one top-level soroswap router invocation, repeated calls into the same pair contract should not repeatedly retrieve the pair contract instance, scan the same raw `ScMap`, extend the same pair instance/code TTL, and rebuild the same instance-storage view. The efficient path should cache a validated, invocation-local `SoroswapPoolInstanceView` keyed by pair contract ID, reuse it for native `token_0`, `token_1`, `factory`, `get_reserves`, `k_last`, and `swap` hits, and invalidate or update it when the native `swap` mutates reserves. Observable contract calls, diagnostics, storage effects, events, and fallback behavior should remain identical.

## Mechanism

`Host::call_contract_fn` retrieves the contract instance before every Wasm executable call, then the native pool getter and native pair-swap gates independently validate the same raw pair storage. A soroswap router swap calls several pool getters and then the pair `swap` against the same pair, so the host repeats instance retrieval, raw-map linear scans, TTL extension, and lazy instance-storage setup within a single top-level host invocation. An invocation-scoped cache attached to the host context can store the exact-code-hash/native-layout result after the first pool hit, remember that the pair instance/code TTL was already serviced for the current `(threshold, extend_to)`, and carry updated reserves after `swap`, while falling back to the existing path for non-matching code hash, symbol, arity, layout, or re-entry cases.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each benchmark transaction invokes the router Wasm, which repeatedly calls the same pair contract's zero-argument getters and `swap`; the accepted p26 native gates handle those pool calls under `applyLedger`, but each subcall currently starts from `call_contract_fn` as an independent contract invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:779-825` — `call_contract_fn` retrieves a fresh `ScContractInstance`, builds `args_vec`, then tests native pool getter and pair-swap gates independently for each pool subcall.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-969` — native pool getter gate scans raw storage, extends TTL, and reads through instance storage for each getter call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1070` — native pair-swap gate repeats raw-layout validation for the later `swap` call against the same pair.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:928-943,1079-1090` — native getter and native swap paths separately extend the same pair instance/code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1826` — same-contract frame pop reloads instance storage for outer frames; cache invalidation/update must respect this existing re-entry consistency rule.

## Evidence

The current trace confirms the native pool-call residual work is inside `applyLedger`: `storage get` totals **633.937 ms**, `map lookup indexed` **547.023 ms**, `ScVal to Val` **1,027.178 ms**, `new map` **413.548 ms**, and `extend_current_contract_instance_and_code_ttl` has **29,815** current-contract TTL events in the trace, with the hot path under `applySorobanStageClustersInParallel`. The source structure shows why these categories can repeat for the same pair: every getter/swap subcall starts by retrieving the pair instance and running a native gate, even though the top-level router sequence is within one host invocation and the pair layout is immutable until the final reserve update. Reusing a validated view across the getter sequence and updating it at swap time targets a broader repeated-work pattern than a single getter cleanup.

## Anti-Evidence

This must not become a cluster-wide or cross-ledger cache: prior failures show those caches are sub-threshold and risk cache pressure. The cache should be scoped to one top-level host invocation and cleared on frame-stack exit, with conservative invalidation on any non-native same-contract call or storage mutation. The PoC must also demonstrate that the router actually calls multiple native getters before each native swap on the accepted workload; if the native pair-swap path has already removed most getter traffic, the residual retrieval/TTL share may fall below the Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent raw getter and TTL-cache investigations exist, but this exact invocation-scoped getter+swap view-cache hypothesis was not previously confirmed; the earlier raw-getter failure predated the current native Soroswap hooks
**Failed At**: reviewer

### Trace Summary

The soroswap apply-load transaction is a protocol 23+ Soroban `INVOKE_HOST_FUNCTION` applied through `InvokeHostFunctionOpFrame::doParallelApply`, which calls the p26 Rust bridge and creates a fresh enforcing `Host` for one transaction. The router invocation reaches `HostFunction::InvokeContract`, `call_n_internal`, and then `call_contract_fn`; for pair contracts with the exact Soroswap pool Wasm hash, the current source first retrieves the pair `ScContractInstance`, then tries the native getter gate and native swap gate before falling back to VM execution. The inefficiency is real: each native getter/swap subcall starts with a storage-backed instance retrieval, repeats raw `ScMap` layout checks, extends instance/code TTL independently, and creates a separate native frame whose first instance-storage read lazily materializes an `InstanceStorageMap`. However, the broad trace categories available for this residual work are already too small after 8-way cluster normalization, and only a fraction of them belongs to this specific native-pair view-cache target.

### Code Paths Examined

- `ai-summary/CURRENT_STATE.md:44-67` — current authoritative soroswap median baseline averages 230.225 ms; Medium severity requires a reproducible 3-10% reduction, so the lower bound is about 6.9 ms per ledger.
- `ai-summary/CURRENT_STATE.md:76-126` — diagnostic trace and build state confirm the accepted baseline includes native Soroswap pool getter and native pair swap emulation under next-protocol gating.
- `src/simulation/ApplyLoad.cpp:3381-3505` — each benchmark transaction invokes router `swap_exact_tokens_for_tokens`, includes router/SAC/pair code and instances in the footprint, and marks the pair contract instance read-write.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ serializes the host function, resources, footprint entries, TTL entries, auth, ledger info, and module cache before crossing into `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ Soroban apply runs `InvokeHostFunctionOpFrame::doParallelApply`, placing this host invocation inside the objective's parallel close-ledger apply path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-556` — the Rust bridge builds enforcing storage, installs ledger/auth/module-cache state, calls `Host::invoke_function`, and then extracts storage/events from the fresh host.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1700-1723` — `HostFunction::InvokeContract` converts the contract ID, function symbol, and arguments and dispatches through `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1498-1697` — `call_n_internal` performs re-entry checks and diagnostics, then calls `call_contract_fn` for production contract execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:779-825` — `call_contract_fn` constructs the instance ledger key, retrieves the `ScContractInstance`, clones arguments, tries native Soroswap getter/swap gates for Wasm executables, and otherwise instantiates/invokes the VM.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:837-969` — the native getter path checks protocol/hash/arity/symbol, scans raw instance `ScMap` fields, pushes a native frame, extends instance/code TTL, and reads values via `soroswap_pool_instance_storage_get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1090` — the native swap path checks protocol/hash/arity/symbol/argument shape, repeats raw layout validation, pushes a native frame, and separately extends the same pair instance/code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1092-1263` — native swap re-reads token/reserve values through instance-storage lookups, invokes SAC transfer/balance subcalls, computes the invariant, and updates reserves through `with_mut_instance_storage`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:520-591,1771-1801,1804-1849` — frame exit persists modified instance storage, rolls back on errors, and reloads same-contract outer frames after persistence; any cache carrying updated reserves must integrate with these rollback/reload semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72,114-120,247-280` — instance-storage access lazily materializes `InstanceStorageMap`, contract instance retrieval reads from `Storage`, and code-TTL extension re-retrieves the instance to recover the Wasm hash.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-377,531-688` — storage `get` and TTL extension enforce footprint access, read the storage map, and optionally update TTL state; repeated calls are real work but must still preserve storage errors and protocol-visible metering expectations.
- `ai-summary/fail/transaction-ledger/002-raw-native-pool-getter-instance-view.md:44-79` — prior adjacent getter-only review is not a current duplicate because it failed when the native getter symbols were absent from that source, but it documents the same correctness risks around raw instance views and budget accounting.
- `ai-summary/fail/transaction-ledger/005-cluster-wide-ttl-extension-idempotency-cache.md:89-130` — prior TTL-cache analysis shows hundreds of milliseconds of aggregate TTL self-time normalize to sub-1% critical-path savings after dividing by 70 ledgers and 8 clusters.
- `ai-summary/fail/transaction-ledger/summary.md:184-194` — prior meta-patterns warn that Soroban host micro-caches are usually sub-threshold and that decoded-value reuse changes protocol-visible budget accounting unless explicitly protocol-gated.

### Why It Failed

The claimed repeated work exists, but the objective accepts only Medium or High findings and this cache does not have a credible Medium-sized ceiling. The current baseline is about 230.225 ms median apply time, so a 3% Medium result requires roughly 6.9 ms of critical-path improvement per ledger. Even if one unrealistically assigns the entire cited broad trace categories to this optimization — `storage get` 633.9 ms, `map lookup indexed` 547.0 ms, `ScVal to Val` 1,027.2 ms, `new map` 413.5 ms, plus the known TTL self-time order of hundreds of milliseconds — the aggregate worker total across the 70-ledger, 8-cluster diagnostic run normalizes to roughly 5-6 ms per ledger before subtracting unrelated SAC/router/generic storage work and before preserving mandatory metering. The native-pair view-cache share is therefore below the 3% objective floor.

There are also correctness costs that reduce the removable subset further. A cache that skips repeated TTL work must either preserve or intentionally protocol-gate visible CPU/memory accounting; a cache that carries updated reserves must be rolled back if the native swap frame fails after reserve mutation or persistence fails on frame exit; and any non-native same-contract call or re-entry must invalidate cached raw instance values to match the existing `persist_instance_storage` and `maybe_reload_instance_storage_on_frame_pop` rules. These constraints are manageable for a Low-tier cleanup, but they are disproportionate for a sub-Medium projected win.

### Lesson Learned

After native getter and native pair-swap emulation, the remaining per-pair host work is fragmented across small storage, map, conversion, and TTL categories. Future Soroswap hypotheses should add narrow native-pair spans or counters before promotion and must clear the 6.9 ms-per-ledger Medium floor after dividing aggregate worker time by the configured cluster parallelism and subtracting unrelated SAC/router work.
