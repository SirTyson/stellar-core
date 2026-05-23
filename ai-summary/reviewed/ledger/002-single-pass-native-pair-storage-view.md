# H002: Single-Pass Native Pair Storage View for Soroswap Swap

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by replacing repeated generic instance-map reads/inserts in the native pair `swap` path with one validated typed view and one reserve writeback
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a matching next-protocol Soroswap pair `swap`, the host should read token addresses and reserves, validate output amounts, perform the SAC transfer, read post-transfer balances, update reserves, enforce the fee-adjusted K invariant, emit the swap event, and persist instance storage exactly as the current native path does. Because the native gate already requires the fixed vendored pool layout, the implementation should not repeatedly rediscover the same instance keys through generic `ScMap` scans, `InstanceStorageMap` lookups, `Val` conversions, and two separate immutable-map inserts.

## Mechanism

The current native gate scans the loaded `ScContractInstance.storage` with `soroswap_pool_scmap_get` for keys 0, 1, 2, and 3, then the native swap body re-reads key 0 for initialization, keys 2 and 3 for reserves, keys 0 and 1 for token addresses, and finally updates reserves through two functional `s.map.insert(...)` calls. A typed `NativeSoroswapPairView` built in one pass from the already-loaded `ScMap` could carry token/reserve values into the native frame, and a paired reserve update helper could rebuild/persist the instance map once. This preserves deterministic frame semantics while removing repeated generic map searches and one of the two reserve-map rebuilds on every accepted native swap.

## Trigger

Run the current accepted soroswap apply-load benchmark (`soroswap-tx-2000-t-8`) with the p26 submodule at `fbbea0d9`. Every recognized native pair `swap` validates the same pool instance layout and then repeatedly calls `soroswap_pool_instance_storage_get` / `soroswap_pool_get_required_val` before writing reserve keys 2 and 3.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-929` — native getter/swap layout checks call `soroswap_pool_scmap_get`, which linearly scans the instance `ScMap` for each key.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1009` — `soroswap_pool_instance_storage_get` converts integer keys to `Val` and performs generic `InstanceStorageMap` lookups during native execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1130` — native pair `swap` rereads initialization, reserve, and token fields that were already proven present by the gate.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1257-1266` — reserve writeback rebuilds the immutable instance map twice with two `insert` calls.

## Evidence

The current source contains the native Soroswap pair path at p26 `fbbea0d9`, resolving the earlier native-path-absent failure pattern. Tracy confirms the surrounding generic storage/map work is inside `applyLedger`: `map lookup indexed` at `soroban-env-host/src/host/metered_map.rs:330` has 441,212,837 ns self-time and 839,562 in-apply events, `map lookup` at `soroban-env-host/src/host/metered_map.rs:173` has 373,789,996 ns self-time, `new map` at line 148 has 350,833,562 ns self-time and 181,114 in-apply events, and `ScVal to Val` at `soroban-env-host/src/host/conversion.rs:436` has 493,872,860 ns self-time. The code path is structurally redundant even before attribution: the same four fixed pair fields are scanned/validated, then fetched again through the native frame, and reserve writeback performs two separate immutable-map rebuilds.

## Anti-Evidence

The aggregate map/conversion zones include storage, footprint, TTL, and non-pair work, so the reviewer should isolate native pair key 0/1/2/3/5 accesses before promotion. A typed view must still preserve frame rollback, budget-visible behavior under the next-protocol gate, malformed-layout fallback/error behavior, and byte-equivalent persisted `ScMap` ordering. The reserve update can only be batched if it produces the same sorted map and charges either the same costs or intentionally changes costs behind the accepted next-protocol metering gate.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated on the current native-hook source path

### Trace Summary

The current p26 host does contain production native Soroswap getter and pair `swap` hooks under `Host::call_contract_fn`, so earlier failures based on native-path absence are stale for this checkout. The accepted native swap path validates the pair layout by repeatedly scanning the loaded XDR `ScMap`, then enters a `NativeContract` frame and lazily materializes the same instance storage into a generic `InstanceStorageMap` for five fixed-key reads. On successful swaps it performs two immutable `MeteredOrdMap::insert` rebuilds for reserve keys 2 and 3, and frame pop converts the whole instance map back to `ScMap` for persistence. A one-pass typed view plus typed reserve replacement can remove real repeated scans, host-map lookups, XDR-to-host conversions, and one reserve-map rebuild while preserving deterministic frame rollback if persistence remains tied to the native frame.

### Code Paths Examined

- `ai-summary/fail/ledger/002-typed-native-pair-instance-storage.md:38-65` — closest prior file rejected the same broad storage-specialization angle because the reviewed checkout lacked native hooks; this source now contains those hooks, so that failure is stale rather than a duplicate for the current path.
- `ai-summary/fail/ledger/001-move-loaded-native-instance-into-frame.md:38-70` — confirms the pipeline has already treated stale absent-native-path failures as novelty-pass when re-traced against the current native implementation, but rejected only the narrower instance-clone variant for low impact.
- `src/ledger/LedgerManagerImpl.cpp:2531-2704` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — Soroban invocations execute inside `applySorobanStageClustersInParallel` worker threads during `closeLedger`, so native Soroswap swaps are in the apply hot path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-585` — C++ invokes the Rust host bridge, which constructs a `Host`, calls `Host::invoke_function`, then extracts ledger changes; the native pair hook runs inside this apply-contained host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` retrieves the contract instance, probes native getter/swap hooks for matching Wasm contracts, and otherwise falls back to normal Wasm execution.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-929,1013-1074` — native getter/swap gates validate fixed pool storage by repeated `soroswap_pool_scmap_get` scans over the loaded XDR `ScMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:47-67` — the first native storage access lazily converts the frame `ScContractInstance.storage` into a generic `InstanceStorageMap`, including `ScVal` to `Val` conversion for every instance-storage key/value.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1009,1076-1130` — native `swap` re-fetches key 0, reserves 2/3, and token addresses 0/1 through `soroswap_pool_instance_storage_get` and generic map lookup even though the gate already proved the layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1257-1266` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-225` — reserve writeback performs two sequential immutable-map inserts, each doing a lookup and constructing a new vector-backed map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:325-384` — indexed `get_at_known_position` / `insert_at_known_position` helpers already show the host accepts side-indexed map access when the caller independently validates positions, but the native pair swap does not use them.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1882` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:278-288` — frame pop persists modified instance storage by converting the whole host map back to a sorted XDR `ScMap` and storing the contract instance.

### Findings

The inefficiency exists and is on the target hot path. A successful accepted native pair swap performs four fixed-key XDR `ScMap` layout probes during the native gate, then materializes the entire pair instance storage into a host `InstanceStorageMap`, then does five fixed-key generic reads and two reserve inserts against that vector-backed map. The generic operations are correct for arbitrary contract instance storage, but the accepted native path has already restricted execution to the vendored Soroswap pool hash, `swap` symbol, argument shape, and fixed key layout, so the repeated discovery of keys 0/1/2/3 is unnecessary for matched swaps.

Existing optimizations do not already cover this path. The source has side-indexed `MeteredOrdMap` helpers, direct SAC balance reads, and next-protocol native Soroswap dispatch, but `call_native_soroswap_pool_swap` still goes through `soroswap_pool_instance_storage_get` and `s.map.insert`. The narrower "move loaded instance into native frame" cleanup would only remove one XDR instance clone and was below threshold; this hypothesis targets the larger materialization/read/update/persist envelope for pair storage itself.

The proposed fix is correctness-plausible if it remains strictly inside the existing next-protocol native gate. The typed view must be built only after hash, function, arity, argument, and storage-layout validation pass; malformed or unsupported instances must still return `Ok(None)` from the native probe so Wasm fallback handles them. Reserve replacement must preserve sorted `ScMap` ordering byte-for-byte except for values at keys 2 and 3, must keep `with_frame` rollback semantics for later event/persist failures, and must trigger any same-contract instance-storage reload behavior that the current `persist_instance_storage` path would trigger.

The projected impact is Medium rather than merely Low. Each accepted native swap can avoid repeated fixed-key scans/lookups and, more importantly, avoid generic instance-map construction/conversion plus one of the two functional reserve-map rebuilds; the cited `new map`, `map lookup`, `ScVal to Val`, and `Val to ScVal` envelopes are large enough that the pair-storage subset has a plausible 3-10% apply-time ceiling. Final promotion still depends on PoC benchmarks isolating this subset from unrelated storage/footprint work.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (`try_call_native_soroswap_pool_swap`, `call_native_soroswap_pool_swap`, reserve writeback, and native frame/persist integration if needed); possibly `src/rust/soroban/p26/soroban-env-host/src/storage.rs` or `host/metered_map.rs` only if a reusable typed/known-position helper is cleaner.
- **Change description**: Add a `NativeSoroswapPairView` built in one pass over `ScContractInstance.storage` for matched swaps, carrying token addresses, reserve values, and key positions. Thread that view into the native swap body so it does not call `soroswap_pool_instance_storage_get` for keys 0/1/2/3. Replace reserve writeback with a single deterministic update of the original sorted `ScMap` (or one known-position host-map rebuild if direct XDR persistence is too invasive), and persist through the frame so rollback/reload semantics remain equivalent.
- **Correctness check**: Existing coverage should include the native Soroswap apply-load path (`src/simulation/test/LoadGeneratorTests.cpp` soroswap apply-load test) plus the full unit suite. Add focused host/native-pair tests if current tests do not cover malformed storage fallback, negative/zero output errors, invalid `to`, reserve updates, event output, and rollback after a post-update failure.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` repeatedly and require at least a 3% soroswap median apply-time reduction. Tracy attribution should show fewer native-pair `map lookup`, `new map`, `ScVal to Val`, and `Val to ScVal` events inside `applyLedger`, with no regression in SAC or non-native Soroban paths.
