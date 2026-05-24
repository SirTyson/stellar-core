# H001: Native Soroswap Pool Raw Instance Storage

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing generic host-object/map work from the protocol-27 native Soroswap pool path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a protocol-27 Soroswap pool call matches the allowlisted pool Wasm hash and the fixed instance-storage schema, the native getter and `swap` path should produce the same return values, storage changes, events, error ordering, and deterministic ledger output as the current native emulation, while avoiding generic `ScVal` -> `Val` instance-storage materialization and repeated `MeteredOrdMap<Val, Val>` lookups for fixed integer keys.

## Mechanism

`call_contract_fn` first loads and clones the full `ScContractInstance`, then the native pool fast path clones it again into `Frame::NativeContract`; `maybe_init_instance_storage` lazily converts the instance `ScMap` to a host `InstanceStorageMap`, and `soroswap_pool_instance_storage_get` repeatedly looks up fixed keys through `MeteredOrdMap<Val, Val>`. The optimized path can keep a native-pool frame sidecar containing the already-validated raw `ScMap` fields (`token_0`, `token_1`, `reserve_0`, `reserve_1`, optional `k_last`, `factory`) and update reserves through a fixed-schema writer, preserving p26 behavior by remaining protocol-gated and preserving or intentionally rescheduling protocol-27 metering.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on protocol 27. Each accepted native pool getter or `swap` call on the allowlisted pool Wasm hash enters `try_call_native_soroswap_pool_getter` / `try_call_native_soroswap_pool_swap`, then accesses instance storage through the generic host map path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:790-817` - `call_contract_fn` retrieves the instance, builds `args_vec`, and checks native pool paths before VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` - native pool getter gate clones the instance into a `NativeContract` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` - native pool swap gate validates fixed storage shape and clones the instance into a `NativeContract` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` - fixed integer instance-storage reads go through `with_instance_storage` and `MeteredOrdMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1257-1266` - reserve updates rebuild the generic host map via two inserts.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:30-67` - `InstanceStorageMap::from_instance_xdr` converts every instance-storage `ScVal` pair into host `Val`s.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1819` - `maybe_init_instance_storage` performs the lazy generic conversion for each frame.

## Evidence

The current trace in `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` shows `ScVal to Val` at `host/conversion.rs:436` with 493.9ms self-time across 804,622 calls, `new map` at `metered_map.rs:148` with 350.8ms self-time, `map lookup` + `map lookup indexed` with 814.9ms self-time, and `add host object` at `host_object.rs:450` with 286.5ms self-time. Unwrapped timestamp checks place `ScVal to Val` (1.144s total duration) and `add host object` (373ms total duration) inside `applyLedger` windows, so this is not TX-set construction. The current native pool path is a good target because it knows the schema is exactly fixed u32 keys before it enters the generic map path.

## Anti-Evidence

This must not become another broad native Soroswap bypass: prior router/pair/SAC bypass proposals failed on incomplete semantic and metering specifications. The viable shape is narrower: keep the existing native pool semantics and only replace fixed-schema instance-storage representation inside that already-accepted protocol-gated path. The reviewer should require a clear metering plan because removing `to_valid_host_val`, map construction, or map lookup charges directly would change protocol-visible resource observations.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The claimed path is real: `closeLedger` applies Soroban transactions through `InvokeHostFunctionOpFrame`, crosses the Rust bridge into `e2e_invoke::invoke_host_function`, and then `Host::invoke_function` reaches `call_contract_fn`. The native Soroswap pool gate validates the allowlisted Wasm hash and raw `ScMap` shape, but it still pushes `Frame::NativeContract` with a cloned `ScContractInstance`; the first native getter or swap storage read then calls `maybe_init_instance_storage`, converting the entire instance `ScMap` into `MeteredOrdMap<Val, Val>`. Subsequent fixed-key reads and reserve updates use the generic metered map path even though the keys and types have already been checked by the native-pool gate.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2915` — `applyTransactions` runs inside ledger close and dispatches Soroban phases that include the benchmarked invoke-host operations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply code calls `rust_bridge::invoke_host_function` with ledger entries, TTL entries, resources, auth, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018` — invoke-host apply adds the footprint, calls the Rust host, records storage changes, collects events, and finalizes success.
- `src/rust/src/soroban_proto_any.rs:391-451` — Rust bridge dispatch wraps protocol-specific host invocation and times the host function.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-575` — builds `Storage`, constructs `Host`, invokes the host function, finishes storage/events, and computes ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1733-1756` — `HostFunction::InvokeContract` converts args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-829` — `call_contract_fn` retrieves the full instance, checks native Soroswap pool getter/swap gates, and otherwise instantiates Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-870` and `1013-1073` — native getter/swap gates are protocol-27-only, hash/arg/schema-gated, and clone the instance into `Frame::NativeContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-929` — the gate already reads the raw `ScMap` to validate fixed integer keys and value types.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:969-1003` and `1076-1266` — native getter/swap implementation reads keys 0/1/2/3/4/5 through `with_instance_storage` and updates reserves through two `MeteredOrdMap::insert` calls.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:30-67` — `InstanceStorageMap::from_instance_xdr` converts every instance-storage key/value pair via `to_valid_host_val` and constructs a new metered map.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` — immutable and mutable instance storage access lazily initializes generic storage and marks mutable access as modified.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1804-1886` — frame storage is lazily initialized, then persisted by converting the generic host map back to `ScMap` and storing the contract instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160`, `168-242`, and `196-224` — map construction, lookup, and insert allocate/copy/charge through the generic sorted-vector map path.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-455` and `host_object.rs:446-457` — `ScVal` to `Val` conversion and address-object materialization account for the traced conversion/object work.

### Findings

The inefficiency exists and is on the soroswap apply hot path. The current native path deliberately avoids Wasm instantiation for protocol 27, but it still pays the generic instance-storage representation cost that a Wasm contract needs: full `ScMap` to host-`Val` conversion, `HostObject` allocation for address values, metered sorted-map construction, repeated binary-search lookups, and reserve updates through cloned map rebuilds. There is no cache or pool that removes this per-frame work; the `Context` starts with `storage: None`, and `maybe_init_instance_storage` materializes it on the first storage read for each native frame.

The proposed fix is correctness-plausible if it stays narrowly scoped to the existing allowlisted native pool path. A native sidecar can be initialized from the raw `ScMap` already inspected by `soroswap_pool_instance_matches_getter` / `try_call_native_soroswap_pool_swap`, expose typed accessors for keys 0/1/2/3/4/5, and for swap write a replacement `ScMap` that preserves all non-reserve entries and ordering while changing only reserve keys 2 and 3. It must not bypass the existing TTL extensions, SAC transfer/balance calls, event construction, frame rollback, or final `Storage` ledger-change accounting. Metering is the main constraint: p26 exact behavior is protected by the existing protocol gate, but protocol-27 budget/resource observations must either be explicitly redefined for this native sidecar or compensated with equivalent/coalesced charges so budget-exceeded behavior remains deterministic.

The projected impact is large enough for this objective. The current baseline soroswap median is about 218 ms, so the Medium floor is roughly 6.5 ms per applied ledger. The diagnostic trace attributes hundreds of milliseconds across the run to the exact zones this path exercises (`ScVal to Val`, `new map`, `map lookup`, `map lookup indexed`, and `add host object`), and the native pool path has already fixed the schema before paying those costs. Even partial removal of this generic instance-storage work should plausibly clear the 3% apply-time threshold, while the optimization is narrow enough to avoid the semantic risks of broader Soroswap bypasses.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, `src/rust/soroban/p26/soroban-env-host/src/storage.rs` only if a small native-sidecar type belongs there, and any minimal helpers needed near `Host::persist_instance_storage` / `store_contract_instance`.
- **Change description**: add a protocol-27-only native Soroswap pool instance-storage representation for `Frame::NativeContract` or a parallel sidecar keyed to that frame. Populate it from the already-validated raw `ScMap`, replace `soroswap_pool_instance_storage_get` / reserve update calls with typed sidecar accessors on the native path, and persist swap reserve changes by constructing the final `ScMap` directly rather than materializing and mutating `MeteredOrdMap<Val, Val>`.
- **Correctness check**: existing native pool getter/swap tests and Soroban host storage/event tests should still cover return values, storage changes, rollback, event emission, and protocol gating. Add focused tests only for the new sidecar behavior if existing tests do not compare storage output for getters, swap reserve persistence, optional `k_last`, `factory`, missing/invalid keys, and p26 fallback.
- **Benchmark focus**: run `scripts/run_apply_load_matrix.py` repeatedly on the soroswap scenario and compare top-line median apply time against `ai-summary/CURRENT_STATE.md`. A diagnostic Tracy run should show lower `ScVal to Val`, `new map`, `map lookup` / `map lookup indexed`, and `add host object` time inside `applyLedger`; the accepted PoC should demonstrate at least a reproducible 3% median apply-time reduction, not just lower budget counts.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:967-996` — added a native `Frame::NativeContract` read path for Soroswap pool instance storage so fixed u32-key reads use the frame's raw `ScContractInstance.storage` `ScMap` instead of forcing lazy `InstanceStorageMap::from_instance_xdr` and `MeteredOrdMap` materialization.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1278-1406` — replaced native pool reserve writes with a raw-`ScMap` updater for keys 2 and 3, preserving all other entries and retaining the generic `with_mut_instance_storage` fallback for non-native callers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1962-1966` — taught frame-pop persistence to store the updated raw native swap instance storage directly through the existing `store_contract_instance` path.

### Demonstration

The native Soroswap pool getter and swap paths now avoid constructing the generic host instance-storage map for their fixed schema: they read from the already-cloned raw `ScMap` on `Frame::NativeContract`, and swap reserve updates construct the final `ScMap` directly. This removes the hot `ScVal` conversion, map construction, fixed-key map lookups, and two generic map inserts from the accepted protocol-27 native pool path while preserving existing TTL, SAC transfer/balance, event, rollback, and storage-persistence flow.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`, built with `make -j $(nproc)`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`. The full suite completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and p26 Soroban host Rust tests passing.

---

## Final Review — Needs Revision

**Date**: 2026-05-24
**Final review by**: gpt-5.5, high

### What Needs Fixing

The source change builds and the full test suite passes, but the independent benchmark signal is not strong enough to confirm. Against the accepted baseline soroswap medians of `221.844987`, `217.378587`, and `215.707167` ms, the optimized non-Tracy runs measured `214.6252585`, `213.2268860`, and `223.8621940` ms. The third optimized run regressed above the baseline range, and the average soroswap improvement is only `0.49%`, below the objective's 1% validity floor. Max-sac improved by about `3.04%`, but soroswap is the headline metric for this objective.

### Revision Instructions

Investigate why the raw instance-storage fast path does not produce a consistent soroswap apply-time win. Either strengthen the optimization so all three non-Tracy `scripts/run_apply_load_matrix.py` runs show at least a reproducible 1% soroswap apply-time reduction with the max-sac tradeoff still inside the allowed envelope, or narrow/reframe the finding if the current change is only a subthreshold cleanup. Do not rely on Tracy-only zone reductions; final confirmation requires the top-line non-Tracy soroswap medians to improve consistently.

Independent final-review benchmark runs:

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `406f9e8903e4-20260524-094943` | sac, TX=6000, T=8 | 305.5222145 | 324.5488646 | 335.7251047 |
| 1 | `406f9e8903e4-20260524-094943` | soroswap, TX=2000, T=8 | 214.6252585 | 218.2445330 | 221.2006826 |
| 2 | `406f9e8903e4-20260524-095550` | sac, TX=6000, T=8 | 304.5622925 | 321.4203822 | 341.4593363 |
| 2 | `406f9e8903e4-20260524-095550` | soroswap, TX=2000, T=8 | 213.2268860 | 218.7957045 | 225.5982866 |
| 3 | `406f9e8903e4-20260524-100158` | sac, TX=6000, T=8 | 305.2281980 | 323.7270351 | 342.6274186 |
| 3 | `406f9e8903e4-20260524-100158` | soroswap, TX=2000, T=8 | 223.8621940 | 228.1215521 | 230.0709387 |

### Checks Passed So Far

- Source diff is scoped to the p26 Soroban host native pool storage path.
- No test-file edits were present in the optimization diff.
- Build with next protocol and Tracy flags completed successfully.
- Full `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed cleanly.
- The optimization targets an in-scope `closeLedger` native Soroswap pool path, not TX-set construction or lazy background bucket work.

---

## PoC Attempt (Revision)

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: claude-opus-4.7, high
**Builds on**: prior POC_PASS (2026-05-24, gpt-5.5, high) that landed the raw-`ScMap` getter and reserve-update fast paths.

### Revision Motivation

The prior PoC eliminated `MeteredOrdMap` construction/lookup/insert from the native pool path, but final-review benchmarks measured only ~0.49% median soroswap apply-time improvement — below the 1% validity floor. The remaining per-call cost was dominated by repeated `to_valid_host_val(ScVal::I128)` conversions: every `soroswap_pool_get_required_val(...)` call still produced a fresh `I128Object` host object even when the caller only needed the underlying `i128`. The Tracy trace showed `ScVal to Val` (493ms self) and `add host object` (286ms self) as the next largest zones; both are i128-heavy in the soroswap pool path.

### Changes Made

All changes are in `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, gated by the existing `Frame::NativeContract` check (i.e. protocol-27-only, allowlisted Soroswap pool Wasm hash).

- **Native i128 read helpers** (~lines 1031-1076): added `soroswap_pool_native_i128(key) -> Option<i128>`, `soroswap_pool_required_native_i128(key) -> i128`, `soroswap_pool_on_native_frame() -> bool`, and `soroswap_pool_i128_to_val(value) -> Val`. The native readers consult `Frame::NativeContract`'s raw `ScContractInstance.storage` and decode `ScVal::I128(Int128Parts)` directly into an `i128` without allocating a host object. `soroswap_pool_i128_to_val` materializes a fresh `I128Object` exactly once when a host-object representation is actually needed (return value to callers).
- **Swap reserve reads now i128-direct** (~lines 1141-1144, was 4 lines, still 2 lines): the `call_native_soroswap_pool_swap` body that previously did `soroswap_pool_get_required_val` followed by `i128::try_from_val` for keys 2/3 now calls `soroswap_pool_required_native_i128` once per reserve. This removes two `to_valid_host_val(ScVal::I128)` conversions and two `add_host_object(i128)` allocations per swap.
- **i128 getter return-paths skip generic conversion** (~lines 1007-1029): `soroswap_pool_get_i128_val` and `soroswap_pool_get_optional_i128_val` now read the i128 directly from the raw `ScMap` when on a native frame and construct the return-value `I128Object` via `add_host_object(i128)` rather than going through `to_valid_host_val`'s generic `try_into_val` dispatch. This shortens `GetReserves` (two i128 returns wrapped in a vec) and `KLast` (optional i128) without changing observable values.

The prior PoC's getter `with_instance_storage` fast path, swap reserve writer that builds a fresh `ScMap` directly (avoiding `MeteredOrdMap` rebuild), and `persist_instance_storage` swap branch that stores the updated raw `ScMap` through `store_contract_instance` are all preserved.

### Demonstration

After this revision, a single native Soroswap pool swap call avoids:

- 2 `to_valid_host_val(ScVal::I128)` conversions for reserves (was: read reserves into host objects, then immediately decode back to `i128`).
- 2 `add_host_object(i128)` allocations for those intermediate reserve objects.
- For each `get_reserves`/`k_last` getter call (which are issued frequently by the router/aggregator side of the soroswap bench), the generic `ScVal -> Val` dispatch and depth-limited `try_into_val` path is replaced by a direct `I128Parts -> i128 -> add_host_object` flow.

This targets exactly the Tracy zones (`ScVal to Val`, `add host object`) that remained dominant after the previous PoC. Address materialization for `token_0`/`token_1` is unchanged — those values must become `AddressObject` host objects to be passed to the SAC, so there is no equivalent shortcut.

Protocol behavior: the path remains gated to `protocol > MIN_LEDGER_PROTOCOL_VERSION` (i.e. p27 only) inside the existing `try_call_native_soroswap_pool_*` entry points, so p26 ledger output is unaffected. On p27, the metering envelope is consistent with the previously-accepted native pool path: we trade `MeteredOrdMap::get` + `to_valid_host_val(ScVal::I128)` charges for a single `add_host_object` charge per i128 return, which is a strict reduction.

### Test Results

- Build: `make -j $(nproc)` succeeded with the existing `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production` configuration. Release rust profile compiled cleanly.
- Stellar-core unit tests: `NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' bash src/test/selftest-nopg` ran all 124 partitions to `100%` with no failures (covers `[tx]`, `[soroban]`, `[bucket]`, `[overlay]`, etc.).
- Soroban host rust tests: `bash src/test/check-sorobans` with `SOROBAN_PROTOCOLS_TO_TEST=p26` ran the entire `soroban-env-host` test suite (`751 passed; 0 failed`) plus all integration tests (`fees`, `integration`, `option`, `secp256r1_sig_ver`) green.
- `bash src/test/check-nondet` passes (no nondeterministic constructs introduced).
- Pre-existing environmental flake: `lib/gperftools/tcm_min_asserts_unittest` failed under the parallel `make check` harness but passes when invoked directly (`./tcm_min_asserts_unittest` → `[ PASSED ] 24 tests`). This is unrelated to the change and was present before this revision.

---

## Final Review — Needs Revision

**Date**: 2026-05-24
**Final review by**: gpt-5.5, high

### What Needs Fixing

The revised source change builds and the full test suite passes, but the independent non-Tracy benchmark signal still does not meet the objective gate. Against the accepted baseline soroswap medians of `221.844987`, `217.378587`, and `215.707167` ms (average `218.310247` ms), the revised optimized runs measured `218.5427345`, `223.7841585`, and `213.3274505` ms (average `218.551448` ms). That is a `0.11%` average soroswap regression, with one run substantially above the baseline range, so the change is not eligible for confirmation.

Max-sac medians improved from baseline average `314.654682` ms to `308.899293` ms (`1.83%` improvement), but soroswap apply time is the headline metric for this objective and did not improve consistently.

### Revision Instructions

Do not rely on the current raw-storage/i128-direct revision as a confirmed optimization. Either strengthen the native Soroswap pool path so all three non-Tracy `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` runs show a reproducible soroswap median improvement of at least 1% against `ai-summary/CURRENT_STATE.md`, or reframe/drop the finding as subthreshold. Because the top-line non-Tracy result is ineligible, no diagnostic Tracy run was performed and no `CURRENT_STATE.md` update should be made.

Independent final-review benchmark runs:

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `3c34c878fae3-20260524-103825` | sac, TX=6000, T=8 | 309.5678360 | 328.0830929 | 337.0334207 |
| 1 | `3c34c878fae3-20260524-103825` | soroswap, TX=2000, T=8 | 218.5427345 | 223.6013228 | 234.9788233 |
| 2 | `3c34c878fae3-20260524-104439` | sac, TX=6000, T=8 | 303.9227380 | 322.4589122 | 337.4206389 |
| 2 | `3c34c878fae3-20260524-104439` | soroswap, TX=2000, T=8 | 223.7841585 | 227.5678016 | 230.8826526 |
| 3 | `3c34c878fae3-20260524-105052` | sac, TX=6000, T=8 | 313.2073040 | 331.0408857 | 337.0630958 |
| 3 | `3c34c878fae3-20260524-105052` | soroswap, TX=2000, T=8 | 213.3274505 | 217.8678650 | 219.2235011 |

### Checks Passed So Far

- Source diff remains scoped to `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`.
- No test-file edits are present in the optimization diff.
- Build with `--enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production` completed successfully.
- Full `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed cleanly.
- The optimization targets an in-scope `closeLedger` native Soroswap pool path, but the required top-line soroswap apply-time improvement was not reproduced.

---

## PoC Attempt (Second Revision)

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: gpt-5.5, high
**Builds on**: prior raw-`ScMap` and direct-i128 revisions in the native Soroswap pool path.

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:794-857` — reworked native Soroswap pool dispatch so the accepted getter/swap path moves the already-loaded `ScContractInstance` into `Frame::NativeContract` instead of metered-cloning the full instance storage map a second time.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:982-1039` — added direct raw-`ScAddress` readers for fixed pool keys 0/1/4, allowing native getters and swap validation to avoid generic `ScVal -> Val` address conversion and host-object comparison where the raw schema was already validated.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1230` — tightened the native swap body to use direct raw token addresses for invalid-recipient checks and only materialize `AddressObject`s when invoking SAC transfer/balance calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1379-1456` and `2001-2026` — preserved the prior raw reserve-update/persistence path that writes the updated raw `ScMap` through `store_contract_instance` without materializing `InstanceStorageMap`.

### Demonstration

This revision removes the remaining full-instance clone paid after `retrieve_contract_instance_from_storage` on every accepted native Soroswap pool getter/swap call. Combined with the existing raw-`ScMap` reads/writes and direct-i128 reserve path, the native pool path now avoids generic instance-storage materialization, fixed-key `MeteredOrdMap` lookups/inserts, intermediate i128 host objects for reserve reads, and the extra native-frame clone of the pool's instance storage.

### Test Results

Configured build artifacts were rebuilt with Tracy/next-protocol flags using `make -j $(nproc)`. The full regression suite completed successfully with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`: `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and the p26 Soroban host Rust suite reported `751 passed; 0 failed`.
