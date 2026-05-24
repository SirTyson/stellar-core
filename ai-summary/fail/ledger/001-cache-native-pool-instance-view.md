# H001: Cache typed native Soroswap pool instance views across getter and swap calls

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban native Soroswap apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated native pool instance materialization, fixed-key scans, TTL extension checks, and host-object conversions inside `closeLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During one successful Soroswap router transaction, repeated native calls into the same pool contract should read the pool instance entry once, derive the fixed typed fields (`token_0`, `token_1`, `reserve_0`, `reserve_1`, optional `k_last`) once, and reuse that view for protocol-gated native getter and swap emulation until the native swap mutates reserves. The observable behavior should remain identical: every native call must still push the correct contract frame, charge the protocol-gated budget profile, extend the same instance/code TTLs when the Wasm path would, emit the same swap event, and write the same updated reserve values.

## Mechanism

`Host::call_contract_fn` currently retrieves and `metered_clone`s the full `ScContractInstance` before every native Soroswap getter/swap decision, and the native helpers then re-scan the instance `ScMap` for fixed u32 keys and clone the instance again into the frame. A per-host, per-contract typed `SoroswapPoolInstanceView` cache populated from `frame.rs:790-817` and consumed by `try_call_native_soroswap_pool_getter` / `try_call_native_soroswap_pool_swap` would amortize these repeated reads across the router's getter+swap sequence without changing ledger output; the cache can be invalidated or updated in `call_native_soroswap_pool_swap` when reserves are written.

## Trigger

Run the current soroswap apply-load scenario (`TX=2000, T=8`) on the accepted native Soroswap branch. Each router swap calls the same pair contract several times for `token_0`, `token_1`, `get_reserves`, and `swap`; every call re-enters `Host::call_contract_fn`, loads the same pool instance, and scans the same fixed-key instance storage before the native path takes over.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `Host::call_contract_fn` retrieves the contract instance and eagerly builds `args_vec` before checking native Soroswap fast paths.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872` — `try_call_native_soroswap_pool_getter` validates the same pool instance layout and clones the instance into a native frame for each getter.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:893-930` — fixed pool-storage probes perform repeated linear `ScMap` scans over u32 keys.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — `try_call_native_soroswap_pool_swap` repeats layout validation and instance cloning before the native swap.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1266` — `call_native_soroswap_pool_swap` re-reads typed fields and mutates reserves.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. Timeline filtering against `applyLedger` windows showed the relevant host/storage work occurs inside apply: `storage get` totals 672.085 ms over 321,802 in-apply events, `ScVal to Val` totals 1,144.488 ms over 800,217 in-apply events, `new map` totals 461.915 ms over 181,114 in-apply events, `map lookup indexed` totals 585.969 ms over 839,562 in-apply events, and `extend_current_contract_instance_and_code_ttl` totals 455.825 ms over 23,595 in-apply events. The native Soroswap source structurally repeats pool-instance loading, fixed-key scans, and TTL-extension setup for multiple calls to the same pair contract within one router transaction.

Prior failures rejected moving only one loaded instance into the frame as too narrow, and rejected native pool raw-storage ideas when the native path was absent. The current checkout now contains `try_call_native_soroswap_pool_getter`, `try_call_native_soroswap_pool_swap`, and `call_native_soroswap_pool_swap`; this hypothesis targets a broader per-host typed-view cache across multiple native calls, not merely ownership transfer of one clone.

## Anti-Evidence

The pool instance `ScMap` is small, so a cache that only removes u32 linear scans will be below threshold. The implementation must remove or amortize the full repeated instance materialization path and preserve metering; if the cache still clones the instance into every frame and performs normal `with_instance_storage` lookups, it will collapse to the previously rejected low-impact ownership/insert optimizations. The cache also needs a conservative fallback for noncanonical pool layout, protocol p26, missing instance storage, or any call shape not exactly matching the native Soroswap fast path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The repeated work exists on the native Soroswap apply path: `closeLedger` reaches Soroban parallel apply, each worker calls `InvokeHostFunctionOpFrame::doParallelApply`, Rust constructs one `Host` per transaction, and repeated router calls enter `Host::call_contract_fn` for the same pool contract. The native getter/swap code clones the loaded instance into a `NativeContract` frame, scans the small `ScMap` for fixed keys, lazily materializes instance storage through `InstanceStorageMap::from_instance_xdr` when getters read fields, and calls TTL extension helpers that re-load the contract instance to find the code hash. However, the maximum removable portion is far below this objective's 3% Medium floor after normalizing the cited aggregate Tracy totals by the 236 measured soroswap benchmark samples in the diagnostic run and by the 8 configured parallel clusters.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2785-3030` — `applyTransactions` dispatches the soroswap phase to `applyParallelPhase`, which constructs apply clusters and calls `applySorobanStages` inside `closeLedger`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2511` — each worker in `applyThread` calls `parallelApply` for every transaction in its cluster, so Rust host work is aggregate worker time and must be normalized by cluster parallelism when estimating top-line apply-time impact.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the C++ apply helper bridges each invoke-host-function transaction into `rust_bridge::invoke_host_function` with per-transaction encoded footprint entries and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:983-1017` and `1328-1378` — successful Soroban apply performs footprint loading, host invocation, storage-change recording, event collection, and fee/refund finalization.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` — `invoke_host_function` builds enforcing storage, creates a per-transaction `Host`, invokes the function, finishes the host, and extracts ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1721-1755` — top-level `InvokeContract` dispatch calls `call_n_internal`, which then calls `call_contract_fn` for router/pool/SAC contract calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` builds the instance ledger key, retrieves and clones the `ScContractInstance`, copies args, then tries native Soroswap getter/swap dispatch before falling back to VM/SAC frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-930` — native getter dispatch validates the Soroswap pool hash, checks getter symbols, linearly scans the instance `ScMap` for fixed keys, clones the instance into the native frame, and then calls the native getter.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:931-1011` — native getters extend instance/code TTLs and read fields through `with_instance_storage`, which lazily materializes a `MeteredOrdMap` from the frame instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — native swap repeats layout validation, clones the instance into a frame, reads reserves/tokens through instance storage, invokes SAC transfer/balance helpers, mutates reserve keys 2/3, and emits the swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:32-72` and `112-120` — instance storage is lazily initialized per frame, and `retrieve_contract_instance_from_storage` clones the contract instance from the ledger entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:287-321` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-688` — TTL extension must still read live-until state and may update the storage map; `extend_contract_code_ttl_from_contract_id` currently re-retrieves the instance just to identify the Wasm code hash.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:434-595` and `1863-1886` — `with_frame` supplies rollback and persistence semantics; any cache update for mutated reserves would need to occur only after successful frame persistence or be rollback-aware.
- `ai-summary/fail/ledger/summary.md:75-80` — prior related investigations rejected absent native raw-storage paths, one-clone native-frame ownership as sub-1%, and pair-storage insertion fusion after a measured 0.56% benchmark improvement.
- `ai-summary/CURRENT_STATE.md:47-57` and `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/results.csv` — authoritative baseline is ~218 ms median soroswap apply time; the diagnostic Tracy run's model median is ~213.6 ms.

### Why It Failed

The optimization target is real but too small for this objective. The hypothesis's own in-apply Tracy totals sum to about 3.32 s of aggregate worker time across broad zones (`storage get`, `ScVal to Val`, `new map`, `map lookup indexed`, and TTL extension), but the diagnostic log contains 236 measured `Model tx benchmark` samples for the soroswap run. Even pretending the cache could eliminate every event in those broad zones, the aggregate ceiling is about 14 ms per sample before parallel normalization; divided by the 8 configured clusters it is roughly 1.8 ms of wall-clock apply time, under 1% of the ~213-218 ms soroswap median. The actual removable subset is smaller: first contact with each pool still needs a validated instance load, getters still need correct frame/TTL behavior, swap still needs mutable instance storage for reserve writes and persistence, and prior targeted PoCs around the same native-pool mechanics measured sub-1% to 0.56% improvements.

Because the optimize-soroswap reviewer objective accepts only Medium-or-High hypotheses, this is rejected as below objective severity threshold rather than promoted as a Low optimization.

### Lesson Learned

For native Soroswap host optimizations, broad Tracy zones must be divided by both the number of benchmark samples and the configured cluster parallelism before projecting top-line apply-time savings. A cache that only amortizes small per-call instance clones, fixed-key scans, or per-frame instance-storage materialization is not enough; future viable work needs to remove a larger semantic phase or demonstrate a wall-clock A/B effect above 3%.
