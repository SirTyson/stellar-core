# H002: Cache Enforcing Storage Val Conversions Across Repeated Reads

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding repeated `ScVal`/`Val` conversion and host-object allocation for the same contract-data entries within one invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated reads of the same contract-data key during one enforcing Soroban invocation should return values that are semantically identical to today's values, preserve storage footprint enforcement, keep writes/deletes visible to later reads in the same invocation, and produce identical final ledger effects. The host should not repeatedly rebuild the same host-object graph from an unchanged `ContractDataEntry.val` or repeatedly rebuild the same ledger key from the same storage key `Val` when a per-invocation cache can prove the source value has not changed.

## Mechanism

Every persistent or temporary storage access in `Host::{has_contract_data,get_contract_data,put_contract_data,extend_contract_data_ttl}` converts the guest key `Val` to a `ScVal` via `storage_key_from_val`, constructs a fresh `Rc<LedgerKey>`, and then searches enforcing `Storage`. Every successful `get_contract_data` then converts the stored `ScVal` back to a host `Val` via `to_valid_host_val`, recursively allocating host objects for maps, vectors, addresses, and big integers. Soroswap repeatedly touches the same SAC, pair, and router keys inside one swap; a cache scoped to the `Host`/`Storage` invocation, invalidated on `put`/`del` for that key, could reuse decoded storage values and/or storage keys while preserving deterministic ledger output and keeping parallelism unchanged.

## Trigger

Run the current soroswap Tracy benchmark from `ai-summary/CURRENT_STATE.md` and timestamp-filter conversion zones to `applyLedger`. The current trace shows apply-window overlap of 721.780 ms for `ScVal to Val` at `soroban-env-host/src/host/conversion.rs:436`, 231.230 ms for `Val to ScVal` at `conversion.rs:411`, 2,372.465 ms total / 1,225.983 ms self for `visit host object` at `host_object.rs:468`, and 152.544 ms self for `add host object` at `host_object.rs:450`; these events occur under `Host::invoke_function` during `InvokeHostFunctionOpFrame::doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2244` — `has_contract_data` and `get_contract_data` convert each guest key to a ledger key, then convert returned `ContractDataEntry.val` back to a host `Val`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2292-2317` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2389-2416` — TTL extension paths rebuild storage ledger keys from guest key values.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — writes use the same key, perform `has` and sometimes `get`, then update the storage entry; this is a natural invalidation point for cached decoded values.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-443` — `from_host_val` / `from_host_val_for_storage` / `to_host_val` wrap the recursive conversion zones visible in Tracy.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-565` — `to_host_obj` recursively allocates host vectors/maps for `ScVal` objects.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-357` — enforcing storage get/put helpers are the right place to associate cached decoded values with storage-map entries and invalidate them on mutation.

## Evidence

The trace confirms the conversion work is in the measured apply subtree rather than TX-set construction: the timestamp-filtered soroswap run has 480,076 `ScVal to Val` events and 386,259 `Val to ScVal` events overlapping `applyLedger`, and the hottest apply window contains 320.219 ms aggregate / 50.328 ms hottest-thread `ScVal to Val` overlap. The source confirms the repeated conversion boundary: guest-visible storage APIs always enter through `Val`, while the enforcing storage map stores XDR-shaped `LedgerEntry`/`ScVal` values. A per-invocation cache is deterministic because it is local to a single `Host`, does not share data across transactions or threads, and can be invalidated synchronously when the same storage entry is updated or deleted.

## Anti-Evidence

Budget accounting is the main correctness risk. Current conversions charge for object visits, shallow copies, heap allocation, and map/vector construction; a cache that simply returns a previous host object would reduce consensus-visible resource use unless this is accepted as a protocol-versioned metering change or compatibility charges are added. Host object handles must also remain unobservable: a PoC should verify contracts cannot distinguish receiving the same cached immutable object from receiving an equal freshly allocated object, and should avoid caching mutable frame-relative handles. If soroswap's repeated keys are mostly equal-by-value but not the same host `Val` handle, a handle-keyed cache may underperform; a value-keyed cache would need to avoid spending more comparison work than it saves.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no duplicate found in the transactions fail/success records; cross-subsystem fail/success directories were absent in this workspace
**Failed At**: reviewer

### Trace Summary

The repeated conversion path is real: parallel Soroban apply enters C++ `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, constructs an enforcing `Storage`, and then guest storage host functions convert `Val` keys into `Rc<LedgerKey>` and successful ledger reads back into host `Val` objects. However, those conversions are also the current metering path: object visits, vector/map allocation, shallow copies, and host-object allocation all charge the per-transaction Soroban budget that is returned to C++ and used for resource-limit behavior. A cache that simply reuses decoded keys or values would therefore change protocol-visible `cpu_insns`/`mem_bytes`; an exact-compatibility cache would need to replay much of the same recursive traversal and budget charge sequence, leaving only physical allocation avoidance and making the claimed Medium impact unproven. The proposed Host/Storage-scoped cache also omits rollback integration: frame rollback restores `Storage.map`, events, and auth state, but would not automatically restore an independent conversion cache.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584,603-629,1358-1377` — parallel invoke calls the Rust bridge and uses returned `cpu_insns`/`mem_bytes` to classify resource-limit failures.
- `src/rust/src/soroban_proto_any.rs:412-448,458-466,478-506` — the bridge constructs the enforcing budget, invokes the protocol host, reads consumed CPU/memory from the budget, and returns those values in `InvokeHostFunctionOutput`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452,478-507` — enforcing invocation decodes footprint/storage inputs, builds `Storage::with_enforcing_footprint_and_map`, runs `Host::invoke_function`, then extracts ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2243,2268-2317,2389-2416` — persistent/temporary storage APIs rebuild `LedgerKey`s from guest `Val`s and `get_contract_data` converts `ContractDataEntry.val` to a host `Val` on each read.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-165,407-443,543-565` — `storage_key_from_val` funnels through metered `Val` to `ScVal` conversion, while `to_host_val` recursively builds host vectors/maps and host objects from `ScVal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — writes use the same converted key, perform `has`/`get_with_live_until_ledger`, and mutate the stored `ContractDataEntry.val`, so they are invalidation points but also duplicate the same metered conversions.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-357,401-428,431-551` — enforcing storage still performs footprint checks and map lookups on every get/has/put/TTL extension; caching decoded values cannot bypass this without changing enforcement.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:412-438,446-475` — returning objects to Wasm creates fresh relative handles, but `add_host_object` and `visit_obj_untyped` also charge `MemAlloc`/`VisitObject` budget costs that a cache would skip unless replayed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:77-94,117-132` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:365-371` — heap allocation, bulk initialization, object visits, and serialization/copy-like work have non-zero budget costs; these charges are part of the observable Soroban resource model.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-225` — contract-frame rollback restores `Storage.map`, events, and authorization state only; an independent conversion cache would need explicit rollback semantics or storage-map embedding to avoid stale entries after failed nested calls.

### Why It Failed

The inefficiency exists and is on the apply path, but the proposed current-protocol cache is not correctness-preserving as stated. In p26, the conversion work is not merely physical decoding overhead: it is also where the host charges `VisitObject`, `MemAlloc`, `MemCpy`, map/vector construction, and related recursive conversion costs. Reusing a cached `Val` or `LedgerKey` without replaying those charges can change whether near-limit transactions trap with `INVOKE_HOST_FUNCTION_RESOURCE_LIMIT_EXCEEDED`; replaying the charges requires re-traversing the same key/value graphs and would retain much of the cost that dominates the cited zones. After exact metering and rollback-safe cache placement are accounted for, the remaining safely removable work is mostly physical object allocation/reconstruction, and the review found no source-backed basis for the required 3-10% soroswap apply-time improvement.

### Lesson Learned

Soroban storage conversion hotspots must be separated into protocol-visible metering work and removable physical allocation work before promotion. A cache that is local and deterministic is still not sufficient if it changes budget consumption or fails to roll back with nested contract frames; future candidates should either be explicitly protocol-gated with a recalibrated cost model or prove exact compatibility charges plus rollback-safe cache state still clear the Medium threshold.
