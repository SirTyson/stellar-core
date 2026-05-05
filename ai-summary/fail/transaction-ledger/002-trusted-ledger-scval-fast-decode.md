# H002: Trusted ledger-value `ScVal` to `Val` fast decode for contract-data reads

**Date**: 2026-05-05
**Subsystem**: transaction-ledger / Soroban host conversion
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding adversarial `ScVal` validation work for consensus-originated contract-data values
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `get_contract_data` reads a value from ledger state that was previously produced by the Soroban host, the host should reconstruct the equivalent runtime `Val` / host-object graph deterministically and charge the protocol-defined read/conversion cost. It should not always route ledger-originated values through the same fully adversarial `ScVal` conversion path used for transaction input, rechecking representability, depth, map ordering, and object validity as if the value came from untrusted external XDR.

## Mechanism

`Host::get_contract_data` calls `to_valid_host_val(&e.val)` for every persistent/temporary contract-data value. `to_valid_host_val` delegates to generic `to_host_val`, which recursively converts `ScVal::Vec` and `ScVal::Map`, allocates host objects, and calls `HostMap::from_map_with_host` after validating keys and values. For ledger-originated contract data in enforcing mode, these values were accepted into ledger state by prior host execution; a protocol-gated trusted decode path could keep corruption checks at ledger-ingest or debug boundaries while using a leaner builder for hot apply reads, removing repeated validation and comparison work without changing ledger effects or object ordering.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) using `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. SAC balance reads and pair/router contract-data reads call `get_contract_data`, which converts ledger-stored `ScVal` values back into host values before contract logic can inspect them.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2249` — `get_contract_data` reads a `LedgerEntryData::ContractData` value and calls `to_valid_host_val(&e.val)`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460` — `to_host_val` / `to_valid_host_val` apply the generic `ScVal` to `Val` conversion path.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-565` — `to_host_obj` recursively converts `ScVal::Vec` / `ScVal::Map`, builds intermediate vectors, and constructs `HostMap` through validation-heavy generic builders.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:443-457` — converted compound and large scalar values are inserted into the host object table.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-303` — storage reads provide the ledger-originated entry values that could use the trusted decode path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999,1358-1377` — host storage reads occur during invoke-host-function apply / parallel apply under `applyLedger`.

## Evidence

- `csvexport-release -e` on the current soroswap trace reports `ScVal to Val,soroban-env-host/src/host/conversion.rs:436` at **429,988,065 ns** self-time over **691,521** calls.
- Related object-construction categories are also significant: `add host object,soroban-env-host/src/host_object.rs:450` is **270,971,092 ns** over **935,719** calls, and `new map,soroban-env-host/src/host/metered_map.rs:148` is **331,023,872 ns** over **170,072** calls. The full removable subset is smaller than these broad zones, but the combined conversion/object-building ceiling is large enough to justify a Medium hypothesis if ledger-value reads account for a substantial share.
- Timestamp filtering confirms the conversion work sits inside the measured apply path: the 16 long `applyLedger` windows contain **690,145** `ScVal to Val` events totaling **994,813,298 ns** of inclusive time, plus **933,305** `add host object` events.
- The target is distinct from the accepted typed SAC balance fast path. That success specialized SAC `BalanceValue` storage layout; this hypothesis targets generic ledger-originated `ContractData` values still returned through `Host::get_contract_data`, including pair/router state and non-balance SAC values.

## Anti-Evidence

- Ledger corruption and catchup safety matter. A fast path must not silently accept malformed historical state; it needs a clear trust boundary, such as validation when ledger entries enter `InMemorySorobanState` / BucketList state, debug assertions, or fallback validation on unexpected shapes.
- Budget metering for conversion is protocol-visible. Skipping validation or changing charge granularity requires a protocol gate and updated budget expectations, while p26 must preserve the current recursive conversion charges.
- The `ScVal to Val`, `add host object`, and `new map` Tracy zones are broad. A reviewer should instrument `to_valid_host_val` callers and isolate ledger contract-data reads before assuming this removes enough of the category to clear the ~8.2 ms Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The hot path is `InvokeHostFunctionOpFrame::doApply` / `doParallelApply` collecting footprint entries into CxxBufs, crossing the Rust bridge into `invoke_host_function`, building enforcing `Storage`, then executing contract host calls that route persistent/temporary `get_contract_data` through `Storage::get` and `Host::to_valid_host_val`. The claimed generic conversion work exists: `to_valid_host_val` is a thin wrapper over `to_host_val`, and map/vector values recurse through `to_host_obj`, allocate host objects, and validate map ordering through `HostMap::from_map_with_host`. However, the cited Tracy time is aggregate worker CPU across an 8-cluster parallel apply shape; even deleting the entire `ScVal to Val` inclusive zone would save at most about `994.8ms / 16 ledgers / 8 clusters = 7.8ms` per ledger, below the 3% Medium floor of roughly 8.2ms on the 272ms soroswap baseline. A trusted decode would remove only part of that zone, because object allocation, recursive construction, required metering, and host-object insertion remain.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:537-584` — `addFootprint` serializes footprint ledger entries and calls `rust_bridge::invoke_host_function` with the ledger-entry and TTL buffers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-999` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — sequential and parallel invoke-host-function apply both execute this path under `applyLedger`.
- `src/rust/src/soroban_invoke.rs:7-38` — the C++ bridge dispatches to the protocol-specific Soroban host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523` — enforcing invocation decodes resources, footprint, ledger entries, and TTLs, constructs `Storage::with_enforcing_footprint_and_map`, and then invokes the host function.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1151` — storage-map construction validates XDR shape, TTL presence/liveness, and footprint membership, but does not validate `ContractData.val` representability, symbol bytes, address variants, or ScMap sortedness.
- `src/transactions/TransactionUtils.cpp:1973-2001` — `validateContractLedgerEntry` checks only contract-code and contract-data byte-size limits, not the internal `ScVal` validity needed by a trusted decoder.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2255-2267` — `get_contract_data` loads the ledger entry and converts `ContractData.val` with `to_valid_host_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460` — `to_valid_host_val` delegates to generic `to_host_val`, preserving the generic conversion cost and only remapping non-budget errors to internal errors.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:521-599` and `src/rust/soroban/p26/soroban-env-common/src/val.rs:596-652` — generic `ScVal` to `Val` conversion checks representability at each recursive level and classifies object-valued `ScVal` variants.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:543-565` — vec/map conversion recursively converts elements, builds intermediate `Vec<Val>` / `Vec<(Val, Val)>`, and inserts a new host object.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-137,394-410` — `HostMap::from_map_with_host` delegates to `from_map`, which scans and compares adjacent keys to enforce sorted unique map invariants.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:443-457` — every large scalar, vec, and map decode still requires `add_host_object` allocation/insertion even with a trusted validation path.

### Why It Failed

The inefficiency exists, but the objective requires Medium-or-better projected apply-time improvement. The hypothesis's own strongest apply-window measurement, `994,813,298ns` inclusive `ScVal to Val` time across 16 apply windows, is aggregate parallel-worker time. For the target `T=8` soroswap shape, the critical-path ceiling is about 7.8ms per ledger before subtracting non-removable work; this is below the ~8.2ms Medium floor, and a trusted decoder could only remove validation/comparison overhead, not recursive object construction, host-object allocation, XDR ingress, or protocol-visible conversion metering. Correctness also prevents simply skipping validation: current ingress checks do not validate `ContractData.val` ScVal invariants, so any safe design must either keep validation on read, add an ingress validation pass, or protocol-gate the metering/validation change, further reducing or complicating the projected win.

### Lesson Learned

For Soroban worker-thread hotspots, Tracy self/inclusive totals must be normalized by the configured cluster parallelism before comparing to the top-line apply-time threshold. Broad conversion zones are especially misleading: they include mandatory object construction and budget-visible metering, while the proposed optimization targets only a validation subset.
