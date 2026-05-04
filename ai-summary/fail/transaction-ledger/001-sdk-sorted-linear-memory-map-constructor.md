# H001: SDK-sorted linear-memory map constructor for guest UDT maps

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host VM boundary
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding generic host-map validation and construction work for SDK-generated maps
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When guest code builds a map from a statically generated SDK key list, the host should be able to construct the corresponding `HostMap` in one deterministic pass, validating the fixed key order once and preserving the same duplicate/ordering rejection behavior. It should not always route through the fully generic `map_new_from_linear_memory` path that scans key slices, materializes a temporary symbol vector, zips values, constructs a `MeteredOrdMap`, charges a full scan, and re-compares adjacent keys as if the key order were unknown.

## Mechanism

`Host::map_new_from_linear_memory` is optimized for general untrusted map construction, but soroswap's generated pair/router contract code repeatedly constructs maps whose keys are static SDK-generated symbol lists. The current path reads those symbols into `key_syms`, reads the value `Val`s separately, and then calls `HostMap::from_exact_iter`, which enters `MeteredOrdMap::from_map` and scans/re-compares the resulting vector. A new protocol-gated SDK fast path, such as a `map_new_from_sorted_linear_memory` import or an SDK/host convention for generated UDT maps, could validate static sorted keys while streaming key/value pairs directly into the final map vector, removing a large fraction of guest map-construction work without changing ledger state, event order, or deterministic map ordering.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) using the diagnostic trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Router/pair Wasm calls that marshal SDK contracttype maps through linear memory repeatedly call `map_new_from_linear_memory`; in the seven long `applyLedger` windows this zone occurs 20,233 times.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1856` — `map_new_from_linear_memory` scans key slices, builds `key_syms`, reads values, zips them, and calls `HostMap::from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:213-264` — `metered_vm_scan_slices_in_linear_memory` reads the SDK key-slice table from guest memory one slice at a time.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `MeteredOrdMap::from_map` charges a scan and compares every adjacent key even when the caller already knows the key list is sorted.
- `src/rust/soroban/p26/soroban-env-guest/src/guest.rs:130` — the guest environment exposes `map_new_from_linear_memory` as the map-construction import used by generated guest code.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol 23+ soroswap transactions run this Rust host/VM work under `InvokeHostFunctionOpFrame::doParallelApply`, an `applyLedger` descendant.

## Evidence

- `csvexport-release -e` on the current soroswap trace reports `map_new_from_linear_memory,soroban-env-host/src/vm/dispatch.rs:304` at **132,941,341 ns self-time** over **20,275 calls**, and `new map,soroban-env-host/src/host/metered_map.rs:148` at **331,023,872 ns self-time** over **170,072 calls**.
- Timestamp filtering against the seven long `applyLedger` windows confirms the target work is inside the measured close-ledger path: `map_new_from_linear_memory` totals **252,665,091 ns** over **20,233 calls** (**36.095 ms aggregate per long window; 4.512 ms after T=8 normalization**), while `new map` totals **448,726,196 ns** over **169,483 calls** (**64.104 ms aggregate per long window; 8.013 ms after T=8 normalization**).
- The source has a structural redundancy for SDK-generated maps: the guest already supplies a fixed key-slice table, but the host still materializes all symbols and then asks `MeteredOrdMap::from_map` to prove the resulting vector is sorted by re-running adjacent host comparisons.
- This is distinct from the accepted bulk-build host storage-map success. That work targeted enforcing storage/footprint maps built during host setup; this hypothesis targets guest Wasm linear-memory map construction during contract execution.

## Anti-Evidence

- The generic `map_new_from_linear_memory` API must continue to reject arbitrary unsorted or duplicate keys. A fast path needs either a new import used only by generated SDK code or a protocol-gated ABI convention that still validates the static key list deterministically.
- Budget totals are protocol-visible. If the fast path removes scan/comparison metering rather than only wall-clock work, it must be gated behind a future protocol and covered by updated budget expectations.
- `new map` is a shared `MeteredOrdMap` zone, so a PoC needs narrow counters to isolate the share attributable to guest UDT map construction. The full `new map` critical-path total is an upper bound, not guaranteed savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact sorted-key ABI proposal
**Failed At**: reviewer

### Trace Summary

Generated contracttype structs do provide static sorted `KEYS` arrays and route them through `EnvBase::map_new_from_slices`, which the guest implementation lowers to `map_new_from_linear_memory`. The VM dispatch path then calls `Host::map_new_from_linear_memory` during `InvokeHostFunctionOpFrame::doParallelApply` via the Rust host invocation path, so the inefficiency is on the apply path. However, the host import receives untrusted guest memory and cannot safely skip duplicate/order validation merely because an SDK-generated caller normally supplies sorted keys; preserving map invariants still requires deterministic validation or a substantially different trusted keyset mechanism. Even assuming a correct inline builder removes the temporary `key_syms` vector and one generic `from_exact_iter`/`from_map` pass for the target calls, the measured upper bound is below the objective's Medium severity threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-builtin-sdk-macros/src/derive_type.rs:9-21,71-80` — named struct fields are sorted at macro expansion time and the generated conversion calls `env.map_new_from_slices(&KEYS, &vals)`.
- `src/rust/soroban/p26/soroban-env-guest/src/guest.rs:123-130` — guest `map_new_from_slices` passes the key-slice table pointer, value-array pointer, and length to `map_new_from_linear_memory`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-253` — VM host-function dispatch returns fuel to the host, charges dispatch, marshals arguments, and calls the concrete host method.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1856` — `map_new_from_linear_memory` reads key slices into `key_syms`, reads and translates values, checks value integrity, zips keys/values, and constructs a `HostMap` through `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:213-264` — the key scan reads an untrusted guest table of `(ptr,len)` slices and therefore still needs bounds checks and symbol validation.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,318-346` — `from_exact_iter` collects the final vector, charges clone/scan work, and `from_map` rejects unsorted or duplicate keys by comparing adjacent keys.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-207` and `src/rust/soroban/p26/soroban-env-common/src/symbol.rs:107-151,220-255` — symbol conversion/comparison is real work, but it is also the mechanism that validates the untrusted key bytes and sorted map invariant.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017,1358-1377` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-480` — parallel Soroban apply invokes the Rust host under `doParallelApply`, builds the enforcing host, and calls `Host::invoke_function`.

### Why It Failed

The optimization does not meet the objective's Medium severity floor. The current accepted soroswap baseline is about 272.896 ms median apply time, so Medium requires at least roughly 8.2 ms of reproducible apply-time reduction. The hypothesis's own filtered trace gives only 4.512 ms after T=8 normalization for the entire `map_new_from_linear_memory` zone, and a correct implementation cannot remove the whole zone because guest-memory access, bounds checks, symbol validation, value handle translation, value integrity checks, final map allocation, and host-object insertion remain mandatory. The shared `new map` total is not all attributable to guest UDT map construction, and any safe fast path still needs to reject unsorted/duplicate keys unless it introduces a larger trusted-keyset ABI. Therefore the real recoverable savings are below the Medium threshold accepted by this optimization objective.

### Lesson Learned

Static SDK key arrays are useful evidence for avoiding some temporary allocation and generic construction overhead, but host functions remain adversarial ABI entry points. For this objective, trace totals must be compared against the normalized apply-time floor before promoting guest-boundary micro-optimizations; a target whose whole zone is below 3% cannot produce a Medium finding unless it unlocks additional measured savings outside that zone.
