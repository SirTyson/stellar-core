# H002: Cache Repeated Linear-Memory Map Shapes

**Date**: 2026-05-20
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing repeated SDK map import and HostMap construction work inside `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`map_new_from_linear_memory(keys_pos, vals_pos, len)` should construct the same deterministic `MapObject` as today: keys must be valid symbols, key/value slices must be read in the same phase order, duplicate or unsorted keys must raise the same class of host error, and the resulting map ordering must be stable across nodes. On repeated successful imports of the same static SDK map key shape, the host should be able to reuse a validated key-shape descriptor while still reading the current value slice and producing the same map contents.

## Mechanism

The current implementation in `soroban-env-host/src/host.rs:1803-1857` scans key slices from Wasm linear memory, converts every key to `Symbol`, reads and validates every value, then calls `HostMap::from_exact_iter`, which allocates a fresh vector and rechecks sorted/unique key order. Soroswap-style SDK contracts repeatedly construct maps with identical static symbol-key layouts but changing values, so the host repeats symbol validation, sortedness scans, and comparisons for the same map shapes thousands of times. A per-VM or per-ParsedModule cache keyed by the exact ordered key byte slices could reuse the validated `Symbol`/`Val` key vector and sortedness result, leaving only value import and map object allocation on cache hits.

## Trigger

Run the soroswap apply-load benchmark at the current baseline (`TX=2000, T=8`). The triggering condition is repeated Soroban SDK UDT/map construction from linear memory where the key slice vector is byte-identical across calls within a contract module and only the value slice changes.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1857` — `map_new_from_linear_memory` repeatedly scans key slices, converts symbols, imports values, and builds a `HostMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:196-245` — linear-memory slice scanning used to read key byte slices and establish a safe cache key.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `HostMap::from_exact_iter` allocation path used after every linear-memory map import.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:120-137` — `from_map` sorted/unique scan that can be skipped on an exact validated-shape cache hit behind a protocol gate.

## Evidence

In the current soroswap trace, `map_new_from_linear_memory` is fully apply-contained and accounts for 132,941,341 ns self-time across 20,275 calls. Its construction callees are also hot and apply-contained: `new map` reports 331,023,872 ns self-time across 170,072 calls, and `Compare<HostObject>` reports 165,773,848 ns self-time across 413,544 calls. The source shows the key-symbol scan and sortedness validation are independent of the value slice for a fixed SDK map shape, which makes them candidates for reuse without changing the resulting map order.

## Anti-Evidence

The cache must not change observable error phase ordering: key slices still need to be read before values, and a cache hit must only occur after proving the current key byte slices exactly match a previously validated shape. The cache also has to be deterministic and bounded, likely scoped to the current `Vm` or immutable `ParsedModule`, and must not exceed `NUM_CLUSTERS` parallelism or introduce cross-thread mutation races. Existing `new map` and comparison self-time includes other HostMap construction paths, so a PoC needs instrumentation that isolates `map_new_from_linear_memory` cache-hit savings from unrelated map work and from mandatory value import / map-object allocation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

Guest SDK helpers pass static key-slice arrays and current value arrays to `map_new_from_linear_memory` through the generated VM host-function dispatch. The host function first scans every key slice from Wasm memory and converts it to a `Symbol`, then reads every value `Val`, translates relative object handles, checks value integrity, and finally builds a sorted `HostMap` via `from_exact_iter`/`from_map`. A key-shape cache could avoid repeated symbol validation and sortedness checks on successful repeated shapes, but it cannot avoid proving the current key bytes match, importing/checking values, allocating the output map vector/object, or preserving the existing key-before-value error phase ordering.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-common/env.json:1033-1050` — declares `map_new_from_linear_memory` as the VM-visible host function for map construction from linear-memory key/value arrays.
- `src/rust/soroban/p26/soroban-env-guest/src/guest.rs:123-130` — trusted guest-side `map_new_from_slices` passes raw key-slice and value-array pointers to `map_new_from_linear_memory`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-480` — the apply-contained Soroban invocation constructs the host, installs the module cache, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1148` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — `InvokeContract` enters a `HostFunction` frame, instantiates a `Vm`, pushes a `ContractVM` frame with a per-frame relative-object table, and invokes the exported contract function.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:19-39,101-118` — generated dispatch converts object-bearing arguments/results between relative and absolute handles around host-function calls.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1803-1857` — `map_new_from_linear_memory` scans key slices, imports values, checks value integrity, and calls `HostMap::from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/mem_helper.rs:213-265` — `metered_vm_scan_slices_in_linear_memory` reads each `(ptr,len)` pair and follows it to the current key bytes; this scan is still required to establish an exact cache hit safely.
- `src/rust/soroban/p26/soroban-env-common/src/symbol.rs:107-121,220-255` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:997-1015` — key conversion validates small symbols directly and falls back to host-object allocation/validation for larger symbols.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_exact_iter` collects a fresh vector, charges clone/allocation work, and delegates to `from_map` for sorted/unique adjacent-key validation.
- `ai-summary/fail/soroban-env/summary.md:29-31` and `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:44-53` — prior records are related to map/storage mechanics but not duplicates; they also show that broad map/comparison Tracy aggregates overstate Medium-impact projections.

### Why It Failed

The optimization target exists, but the claimed Medium apply-time impact does not survive the code trace. A correct cache hit must still read the current linear-memory slice descriptors and key bytes to prove an exact shape match, must still import and integrity-check all values after the key phase, and must still allocate/populate a fresh `HostMap`/`MapObject` for the current values. The cited `new map` and `Compare<HostObject>` totals are broad aggregates across many `MeteredOrdMap` call sites, not work uniquely under `map_new_from_linear_memory`; the relevant removable subset is only repeated symbol conversion plus adjacent-key sortedness validation for the 20,275 map imports.

The hypothesis's strongest specific number is 132,941,341 ns of `map_new_from_linear_memory` self-time, and even that whole function includes mandatory key-byte access, value import setup, metering, and control-flow overhead that the cache cannot remove. The accepted current soroswap baseline is about 305 ms median apply time, and prior non-Tracy results show that much larger Soroban host aggregate zones can translate to only Low single-digit improvements. After subtracting mandatory work and unrelated aggregate map/comparison zones, this target is below the objective's Medium severity threshold, so it is not accepted for this optimize-soroswap review stage.

### Lesson Learned

For linear-memory map-construction hypotheses, separate "shape-dependent" work from mandatory current-memory proof, value import, output allocation, and protocol-visible error ordering before projecting benchmark impact. Broad `new map` or comparator Tracy totals are only upper bounds unless instrumentation isolates the exact `map_new_from_linear_memory` subset and the repeated-shape cache-hit savings.
