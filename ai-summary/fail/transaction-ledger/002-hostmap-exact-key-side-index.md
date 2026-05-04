# H002: Lazy exact-key side index for hot immutable HostMap lookups

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host objects
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing repeated generic `HostMap` binary searches with deterministic exact-key indexed lookups
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Immutable host maps that are repeatedly queried by exact shallow keys during Soroban execution should be able to locate entries without re-running a metered binary search and recursive host-object comparison every time. Map ordering, duplicate rejection, returned values, and iteration order should remain unchanged; the optimization should only add a private lookup accelerator for maps whose keys can be indexed deterministically.

## Mechanism

`HostMap` is `MeteredOrdMap<Val, Val, Host>`, and `Host::map_get` calls `hm.get(&k, self)`, which reaches `MeteredOrdMap::find` and performs `charge_binsearch` plus `binary_search_by_pre_rust_182` using `Host` comparisons. In the current soroswap apply windows, generic `map lookup` totals **1,121,943,788 ns** of worker time (**20.035 ms T=8-normalized**), with comparison-adjacent zones `obj_cmp` at **7.977 ms T=8-normalized** and `Compare<HostObject>` at **4.008 ms T=8-normalized**. A lazy side index keyed by exact `Val` payloads for shallow, hashable keys (for example symbols, integers, addresses/bytes already represented as host-object handles) could preserve the canonical sorted vector for ordering while avoiding repeated binary-search comparison work on hot guest maps.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect the long `applyLedger` windows in `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Router/pair Wasm execution repeatedly calls map operations through the host-function dispatch path; `map lookup` fires **1,278,276** times inside the seven long apply windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:19-25` — `HostMap` is currently just `MeteredOrdMap<Val, Val, Host>` stored as a host object, with no side lookup structure.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — map construction validates sorted unique keys and stores the canonical ordered vector that must remain the source of iteration order.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — `find` charges and executes a binary search for every lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1708-1724` — `map_get` visits the immutable `HostMap` and calls `hm.get(&k, self)` for each guest lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:51` and `src/rust/soroban/p26/soroban-env-common/src/vmcaller_env.rs:270` — host-object comparisons show up as adjacent hot zones amplified by map lookup.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — parallel apply waits for Soroban workers, so worker-local map lookup reductions are on the `applyLedger` critical path and do not alter execution order.

## Evidence

- Timestamp filtering to `applyLedger` windows longer than 100 ms gives `map lookup` at **1,121,943,788 ns / 1,278,276 calls**, or **160.278 ms aggregate per long window** and **20.035 ms after T=8 normalization**. Even a 40-50% reduction in the lookup/comparison subset would meet the current Medium floor of roughly **8.19 ms** on the 272.896 ms baseline.
- The adjacent comparison zones are also in-scope: `obj_cmp` totals **446,707,529 ns / 486,852 calls** (**7.977 ms T=8-normalized**) and `Compare<HostObject>` totals **224,438,347 ns / 412,535 calls** (**4.008 ms T=8-normalized**), indicating that generic comparison is a meaningful share of map lookup work.
- `MeteredOrdMap` already centralizes sorted-map construction and lookup, so a side index can be implemented below the public host API while preserving all existing callers and deterministic map order.
- This is not the rejected enforcing-storage side-index family. The accepted/rejected storage-map work targeted `StorageMap` and footprint lookups; this hypothesis targets generic guest-visible `HostMap` objects reached through `Host::map_get`.

## Anti-Evidence

- Budget accounting for map lookup is protocol-visible. p26 must continue to charge the existing binary-search model unless the side-index lookup is gated behind a future protocol or reproduces the old charge schedule while still saving wall-clock comparison work.
- A side index on every map may add memory and cache pressure, repeating the failure mode seen with global pre-serialized `InMemorySorobanState` caching. The PoC should build the index lazily only for maps that cross a size or repeated-lookup threshold, and should measure resident memory/cache effects.
- The `map lookup` zone includes all `MeteredOrdMap` users, not only guest `HostMap::map_get`. Review should isolate the share attributable to `HostObject::Map` lookups before assuming the full 20.035 ms T=8-normalized total is removable.
- Keys involving deep host-object comparison may not have a cheap stable hash/equality path. The first implementation should restrict indexing to exact shallow keys or store vector positions keyed by canonical `Val` payload plus object identity where that is semantically safe.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact immutable `HostMap` exact-key side-index proposal in `fail/transaction-ledger` or `success/transaction-ledger`
**Failed At**: reviewer

### Trace Summary

The execution path is real: Wasm host-function dispatch crosses into `Host::map_get` or `Host::map_has`, visits the immutable `HostMap`, and calls `MeteredOrdMap::{get,contains_key}`, which always enters `find`, charges the binary-search access model, and runs the pre-1.82 binary search with `Host`-provided `Val` comparison. This worker-local Soroban host work is under `LedgerManagerImpl::applySorobanStageClustersInParallel`, whose futures are synchronously joined by `applyLedger`. However, the proposed exact-`Val` side index is not equivalent to `HostMap` key equality for object keys, and the fully removable subset of the generic `map lookup` timing is too small and too poorly isolated to meet the objective's Medium floor.

### Code Paths Examined

- `ai-summary/CURRENT_STATE.md:41-64` — the accepted current soroswap baseline averages 272.895607 ms, so the objective's 3% Medium floor is about 8.19 ms per ledger.
- `ai-summary/fail/transaction-ledger/summary.md:41-42,105,115` — related object-comparison and storage-map side-index families were already found sub-threshold or superseded; this exact immutable `HostMap` side-index mechanism is distinct but must still overcome the same worker-time normalization and metering constraints.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:19-25` — `HostMap` is just a `MeteredOrdMap<Val, Val, Host>` variant in the immutable host object table.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-254` — Wasm host-function dispatch translates relative object handles, charges dispatch, and calls concrete host methods such as `map_get`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1697-1724,1748-1755` — `map_put`, `map_get`, and `map_has` all visit the `HostMap`; lookups call `hm.get` or `hm.contains_key`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,168-194,227-242,294-300` — `from_map` preserves sorted unique canonical storage, while `find` charges `charge_binsearch` and runs binary search for each `get` and `contains_key`.
- `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — `Compare<Val>` fast-paths identical payloads, but delegates any object-involving comparison to `Env::obj_cmp`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1224-1281` — `obj_cmp` implements semantic object comparison, including object-vs-object recursive comparison and object-vs-small paired comparisons.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-95` — `Compare<HostObject>` recursively compares host object contents under the budget depth limiter, so object-key equality is content-based, not handle-payload identity.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-528` — `visit_obj_untyped` and `visit_obj` perform object table lookup and type validation around host-object access; these costs surround `map_get` but are not eliminated by an inner map side index.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — parallel Soroban worker futures are joined synchronously, so only critical worker reductions after T=8 normalization count toward apply-time improvement.

### Why It Failed

The hypothesis overstates both correctness and impact. A side index keyed by exact `Val` payload is only semantically complete for small values and for object keys queried with the exact same host-object handle; `HostMap` equality for object keys is defined by `obj_cmp` and `Compare<HostObject>`, so two different object handles with equal bytes, symbols, addresses, vectors, or maps must still match. A correct exact-key accelerator would therefore need to fall back to the existing binary search on exact-payload misses, which means the cited `obj_cmp` and `Compare<HostObject>` totals are not broadly removable unless the design adds a canonical content index; such a content index would itself need recursive host-object traversal, depth limiting, and protocol-visible metering comparable to the comparison path it is trying to avoid.

The performance ceiling is also too tight for this objective. The hypothesis's own `map lookup` number is 20.035 ms after T=8 normalization, and Medium requires about 8.19 ms, so more than 40% of the entire generic `MeteredOrdMap` lookup span would have to disappear. That span includes non-`HostMap::map_get` users, mandatory p26 `charge_binsearch`/comparison budget accounting unless protocol-gated, binary-search result handling, and any new side-index hashing/build/cache cost. Preserving p26 metering leaves only small control-flow/comparison savings, while protocol-gating the metering still requires isolating the `HostMap` exact-small-key hit share; the current evidence does not show that removable subset clearing the 3% floor. Under the optimize-soroswap rule that Low-tier findings are rejected, this is not viable.

### Lesson Learned

For guest-visible `HostMap` lookup optimizations, first isolate `map_get`/`map_has` by key class and by exact-payload hit rate before attributing generic `map lookup` or object-comparison zones to the proposal. Exact host-object handles are an implementation identity, not the semantic equality relation used by Soroban maps, and p26 budget compatibility can easily consume the apparent wall-clock saving.
