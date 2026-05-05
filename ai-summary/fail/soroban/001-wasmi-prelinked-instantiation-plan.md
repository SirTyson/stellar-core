# H001: Cached wasmi prelink plan for repeated Soroswap VM instantiation

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in repeated Soroban Wasm instantiation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban Wasm frame must still instantiate a fresh `wasmi::Store` and `wasmi::Instance`, use the current invocation's `Host`, charge the same next-protocol instantiation budget, reject unsupported imports for the current ledger protocol, and produce identical events, storage changes, return values, and failures. However, for a cached `ParsedModule` whose imported host functions and expected function types are immutable, stellar-core should not need to repeat string-based import lookup and protocol/type validation work from scratch on every instantiation. A per-`ParsedModule` prelink plan should be able to resolve imported symbols to stable host-function descriptors once, then instantiate fresh runtime state through a compact validated import list.

## Mechanism

The current cached-module path keeps one maximal `wasmi::Linker<Host>` in `ModuleCache` and passes it to `Vm::instantiate_wasmi` for every cached contract frame. Even after previous minimal-linker and bulk-import-allocation ideas are discounted, the code still redoes the module-import-to-host-function matching, import type validation, and host-import construction work for 20,389 cached VM instantiations in the current soroswap trace. A deeper prelink plan stored beside `ParsedModule` would cache the declared import order, matching `HostFuncInfo` entries, expected protocol bounds, and expected wasmi function types, then build the fresh per-store import handles directly from that plan; this avoids repeated name lookup and validation while preserving fresh Store/Instance semantics and avoiding the rejected `InstancePre` / resettable-instance designs.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with a warmed module cache. Each ledger repeatedly invokes the same router/pool contract code hashes across Soroban worker threads; every call retrieves an `Arc<ParsedModule>` from the shared module cache but still instantiates through the generic linker path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a fresh store, charges instantiation, checks imports, and calls `wasmi_linker.instantiate` for every cached VM frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-803` — cached-module execution retrieves `Arc<ParsedModule>` but still passes the module-cache maximal linker into `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,185-195` — `ModuleCache` stores parsed modules and one maximal linker, but no per-module prelink/import plan.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-268,403-454` — import-symbol extraction and protocol validation are recomputed from `ParsedModule` during instantiation rather than stored as a validated plan.
- `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:18-21,48-78` — `HostFuncInfo::wrap` is the host-function descriptor surface a prelink plan would reference.

## Evidence

The current accepted soroswap trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` has 71 windows totaling 5,230,315,999 ns. Descendant instantiation zones include:

| Zone | Self/total time | Calls | Source |
|---|---:|---:|---|
| `Vm::instantiate_wasmi - instantiate` | 1,315,387,452 ns self | 20,389 | `soroban-env-host/src/vm.rs:171` |
| `Vm::instantiate_wasmi` | 1,648,211,481 ns total / 79,587,805 ns self | 20,389 | `soroban-env-host/src/vm.rs:160` |
| `ParsedModule::check_contract_imports_match_host_protocol` | 224,014,414 ns self | 20,389 | `soroban-env-host/src/vm/parsed_module.rs:423` |

Prior rejected ideas either trimmed the linker's definition count, bulk-allocated imported host `Func` handles, or tried to reuse initialized instances. This proposal is narrower than instance reuse but deeper than minimal linkers: it attacks repeated per-module import resolution and validation inside fresh instantiation. If the plan removes most of the import-resolution/type-validation part of the 1.315 s instantiate sub-zone, the aggregate worker saving can clear the 3% Medium floor after 8-way cluster normalization.

## Anti-Evidence

The pinned wasmi instantiate path may be dominated by memory/global/table allocation and data-segment initialization rather than import resolution. If so, a prelink plan will collapse to the same sub-threshold family as prior minimal-linker and bulk-import-allocation failures. A PoC must first add wasmi sub-zones or counters around import lookup/type validation versus memory/table/global initialization, and the implementation may require changes in the pinned `soroban-wasmi` fork rather than only stellar-core wrapper code.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a fresh-instance prelink/import-resolution plan in retained Soroban fail/success records
**Failed At**: reviewer

### Trace Summary

The hot path is real: C++ parallel apply invokes the Rust host for each Soroban transaction, the host installs the shared `ModuleCache`, `Host::call_contract_fn` retrieves cached `Arc<ParsedModule>` values, and `Vm::instantiate_wasmi` creates a fresh store and instance for every Wasm contract frame. The repeated protocol/import validation is also real: `ParsedModule::check_contract_imports_match_host_protocol` rebuilds a module import-symbol set and scans `HOST_FUNCTIONS` on every instantiation. However, the proposed prelink plan cannot remove most of the measured `Vm::instantiate_wasmi - instantiate` zone: wasmi still has to allocate per-store imported host `Func` handles and run `Module::instantiate`, which performs import extraction/type validation, Wasm function/table/memory/global allocation, export registration, and active element/data segment initialization.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2560-2574,2622-2635` — Soroban stage application waits for worker futures and therefore includes worker-side host invocation on the apply critical path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-584` — each Soroban operation crosses the Rust bridge with the shared module cache during apply.
- `src/rust/src/soroban_proto_any.rs:429-448` — bridge dispatch times `e2e_invoke::invoke_function` and calls protocol-specific host invocation with the shared module cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-485` — each invocation constructs a fresh enforcing `Host`, installs `module_cache`, calls `Host::invoke_function`, and then finishes storage/events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls retrieve the contract instance, fetch `Arc<ParsedModule>` from `ModuleCache`, and pass the maximal linker to fresh VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a new `Store`, charges instantiation, runs repeated import/protocol validation, calls `Linker::instantiate`, ensures no start function, and extracts memory.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,160-195` — the cache stores one shared engine, one maximal linker, and parsed modules only; it has no cached per-module import/prelink plan.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-268,403-454` — import symbols are recomputed from `wasmi_module.imports()` and checked against every `HOST_FUNCTIONS` entry on each instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` and `src/rust/soroban/p26/soroban-env-host/src/vm/func_info.rs:18-21,42-80` — host functions are registered into a linker via `func_wrap`; these descriptors are the only stable surface a prelink plan could reference in stellar-core code.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:646-659,670-745` — `Linker::instantiate` maps every module import through `process_import`, doing string/interner lookup, `BTreeMap` definition lookup, type checks, and host `Func` materialization before calling `Module::instantiate`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:327-365` and `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/func/mod.rs:175-244` — linker-defined host functions still allocate a store-local trampoline reference and host `Func` entity when converted to imports; this cannot be shared across fresh stores by a stellar-core-side plan.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78,94-159,167-367` — low-level `Module::instantiate` still validates import/external compatibility and performs all per-instance allocation and active segment initialization after linker import processing.

### Why It Failed

The inefficiency exists, but the Medium impact claim depends on treating most of `Vm::instantiate_wasmi - instantiate` as avoidable import-resolution/type-validation work. The actual wasmi call graph shows that only the linker front-end is avoidable by a prelink plan; the mandatory fresh-instance work remains: per-store host `Func` allocation, Wasm function/table/memory/global allocation, export setup, active element/data initialization, and `InstancePre::ensure_no_start`.

The one directly measured stellar-core validation slice, `ParsedModule::check_contract_imports_match_host_protocol`, is 224 ms aggregate worker CPU across the trace. After the benchmark's 8-way Soroban worker normalization, removing it entirely is only about 28 ms over the 5.23 s apply-window trace, roughly 0.5%. The additional avoidable linker string lookup and redundant type-check work is bounded by the same small per-import loop and does not remove the store-local host `Func` materialization or `Module::instantiate` work. Even optimistic removal of the repeated protocol check plus a comparable linker lookup/type-check slice remains far below the objective's 3% Medium floor, while a deeper wasmi unchecked-import API would be an invasive fork change that still must keep fresh allocation and initialization semantics.

### Lesson Learned

For fresh-instance wasmi optimizations, distinguish the measured `Linker::instantiate` zone from the subset before `Module::instantiate`. A cached prelink plan can plausibly remove repeated symbol/protocol lookup and one layer of type validation, but it does not make imported host functions or the instance body reusable; those store-local and per-instance costs dominate enough that the projected wall-time saving is below the optimize-soroswap review threshold.
