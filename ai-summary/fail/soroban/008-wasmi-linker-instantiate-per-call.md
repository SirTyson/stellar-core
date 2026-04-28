# H008: `Vm::instantiate_wasmi` rebuilds a fresh wasmi `Instance` (linker walk + import resolution + Store/Memory allocation) on every Soroban contract invocation, even when the same `(ParsedModule, Linker)` pair was just used by the previous call

**Date**: 2026-04-28
**Subsystem**: soroban-env / vm
**Severity**: Medium
**Impact**: Apply-time reduction; soroswap (per-tx wasm contract invocation) primary beneficiary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`SorobanModuleCache` already caches the parsed wasmi `Module` and the
`wasmi::Linker<Host>` per protocol so that contract invocations reuse the
expensive parse + link work across calls. The remaining per-invocation
work — turning a cached `(Module, Linker)` into an executable
`(Store, Instance, Memory)` — should not include a full linear walk over
the module's ~150 host-function imports for every call. Either the
linker should produce a pre-resolved `InstancePre` once per
`(ParsedModule, Linker)` pair (cached alongside the module in the
`SorobanModuleCache`) and each invocation should only do the cheap
`InstancePre::start(&mut store)` work plus a fresh Store/Memory
allocation, or the per-call instance construction should otherwise
short-circuit the import-resolution loop. The observable behavior must
be byte-identical: every call still gets its own fresh linear memory
and Store; budget, fuel, traps, and host-function dispatch are
unchanged.

## Mechanism

`Vm::instantiate_wasmi` in
`src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` is called
from `Vm::from_parsed_module_and_wasmi_linker`
(`src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218`), which is
in turn called from `Host::instantiate_vm`
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805`)
on every contract entry where the module cache hits. The hot inner
operation is `wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)`
at vm.rs:172, wrapped by the Tracy zone
`Vm::instantiate_wasmi - instantiate`. Internally, `wasmi::Linker::instantiate`
walks each of the module's imports (Soroban host modules expose ~150
host functions across all `mod_str` namespaces in `HOST_FUNCTIONS`),
looks each one up in the linker's hashmap, and constructs the
instance's import table. This is the same set of imports for every call
to a given contract, and even across contracts the imports come from
the same cached `wasmi_linker`; only the *Store* changes between calls
because each invocation needs its own linear memory, globals, and
fuel state.

Tracy soroswap baseline (csvexport, both default and `-e`):
- `Vm::instantiate_wasmi - instantiate,vm.rs,171` — **317.4 ms total /
  4,686 calls** (mean ≈ 67.7 µs / call), all inside `applyLedger`
  windows (372.9 ms / 4,464 calls inside `applyLedger` per
  unwrap-mode cross-check).
- `Vm::instantiate_wasmi,vm.rs,160` — 395.7 ms total / 4,686 calls
  (this is the outer zone wrapping store creation + cost charge +
  instantiate; the dominant child is the linker `instantiate` at 317 ms).
- `Vm::instantiate_wasmi - store,vm.rs,164` — 0.6 ms total — Store
  allocation is *not* the bottleneck; the import-table walk is.
- `Vm::instantiate,vm.rs,197` — 397.7 ms total / 4,686 calls — the
  outermost wrapper, confirming the entire per-call instantiation
  cost is dominated by the linker walk.

Each `applyLedger` window in the soroswap trace involves on the order
of 70 contract instantiations (4,464 inside-`applyLedger` calls / 65
ledgers), distributed across ~8 worker threads. The linker walk is
pure CPU work on each worker, so the contribution to wall-clock is
~`373 ms / NUM_CLUSTERS / 65 ledgers ≈ 0.7 ms / ledger / thread` — but
because instantiation happens *before* contract execution can start
on each call, eliminating most of this work shaves directly off the
critical path of every Soroban tx, where a soroswap swap chains
multiple contract entries (AMM contract → token-A SAC → token-B SAC).
A 50–80% reduction in per-call instantiate cost is plausible if
`InstancePre` is cached per `(ParsedModule, Linker)` pair, putting
total wall-clock saving in the 20–60 ms-per-ledger range — Medium
band against the 620.996 ms soroswap baseline.

The wasmi crate exposes `Linker::instantiate(&mut store, &module) ->
Result<InstancePre, ...>` and `InstancePre::start(&mut store) ->
Result<Instance, ...>`. The `InstancePre` captures resolved imports
and is cheap to `start` — the expensive walk happens only once per
`InstancePre`. Caching one `InstancePre` per cached
`(ParsedModule, wasmi_linker)` pair inside `ProtocolSpecificModuleCache`
(`src/rust/src/soroban_proto_any.rs`) and reusing it across calls is
the canonical wasmi optimization for this pattern. The remaining
per-call work — `wasmi::Store::new(engine, host.clone())` (28 µs in
this trace, but already small) + `InstancePre::start(&mut store)` +
memory export lookup — keeps determinism intact because each call
still gets a fresh Store, fresh linear memory, and fresh fuel.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` for `soroswap, TX=4000,
T=8` against the current baseline. csvexport (default mode) shows
`Vm::instantiate_wasmi - instantiate,soroban-env-host/src/vm.rs,171`
at 317 ms / 4,686 calls (67 µs mean) and `Vm::instantiate_wasmi`
(outer) at 395 ms / 4,686 calls. A PoC should:

1. In `ProtocolSpecificModuleCache::compile`
   (`src/rust/src/soroban_proto_any.rs:~225+`), build and cache a
   `wasmi::InstancePre` alongside each parsed module, using the
   crate's existing `wasmi_linker`.
2. In `Vm::from_parsed_module_and_wasmi_linker`
   (`src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218`), if a
   cached `InstancePre` is available, use it (`pre.start(&mut store)`)
   instead of `wasmi_linker.instantiate(&mut store, &module)`.
3. Verify byte-identical ledger output (full unit-test suite must pass)
   and re-measure soroswap median apply time across multiple runs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` —
  `Vm::instantiate_wasmi` calls `wasmi_linker.instantiate` per call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` —
  `Vm::from_parsed_module_and_wasmi_linker` is the entry point that
  builds a fresh Store + Instance per call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805` —
  `Host::instantiate_vm` is the cache-hit path called from contract
  entry; this is where the cached `InstancePre` (if added) would be
  consulted.
- `src/rust/src/soroban_proto_any.rs` — `ProtocolSpecificModuleCache`
  owns the `ModuleCache` (and indirectly the `wasmi_linker`); the
  cached `InstancePre` would live here to share the same lifetime as
  the parsed module.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` —
  `ParsedModule` could grow an optional `InstancePre` field, populated
  when the module is admitted to the cache.

## Evidence

- Tracy soroswap baseline: `Vm::instantiate_wasmi - instantiate` at
  317.4 ms / 4,686 calls (67.7 µs mean), all inside `applyLedger`.
  Outer `Vm::instantiate_wasmi` at 395.7 ms — confirming the linker
  walk dominates per-call cost.
- The linker walk is *pure import-table reconstruction* on each call;
  the inputs (the cached `wasmi_linker` and the cached
  `wasmi::Module`) are immutable across calls because they live
  inside `ProtocolSpecificModuleCache` (see the
  `subsystem-summary-of-rust` skill: "ModuleCache caches
  Arc<ParsedModule> shared across invocations", and
  `cache.wasmi_linker` is referenced unchanged from
  `frame.rs:800`).
- `Vm::instantiate_wasmi - store` at 0.6 ms total confirms the
  `wasmi::Store::new` portion is negligible — store allocation is not
  the cost being targeted, only the linker walk is.
- wasmi natively supports the `InstancePre` two-phase pattern
  (`Linker::instantiate` already returns it; `InstancePre::start` is
  the cheap second phase used at vm.rs:177 via `ensure_no_start`),
  so the proposed transformation is idiomatic wasmi usage rather than
  invasive surgery into wasmi internals.
- The change is structurally analogous to caching `wasmi::Module` and
  `wasmi::Linker` in `ModuleCache` (already done) — extending the
  cache by one more pre-computed artifact per module. No determinism
  property changes: the same imports resolve to the same host
  functions, every call still gets its own Store/memory/fuel, and the
  observable ledger output is unchanged.

## Anti-Evidence

- `Vm::instantiate_wasmi - instantiate` is inside `soroban-env-host`,
  the audited Soroban host crate. Any change must preserve
  byte-identical execution semantics; a PoC must validate against the
  full unit-test suite (especially Soroban tests under
  `[soroban]`/`[tx]`) and across all linked p21–p26 host crates that
  use the same pattern, not just p26.
- `wasmi::InstancePre` may be tied to a specific `Store` type-parameter
  in some wasmi versions; the PoC needs to verify that an `InstancePre`
  built with a "throwaway" Store at cache-build time is reusable with
  a fresh Store at each call (the wasmi 0.31+ API supports this
  because `InstancePre` is parameterized by the host data type, not by
  a specific Store instance, but this needs to be checked against the
  vendored wasmi version).
- `Host::instantiate_vm` also has an in-storage-recording-mode and a
  cache-miss code path
  (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:839-900`)
  where no cached `InstancePre` is available; those paths must
  continue to work via the existing `wasmi_linker.instantiate` route,
  so the optimization is conditional on `cache.get_module(...)`
  returning `Some` *and* the cache also having an `InstancePre` for
  that module.
- The fix touches multiple per-protocol host crates (p21..p26) plus
  the Rust bridge module-cache shim, so the PR diff is wider than a
  pure C++ change. The win (Medium) justifies the surface area only
  if the soroswap median apply time moves measurably across multiple
  benchmark runs.

---

## Review

**Verdict**: NEEDS_REFINEMENT
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Failed At**: reviewer

### What's Wrong

The hot path exists, but the proposed `InstancePre` cache is not valid for the wasmi version pinned by this checkout. `Linker::instantiate` first walks module imports into a fresh `Vec<Extern>`, but then immediately calls `Module::instantiate`, which allocates a new store-owned `Instance` handle, builds per-instance functions/tables/memories/globals/exports, initializes table elements and memory data, and returns an `InstancePre` containing that store-owned handle plus an `InstanceEntityBuilder`. `InstancePre::ensure_no_start` and `InstancePre::start` both consume `self` and install the builder into the same `Store`; `Instance` is explicitly owned by a `Store`, and the handles stored in the builder are store-local.

So `InstancePre` is not an immutable, reusable resolved-import plan. Caching it in `ParsedModule` or `ProtocolSpecificModuleCache` would either fail to compile because it is consumed and not cloneable, or would be semantically wrong because it contains allocations and handles from the throwaway store used to build it. The trace zone may still contain repeated import-resolution work, but it also includes required per-store instance allocation and memory/data/table initialization, so the current evidence over-attributes the whole `Vm::instantiate_wasmi - instantiate` cost to a cacheable linker walk.

### Alternative Angle

Refine this into a narrower hypothesis that does not cache `InstancePre`. Possible directions are: cache the parsed module's import symbol set used by `check_contract_imports_match_host_protocol`; cache or precompute a per-module import-resolution plan that maps imports to linker definitions but still constructs a fresh `InstanceEntityBuilder`, memory, globals, and store-owned instance each call; or patch/fork wasmi to expose a reusable "linked module/import plan" distinct from `InstancePre`. Any refined version needs instrumentation separating `Linker::process_import` time from `Module::instantiate`'s required per-store allocation/initialization work, then must show the cacheable portion alone clears the objective's 3% Medium threshold.

### Additional Code Paths

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775` — `call_contract_fn` instantiates a fresh `Vm` for each Wasm contract call before pushing the contract VM frame and invoking the export.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805` — cache hits retrieve `Arc<ParsedModule>` from `ModuleCache` and pass the shared `cache.wasmi_linker` to `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` creates a fresh `Store`, charges instantiation, rechecks protocol-gated imports, calls `wasmi_linker.instantiate`, consumes the returned `InstancePre` with `ensure_no_start`, and reads the memory export.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,160-182` — `ModuleCache` caches only the shared `wasmi::Engine`, maximal `wasmi::Linker<Host>`, and `Arc<ParsedModule>` map; no reusable pre-instance artifact exists.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-450` — `check_contract_imports_match_host_protocol` rebuilds the module import symbol set and scans `HOST_FUNCTIONS` on each instantiation, which is a separate potentially-cacheable cost from wasmi instantiation.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:646-658` — `Linker::instantiate` resolves every module import to an `Extern` vector and then calls `module.instantiate(context, externals)`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:57-78` — `Module::instantiate` checks the store instance limit, allocates a new store-owned instance, builds functions/tables/memories/globals/exports, initializes elements/data, and returns `InstancePre`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/pre.rs:11-20,43-80` — `InstancePre` stores an `Instance` handle and `InstanceEntityBuilder`, and `start`/`ensure_no_start` consume it while initializing that builder into the provided store.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/instance/mod.rs:140-147` — wasmi documents instances as owned by a `Store`, confirming a pre-instance built against one store cannot be replayed into another.
