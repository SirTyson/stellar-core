# H006: Reuse wasmi::Store Across Soroban Contract Invocations Within a Host

**Date**: 2026-04-29
**Subsystem**: soroban-env / rust
**Severity**: Low
**Impact**: Sub-3% reduction in soroswap apply time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each Soroban contract invocation that hits the module cache should
instantiate a wasmi `Instance` from the cached `ParsedModule` + cached
`Linker` against a `wasmi::Store<Host>` that minimizes per-instantiation
allocator and wasmi bookkeeping work. Specifically, the Store creation
(`wasmi::Store::new(engine, host.clone())`) and the linker-walk during
`Linker::instantiate` should not pay per-call allocator/setup overhead
when those structures could be reused (resetting fuel and host data) for
the next invocation on the same worker thread.

## Mechanism

`Vm::instantiate_wasmi`
(`src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187`) constructs a
brand-new `wasmi::Store<Host>` for every contract invocation, then calls
`wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` which
walks the module's import section and resolves each import against the
cached linker. The Store carries the host's per-call mutable state (fuel,
limits, host data) and is dropped at the end of the invocation.
A worker thread that processes many soroswap swaps in a row creates,
populates, and drops one Store per nested contract call.

If wasmi exposed (or could be extended to expose) a `reset_data`
operation on Store that swaps out the carried `Host` and resets fuel
without freeing the underlying allocations, a worker thread could keep a
thread-local Store and reuse it across invocations, paying allocator cost
once instead of `~5 invocations/swap * 2000 swaps/ledger / 8 workers =
~1250 allocations/ledger/worker`.

## Trigger

Run the soroswap apply-load matrix
(`scripts/run_apply_load_matrix.py`, soroswap TX=2000, T=8). Inspect
`Vm::instantiate_wasmi - instantiate` and `Vm::instantiate_wasmi - store`
in Tracy.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` —
  `Vm::instantiate_wasmi` creates a fresh `wasmi::Store<Host>` on every
  invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:191-218` —
  `Vm::from_parsed_module_and_wasmi_linker` is the cache-hit path that
  builds a Vm wrapping the new Store and Instance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-804` —
  `instantiate_vm` calls into `Vm::from_parsed_module_and_wasmi_linker`
  on every cache-hit dispatch from `invoke_contract`.

## Evidence

The reference soroswap Tracy trace
(`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/...02-soroswap-tx-2000-t-8.tracy`)
reports `Vm::instantiate_wasmi - instantiate` at **676,355,499 ns
self-time** across **10,061 calls** (mean 67,225 ns). The sibling Store
and linker setup zones are smaller but additive. The path is an
`applyLedger` descendant via `applySorobanStageClustersInParallel` →
`InvokeHostFunctionOpFrame::doParallelApply` → `invoke_host_function` →
`invoke_contract` → `instantiate_vm` →
`Vm::from_parsed_module_and_wasmi_linker` → `instantiate_wasmi`.

## Anti-Evidence

The reviewed `H008: Wasmi InstancePre Caching`
(`ai-summary/fail/soroban/008-wasmi-linker-instantiate-per-call.md`) and
its meta-pattern note that wasmi 0.31's `InstancePre` is store-bound and
single-use; wasmi does not expose `Store::reset` or `Store::swap_data` in
the public API. Adding such an API requires a fork of the pinned wasmi
crate, and any change to `Store` lifetime semantics risks subtle wasmi
state leakage between contract invocations (table state, exported
function references, etc.).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — distinct from the previously-rejected `InstancePre`
caching (this targets Store reuse, not pre-linked Instance reuse)

### Why It Failed

Two compounding issues take this below the objective's Medium floor:

1. **Total upper bound is sub-3%.** `Vm::instantiate_wasmi -
   instantiate` self-time is 676 ms in a 10.2 s trace (~6.6% of trace
   time, but the trace includes large out-of-scope tx-set construction
   work). Mapping back to applyLedger descendants only and amortizing
   across 8 worker threads, the apply-thread critical path saving from
   eliminating Store creation alone is ~1.5–2.5% of the 313 ms soroswap
   median — Low severity, below the objective's 3% floor.

2. **wasmi public API does not support Store reset.** The pinned wasmi
   0.31 does not expose a way to reset a Store's host data or fuel without
   destruction (per H008's lesson). A real fix would require forking
   wasmi, which is out of scope for an apply-time optimization round and
   carries determinism risk that no benchmark win could justify.

### Lesson Learned

Per-invocation wasmi Store creation is a real but distributed cost.
Without a wasmi API change, there is no path to reuse Stores across
invocations within a single host. This means VM-instantiation
optimization for soroswap requires either (a) restructuring contract
invocation to have fewer nested calls (out of scope — protocol-defined),
or (b) upstreaming wasmi changes (out of scope for this round).
