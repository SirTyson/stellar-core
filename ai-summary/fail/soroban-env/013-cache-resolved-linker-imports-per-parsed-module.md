# H013: Cache wasmi `Linker::process_import` resolution table per `ParsedModule`

**Date**: 2026-05-03
**Subsystem**: soroban-env (rust)
**Severity**: Low (below objective threshold)
**Impact**: per-invocation VM instantiation overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::instantiate_wasmi` calls `wasmi_linker.instantiate(&mut store,
&parsed_module.wasmi_module)`, which internally iterates each module import
once, performs a `BTreeMap<ImportKey, Definition<Host>>` lookup keyed by
`(module_str, field_str, kind)` in the linker, and then validates the
resolved definition's type against the import's expected type. For a stable
`(Linker<Host>, ParsedModule)` pair, the lookup result and the type-check
verdict are both invariant across invocations — they depend only on the
module's import section (immutable in `Arc<ParsedModule>`) and the linker's
definitions (set up once at host construction). The expected behavior of an
optimized path is to compute the resolved import index once per
`ParsedModule` and reuse it on subsequent instantiations, skipping the
per-invocation BTreeMap lookups and type comparisons.

## Mechanism

Today, `Linker::instantiate` (`soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:646-659`)
calls `self.process_import(&mut context, import)` for every import in the
module. `process_import` does a `BTreeMap::range`-style lookup (≈O(log N) on
the linker's ~250 host function definitions) plus a `FuncType` equality
check, then calls `Definition::as_func` which does a per-store
`alloc_trampoline(host_func.trampoline().clone())` and `alloc_func(...)`.
The deviation from the expected behavior is that the lookup + type-check work
(but **not** the trampoline/`Func` allocations, which are per-store and
mandatory) is repeated on every instantiation. By caching a per-`ParsedModule`
`Vec<Symbol>` (or `Vec<linker_def_index>`) recording the resolved import
slots after the first instantiation, subsequent instantiations could bypass
the BTreeMap lookups and the `FuncType` equality checks entirely.

## Trigger

Run any soroswap invocation that creates a `Vm`. Each VM instantiation
crosses `Linker::instantiate -> process_import` for every wasm import (≈30–60
per typical Soroban contract).

## Target Code

- `soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:646-659` — `Linker::instantiate`
  iterates `module.imports().map(process_import)`.
- `soroban-wasmi-0.31.1-soroban.20.0.1/src/linker.rs:670-702` — `process_import`
  does BTreeMap lookup + type check + `as_func` allocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:170-173` — `Vm::instantiate_wasmi`
  calls `wasmi_linker.instantiate(...)`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` — `ParsedModule`
  holds the immutable `wasmi::Module` whose import section is invariant.

## Evidence

- Tracy soroswap diagnostic trace
  (`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`)
  reports `Vm::instantiate_wasmi - instantiate` self-time of 1,315 ms over
  20,389 calls (12.77% of trace, ≈64 µs per instantiation).
- The `Linker::definitions` BTreeMap is populated once during host
  construction and never mutated thereafter, so the lookup result is stable.
- `ParsedModule` is `Arc`-shared via `ModuleCache`, so the resolution result
  could be memoized inside the parsed module without breaking sharing.

## Anti-Evidence

- **Lookup + type-check savings are below the Medium floor.** The dominant
  per-instantiate cost inside `wasmi_linker.instantiate` is the per-import
  `as_func` work — `store.alloc_trampoline(host_func.trampoline().clone())`
  and `store.inner.alloc_func(FuncEntity::Host(entity))`. Both are per-store
  allocations into Vec-backed arenas and are not removable by import-resolution
  caching. With ≈50 imports × 20,389 instantiations ≈ 1M arena allocations
  remaining, the work that import caching could remove is the 1M BTreeMap
  lookups (~50 ns each → ~50 ms total Tracy time) plus 1M `FuncType` equality
  checks. Total removable Tracy time ≈ 100 ms; with 8-thread apply
  parallelism, wall savings ≈ 12 ms ≈ 4.4% of the 272 ms soroswap apply
  baseline at the **upper bound**, but that figure is itself inflated by
  Tracy instrumentation overhead. The fail summary's prior
  `002-cache-minimal-wasmi-linker-per-parsed-module` rejection covers exactly
  this distinction: "trimming the definition set can reduce lookup depth but
  does not remove per-import host-`Func` allocations."
- **Implementation requires modifying soroban-wasmi internals**
  (`Linker::process_import` is private; exposing a memoized form requires
  either a new public API or duplicating the resolution logic in the host).
  The risk-adjusted payoff is below this objective's Medium severity floor
  (3–10% non-Tracy soroswap apply-time reduction) and the diff is not "clean
  and low-risk" enough to justify pursuing under the Low-tier carveout
  (1–3%) — and Low is **explicitly not accepted** for this objective per the
  hypothesis prioritization rules.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail `002-cache-minimal-wasmi-linker-per-parsed-module`
(which proposed a per-module *minimal linker*, not a cached resolution table);
distinct from fail `001-cache-import-validation-per-parsed-module` (which
cached the host-protocol import-validity check, a different per-module
predicate).

### Why It Failed

The removable work (BTreeMap lookups + `FuncType` equality checks) is small
relative to the mandatory per-store `alloc_trampoline`/`alloc_func` work that
remains inside `Linker::instantiate`. The upper-bound projected savings of
~4% are inflated by Tracy instrumentation overhead and the actual
non-Tracy production savings would not clear the 3% Medium floor. The
implementation also requires invasive changes to soroban-wasmi internals,
which is disproportionate to the projected Low-tier impact (Low not accepted
at hypothesis stage for this objective).

### Lesson Learned

For per-invocation wasmi instantiation hypotheses, separately quantify
(a) BTreeMap/HashMap lookup time, (b) per-import type-check time, and
(c) per-import `Func`/`Trampoline` arena allocation time *before*
projecting savings. Caching at the linker-resolution layer can only
remove (a) and (b); (c) dominates and remains mandatory because each
`Store<Host>` owns its own per-instance Func arena. To clear the Medium
floor, an instantiation hypothesis must target (c) — which would require
either pooling stores (incompatible with per-invocation `Host` user-state)
or sharing host-Func arenas across stores (deep wasmi redesign).
