# H015: Pre-cache resolved wasmi export Func per Vm to skip per-call get_export

**Date**: 2026-05-04
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: apply-time (Soroban host invocation)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::metered_func_call` should be able to invoke a previously-resolved
`wasmi::Func` directly without redoing string-based export lookup on every
host invocation. Since the soroswap workload almost always creates a fresh
`Vm` per top-level contract entry-point invocation and immediately calls a
single exported function on it, the export resolution work should happen at
most once per `Vm`.

## Mechanism

`metered_func_call` (`vm.rs:275-322`) does:

1. `func_sym.try_into_val(host)` to materialize a `SymbolStr`.
2. `self.wasmi_store.try_borrow_or_err()?` (RefCell check).
3. `self.wasmi_instance.get_export(&store, name)` — walks wasmi's export
   table by name string.
4. `ext.into_func()` — discriminator check.

Steps (1)–(4) repeat for every host invocation even though the underlying
`wasmi::Func` handle is constant for the lifetime of the `Vm`. Replacing
the lookup with a one-time cache populated lazily on first
`metered_func_call` would skip ~3 RefCell checks and one wasmi export-table
walk per Soroban invocation.

## Trigger

Soroban contract dispatch via `Vm::invoke_function_raw` from the e2e_invoke
path. With the soroswap workload the bench profile shows ~20,313
`Vm::invoke_function_raw` calls and ~20,389 `Vm::instantiate_wasmi`
instantiations — i.e. essentially one `metered_func_call` per `Vm`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-322` —
  `metered_func_call` per-call resolution.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:140-200` — `Vm`
  construction site for caching candidate.

## Evidence

`Vm::invoke_function_raw` self-time is 696,879,003 ns over 20,313 calls
(34,307 ns mean) and `metered_func_call` lives inside it. Removing one
wasmi export lookup + a couple of RefCell checks could plausibly shave
~1 µs per call.

## Anti-Evidence

- `wasmi::Instance::get_export(name)` against a small export table is
  roughly an `O(N)` (small N) array scan or hash lookup. Estimated
  per-call cost ≈ 200–500 ns including the `SymbolStr` materialization.
- `treat_missing_function_as_noop` semantics depend on lookup failure
  returning `Val::VOID`; cache must preserve that for callers like
  `__constructor` and `__check_auth` probing.
- Even at the optimistic upper bound (1 µs saved × 20,313 calls = 20 ms
  aggregate), the soroswap apply path is 8-way parallel during
  `applySorobanStageClustersInParallel`, so wall-clock impact ≈ 2.5 ms
  across the 71-ledger trace, or ~0.013 % of the 19.3-second apply
  envelope. Far below the 1 % benchmark-noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated under this scope; related
prior fail entries (002-cache-minimal-wasmi-linker, 013-cache-resolved-linker-imports,
H002 InstancePre, 001-reuse-vm-store-instance) target store and linker reuse
across `Vm` instances, not export resolution within a single `Vm`.

### Why It Failed

The aggregate removable work is below the 1 % benchmark-noise floor and
well below the 3 % Medium floor required by this objective. The wasmi
export lookup is inexpensive (sub-microsecond) and is amortized over a
single use per `Vm`, so the absolute savings are tiny (~20 ms aggregate,
~2.5 ms wall after 8-way parallelism), independent of how cleanly the
cache is implemented.

### Lesson Learned

For Vm-internal one-shot lookups, multiply call count × per-call cost ×
parallelism factor before proposing a cache. Soroswap instantiates roughly
one `Vm` per export call (≈1:1 ratio between `Vm::instantiate_wasmi` and
`Vm::invoke_function_raw`), so any "cache N-th call within a Vm" idea has
no leverage in this benchmark; the only meaningful wins are caching across
`Vm` instances (which itself has its own family of fail entries).
