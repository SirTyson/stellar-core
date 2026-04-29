# H011: Eliminate redundant `is_clean()` fuel check in `add_fuel_to_vm` per host-function dispatch

**Date**: 2026-04-29
**Subsystem**: soroban-env (Wasm dispatch / fuel management)
**Severity**: Low
**Impact**: Per-dispatch overhead reduction in the Wasm→host→Wasm boundary
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each host-function dispatch from Wasm should perform exactly the
state-mutating fuel work required by the protocol — return remaining VM
fuel to the host budget, charge `WasmInsnExec` for what was consumed,
charge `DispatchHostFunction`, run the host function, then re-supply the
host's remaining budget as VM fuel. It should not perform purely defensive
runtime assertions whose answer is statically guaranteed by the
just-completed `reset_fuel()` call. The redundant `is_clean()` precondition
inside `FuelRefillable::add_fuel_to_vm` (vm/fuel_refillable.rs:22-33) makes
two extra wasmi `Option<u64>`-returning API calls (`fuel_consumed()` plus
`fuel_total()`) on every dispatch even though `return_fuel_to_host` at
fuel_refillable.rs:35-40 just called `self.reset_fuel()`, which by wasmi's
contract zeroes both counters.

## Mechanism

The `call` Tracy zone in `vm/dispatch.rs:304` (the host-function dispatch
wrapper) accumulates 424.331 ms of self-time across 19,982 invocations in
the soroswap apply window. Each invocation goes through the
`return_fuel_to_host` → host-fn body → `add_fuel_to_vm` sequence. Inside
`add_fuel_to_vm`, the first thing executed is
`if !self.is_clean()? { return Err(...); }`, which fans out to two extra
Store-trait calls (`fuel_consumed` + `fuel_total`), each of which performs
a `self.fuel_consumed().ok_or_else(...)` chain returning an `Option<u64>`.
Since `return_fuel_to_host` always runs `reset_fuel` immediately before
control returns to the dispatch macro, this check can never fail for the
post-`reset_fuel` `Caller`. Removing it would save ~2 wasmi API calls plus
one branch per dispatch.

## Trigger

Run the soroswap apply-load benchmark and observe the `call` zone at
`soroban-env-host/src/vm/dispatch.rs:304` (Tracy: 424 ms self-time, 19,982
events) inside the longest `applyLedger` interval. Each event traverses the
`add_fuel_to_vm` path containing the redundant `is_clean()` precondition.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-33` —
  `add_fuel_to_vm`'s defensive `is_clean()` precondition.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:18-20` —
  `is_clean` default impl, two trait calls.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:237-294` —
  per-dispatch path that calls
  `return_fuel_to_host` → host body → `add_fuel_to_vm`.

## Evidence

- Each dispatch boundary executes the `is_clean()` check unconditionally
  in production builds (it is *not* `#[cfg(debug_assertions)]`-gated).
- `Vm::metered_func_call` (vm.rs:275-345) follows the same pattern:
  `add_fuel_to_vm` → `func.call` → `return_fuel_to_host`. The first
  `add_fuel_to_vm` after store creation also runs the check, but the
  store has just been created with zero fuel, so the check trivially
  passes there too.
- 19,982 dispatch events × ~2 wasmi API calls saved per event ≈ 40 k saved
  function calls per soroswap apply window.

## Anti-Evidence

- The 424 ms `call` self-time aggregates *all* per-dispatch work: fuel
  return + `bulk_charge(WasmInsnExec)` + `reset_fuel` + Tracy span +
  `host.tracing_enabled()` RefCell borrow + `charge_budget(DispatchHostFunction)`
  + relative-to-absolute object-handle conversion + the *actual* host
  function body (which dominates) + result conversion + `add_fuel_to_vm`
  (consisting of `is_clean` + `get_wasmi_fuel_remaining` + `add_fuel`).
  The redundant `is_clean()` portion is two `Option<u64>`-returning calls
  on a wasmi `Caller`, each ≲50 ns of work. That is ≲100 ns × 19,982 ≈
  2.0 ms total trace time, ~0.25 ms wall at 8-thread parallelism.
- 0.25 ms / 305 ms baseline ≈ **0.08 %** — well below the 1 % benchmark
  noise floor and far below the 3 % Medium severity floor that this
  objective accepts. Per the SEVERITY_SCALE this is sub-Low.
- The 424 ms `call` self-time also includes Tracy `ZoneScoped` overhead
  (zone enter/exit per dispatch in Tracy builds), which is non-production
  per the meta-pattern on Tracy zones. Real per-dispatch self-time in a
  non-Tracy build is significantly lower, further compressing the
  removable fraction.
- The check is also a useful safety net against future changes to wasmi's
  `reset_fuel` contract; removing it weakens an internal invariant for
  vanishing benefit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in fail/hypothesis/reviewed/poc

### Why It Failed

Per-dispatch is_clean overhead is at most ~100 ns per event × 19,982
events ≈ 2 ms total trace time, ~0.25 ms wall at 8-thread parallelism,
or ≈ 0.08 % of the 305 ms soroswap apply baseline. This is far below the
1 % benchmark-noise floor and the 3 % Medium severity floor that this
objective requires. Even if every per-dispatch micro-optimization in this
neighborhood (skipping `is_clean`, hoisting the `host.tracing_enabled()`
RefCell borrow, collapsing the three `try_borrow_mut_or_err` calls in
`metered_func_call`) were stacked together, the projected wall-clock
saving would still be sub-1 %.

### Lesson Learned

The host-call dispatch wrapper (`vm/dispatch.rs`) and the
`metered_func_call` body have many small per-call defensive checks
(`is_clean`, `try_borrow_mut_or_err` triple, `tracing_enabled` RefCell
read) that look attractive in aggregate Tracy self-time, but each
individual check is sub-100 ns. The dominant per-dispatch cost is the
host function body itself plus the protocol-mandated
`bulk_charge(WasmInsnExec)` and `charge_budget(DispatchHostFunction)`
charges, neither of which is removable. Future hypotheses targeting the
`call` Tracy zone should isolate the host-fn-body fraction (which is *not*
in this zone's self-time — it is in child zones) before assuming
recoverable wall-clock time exists in the dispatch wrapper itself.
