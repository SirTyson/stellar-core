# H009: Reduce per-`Vm::invoke_function_raw` arg-marshalling overhead via stack-allocated wasmi value buffer

**Date**: 2026-05-02
**Subsystem**: soroban (rust host VM dispatch)
**Severity**: Low (claimed); promoted to fail under Medium-floor rule
**Impact**: per-Vm-invocation cycles
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::invoke_function_raw` should marshal a small, fixed-shape arg list
(typically 1–4 `Val`s for SAC/soroswap entrypoints) without heap-allocating
a `Vec<wasmi::Value>` on every invocation. For a hot path with ~20K calls
per ledger window, the marshalling cost should be cycles, not microseconds.

## Mechanism

`src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411`:

```rust
pub(crate) fn invoke_function_raw(
    self: &Rc<Self>,
    host: &Host,
    func_sym: &Symbol,
    args: &[Val],
    ...
) -> Result<Val, HostError> {
    let _span = tracy_span!("Vm::invoke_function_raw");
    Vec::<wasmi::Value>::charge_bulk_init_cpy(args.len() as u64, host.as_budget())?;
    let wasm_args: Vec<wasmi::Value> = args
        .iter()
        .map(|i| host.absolute_to_relative(*i).map(|v| v.marshal_from_self()))
        .collect::<Result<Vec<wasmi::Value>, HostError>>()?;
    self.metered_func_call(host, func_sym, wasm_args.as_slice(), ...);
}
```

Each invocation:
1. Calls `charge_bulk_init_cpy` against the budget for the arg-vec
   allocation.
2. Heap-allocates a `Vec<wasmi::Value>` sized to `args.len()`.
3. Maps each `Val` through `absolute_to_relative` + `marshal_from_self`
   into the vec.
4. Passes the vec slice to `metered_func_call`, which itself does another
   `get_export(store, func_name)` string lookup per call.

For soroswap (≤4 args per entrypoint), a `SmallVec<[wasmi::Value; 4]>` or
even a stack `[wasmi::Value; 4]` array filled in a loop would eliminate
the heap allocation and the `charge_bulk_init_cpy` budget call. The
budget charge would still be required for protocol-equivalence but could
be hoisted/coalesced.

## Trigger

Run `apply-load --benchmark soroswap`; measure `Vm::invoke_function_raw`
self-time before and after replacing the `Vec<wasmi::Value>` allocation
with a stack buffer.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` —
  `Vm::invoke_function_raw`
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-330` —
  `Vm::metered_func_call` (also does per-call string-keyed
  `get_export(store, func_name)`)

## Evidence

- Tracy `Vm::invoke_function_raw` self-time = 696 ms across ~20K calls in
  the soroswap trace = ~34 µs per call.
- The bulk of the 34 µs is the `metered_func_call` child (fuel transfer,
  `func.call`, return-fuel) which is unavoidable wasmi work; the
  *parent's* own self-time is dominated by the arg-vec allocation +
  budget charge + relative-handle conversion.

## Anti-Evidence

- The `charge_bulk_init_cpy` is part of the *protocol-observable* budget
  metering — removing it would change consumed budget on every Soroban tx
  and is therefore a protocol break (rejected at hypothesis stage by
  prior fails `001-zero-memory-budget-charge-fast-path` and the
  protocol-gating success #001).
- Even an entirely-free arg marshalling reduces parent self-time by at
  most ~5–8 µs per call. Across 20K calls ÷ 8 worker threads that is
  12–20 ms wall-clock per benchmark window (≈70 ledgers), or
  0.17–0.28 ms / ledger ≈ 0.06–0.10% of soroswap apply. Far below the
  Medium 3% floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Prior fails targeted
`charge`-call coalescing (success #001) and `check_contract_imports`
caching (fail summary), but not the per-invocation `Vec<wasmi::Value>`
allocation specifically.

### Why It Failed

The optimization is below the objective's Medium severity floor (≥3% of
soroswap apply). The remaining cost not gated by metering is at most
~0.1% of apply per benchmark conventions. Furthermore, removing the
budget charge for the alloc would alter protocol-observable budget
consumption, requiring a protocol-version gate similar to success #001 —
adding implementation complexity for a sub-noise win.

### Lesson Learned

For cycle-level micro-optimizations inside the Rust host, the Medium
threshold (~8 ms/ledger) effectively requires either (a) eliminating an
entire dominant phase, (b) coalescing many metering charges behind a
protocol gate, or (c) reducing wasmi-internal work. Lone allocation
removals in 20K-call hot paths land in the 0.05–0.5% noise range and
should not be promoted as standalone hypotheses; they should only be
batched into a larger protocol-gated metering coalescing PR.
