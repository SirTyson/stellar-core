# H030: Coalesce Triple `wasmi_store` RefCell Borrow in `Vm::metered_func_call`

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-call host-VM boundary microcost
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::metered_func_call` should perform the minimum number of mutable
`RefCell` borrows on `self.wasmi_store` required by safety. Each
`try_borrow_mut_or_err()` call performs an atomic-ish Cell write +
overflow check + drop epilogue, so the borrow scope ought to be hoisted
to one acquisition for the contiguous "add fuel → call → return fuel"
critical section.

## Mechanism

In `src/rust/soroban/p26/soroban-env-host/src/vm.rs:327-345`,
`metered_func_call` issues three separate `try_borrow_mut_or_err()`
acquisitions of `self.wasmi_store`:

```rust
self.wasmi_store.try_borrow_mut_or_err()?.add_fuel_to_vm(host)?;        // borrow 1
let res = func.call(&mut *self.wasmi_store.try_borrow_mut_or_err()?,    // borrow 2
                    inputs, &mut wasm_ret);
self.wasmi_store.try_borrow_mut_or_err()?.return_fuel_to_host(host)?;   // borrow 3
```

In addition, line 286-288 takes a fourth `try_borrow_or_err()` for
`get_export`. None of these scopes overlap a re-entrant host call that
would require the borrow to be temporarily released — `add_fuel_to_vm`
and `return_fuel_to_host` only touch the store's fuel counter; the
`func.call` is the one path that re-enters host functions (and they
borrow `wasmi_store` from inside a `with_vmcaller` callback, requiring
the outer borrow to be released).

A single `let mut store = self.wasmi_store.try_borrow_mut_or_err()?;`
covering only `add_fuel_to_vm` would save one of three acquisitions,
since the `func.call` borrow MUST be its own scope to allow re-entrant
host calls to borrow the store. The maximum removable acquisition count
is two (one before `func.call`, one after).

## Trigger

Any Soroban contract invocation. Hot for soroswap because of the high
per-call dispatch rate.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-391` —
  `metered_func_call`, the three `try_borrow_mut_or_err` sites at
  lines 327-329, 333-334, 343-345.

## Evidence

`Vm::invoke_function_raw` self-time in the accepted Tracy trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`)
is 696 ms aggregate across 20,313 calls (34.3 µs / call). The
RefCell borrow itself is a few-ns operation, but the structural pattern
of three back-to-back acquisitions on the same hot path is suggestive.

## Anti-Evidence

- The borrows are uncontended (single-threaded within a Vm), so each
  `try_borrow_mut_or_err` is just a Cell read-modify-write — likely
  10–20 ns each.
- Two removable borrows × ~15 ns × 20,313 calls = 0.6 ms aggregate
  worker CPU. Per-cluster wall-time after 8-way parallel division and
  per-ledger normalization (70 windows): ~1 µs / cluster / ledger.
- Against the 272.9 ms soroswap median this is ~4 × 10⁻⁶ — orders
  of magnitude below the Low (1%) threshold and far below benchmark
  noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — RefCell-borrow consolidation in `metered_func_call`
is not represented in `ai-summary/fail/soroban/summary.md` or any
adjacent fail/success file.

### Why It Failed

The structural opportunity (3 borrows where 2 would suffice) is real,
but the absolute per-call savings (a few tens of nanoseconds) cannot
clear the optimize-soroswap Medium severity threshold — even an upper
bound of ~30 ns × 20,313 calls / 8 clusters / 70 ledgers is ~1 µs per
cluster per ledger, sub-Low. This falls into the category of fail
meta-pattern #5: "VM dispatch micro-optimizations that boil down to
a few wasmi store field reads per host call are structurally below
the optimize-soroswap review threshold."

The `wasmi_store` is also borrowed during `func.call` because that
borrow is required to span the entire wasmi execution; consolidating
fuel transfers around it is constrained by re-entrant host calls
(which `with_vmcaller` borrows the store from inside) — so any
consolidation must keep the `func.call` borrow as its own scope.

### Lesson Learned

For per-host-function-call micro-optimizations, multiply the absolute
per-call saving (in ns) by `N_calls / 8 clusters / 70 ledgers` BEFORE
proposing. RefCell-borrow consolidation in `Vm::metered_func_call`
is structurally bounded to ≪ 0.1% of apply time at the soroswap call
volume, and falls under the same meta-pattern that rejected fuel-sync
coalescing (fail #002) and dispatch-fuel-refill coalescing
(transaction-ledger fail #002).
