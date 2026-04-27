# H006: Soroban dispatch macro performs two `RefCell::try_borrow` checks (`tracing_enabled`) on every host-function call entry and exit, even when no trace hook is installed

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-host-function-call overhead inside the Soroban dispatch macro (production builds with no tracer)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In production stellar-core (no `TraceHook` installed), the per-host-function
dispatch path should not perform any RefCell borrow operations to check
whether tracing is enabled. The "is the trace hook present?" check should be
a single relaxed-atomic load (or a const false in release builds where
tracing is statically disabled) so that the dispatch overhead per host
function call is dominated by useful work (FuelRefillable transfer, value
marshalling, the host body) rather than by RefCell bookkeeping.

## Mechanism

`generate_dispatch_functions!` in
`src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:222-264` checks
`if host.tracing_enabled() { ... }` twice per host call: once before the
host method body to log entry args, once after to log the return value.
`Host::tracing_enabled` (`host.rs:911-919`) executes:

```
if let Ok(disable_tracing) = self.0.disable_tracing.try_borrow() {
    if *disable_tracing { return false; }
}
match self.try_borrow_trace_hook() { Ok(hook) => hook.is_some(), Err(_) => false }
```

That is two `RefCell::try_borrow` calls (each an atomic-add + check + drop)
just to learn that tracing is off. With Soroban host-function call counts on
the order of millions per soroswap apply window (the trace shows 8.7 M
`charge` calls and 1.25 M `visit host object` calls, both invoked from inside
host methods), the dispatch macro is invoked on the order of hundreds of
thousands of times per soroswap-measured ledger. Two RefCell borrows × 2
sites per call × N host calls per ledger contributes a few hundred microseconds
to a couple of milliseconds per soroswap ledger.

Replacing the RefCell-based check with a single `AtomicBool` flag (or a
compile-time `cfg(feature = "tracing")` gate) on the `HostImpl` would let
the compiler short-circuit the entire `if host.tracing_enabled()` branch in
both dispatch sites without any borrow at all in production.

## Trigger

Run the soroswap benchmark (`scripts/run_apply_load_matrix.py --tracy`,
soroswap TX=4000, T=8). Every Soroban host function call routes through the
dispatch macro and pays for two `tracing_enabled()` calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:222-264` — entry
  and exit `if host.tracing_enabled()` branches in the macro body.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:911-919` —
  `tracing_enabled()` implementation with two RefCell borrows.

## Evidence

Each `RefCell::try_borrow` in the no-contention case is an atomic
fetch-modify-write plus a couple of branches; on modern hardware that is
roughly 5–10 ns. With 2 borrows × 2 sites × ~300 k host calls / ledger
≈ 6–12 ms / ledger of pure RefCell overhead in the benchmark window — only
just at the edge of what `closeLedger` measurement can resolve.

## Anti-Evidence

The cited 6–12 ms estimate is an upper bound, since (a) host-call counts in
the trace are spread across many ledgers, not just measured ones; (b) the
RefCell fast path may inline well enough that the actual cost is closer to a
single load; and (c) the structural change is non-trivial because the trace
hook can be set/unset at runtime by the embedder, which is why the original
code uses RefCell. A correct optimisation would need to add an `AtomicBool`
shadow flag and keep it consistent with the RefCell on `set_trace_hook`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelz**: PASS — not previously investigated in soroban/soroban-env hypothesis/fail/reviewed/poc queues

### Why It Failed

Projected apply-time reduction is below the 3 % Medium threshold for this
objective. Even the optimistic upper-bound estimate of 6–12 ms / ledger is
only ~1–2 % of the 620 ms soroswap baseline, and the realistic figure is
lower because most of the host-call counts in the trace come from non-
measured ledgers. The change also touches the protocol-versioned soroban
host (p26), which raises the bar for any micro-optimisation: the determinism
and embedder-API impact of swapping RefCell for an AtomicBool must be
analysed carefully, and the realised win is unlikely to clear the noise
floor on the benchmark machine.

### Lesson Learned

When the dominant remaining apply-path costs sit inside the protocol-
versioned soroban host, individual micro-optimisations to the dispatch
macro are unlikely to deliver Medium-tier wins on their own. Aggregate
wins would require a coordinated redesign of multiple per-host-call
overheads (tracing check, dispatch budget charge, fuel transfer, relative-
to-absolute object translation, marshalling) — a much larger scope than a
single hypothesis at this stage. Defer such hypotheses unless they can be
batched into a coherent dispatch-path redesign with a quantified projected
benefit.
