# H021: Eliminate per-host-call protocol bound check in wasmi dispatch

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban VM dispatch
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a contract calls a host function through wasmi, the dispatch shim
should perform the minimum work necessary to hand off arguments, charge
the `DispatchHostFunction` metering cost, and invoke the host function.
Per-call protocol-version range checks
(`check_protocol_version_lower_bound`/`upper_bound`) are defensive guards
that should be unnecessary on the hot path: the linker rejects
out-of-protocol host imports at VM instantiation
(`check_contract_imports_match_host_protocol`), so by the time a call
reaches dispatch, the host function is already known to be valid for the
current ledger protocol. The expected fast path therefore omits the
duplicate per-call protocol bound checks.

## Mechanism

`generate_dispatch_functions` in
`src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-242`
expands one dispatch shim per host function. Each shim contains:

```
$( host.check_protocol_version_lower_bound($min_proto)?; )?
$( host.check_protocol_version_upper_bound($max_proto)?; )?
```

These calls execute on every host call to a function whose macro
description supplies a `min_proto` or `max_proto` literal — i.e., a
non-trivial fraction of the env. Each check invokes
`Host::with_ledger_info`, which performs a `try_borrow` on the ledger
`RefCell` and reads `protocol_version`. The `call` zone in dispatch is
632 ms aggregate over 30,534 invocations in the soroswap trace
(`vm/dispatch.rs:304`); the protocol bound checks are part of that
self-time but are functionally redundant because
`ParsedModule::check_contract_imports_match_host_protocol`
(`vm/parsed_module.rs:403`) already proved at instantiation time that
every imported host function's protocol bounds are satisfied for the
current ledger protocol.

## Trigger

Run the soroswap apply-load benchmark. Each Soroban transaction performs
multiple cross-contract calls; cumulative dispatch invocations are
30,534 in the trace, with `call` self-time at 632 ms.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-242` —
  per-call protocol bound checks inside the dispatch shim.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454`
  — instantiation-time check that already validates protocol bounds for
  every imported host function.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` — `with_ledger_info`
  borrow used by each `check_protocol_version_*` call.

## Evidence

The redundancy is structurally evident: instantiation-time check
documentation explicitly states that any out-of-protocol-range imports
are rejected at link time. The per-call dispatch checks are described
in the macro comments only as an "additional guard rail". With 30k+
dispatch calls per benchmark, even cutting ~30-50 ns per call yields a
measurable Tracy delta. The estimated savings are bounded above by a
few hundred microseconds aggregate per ledger.

## Anti-Evidence

Even an optimistic 100 ns saved per dispatch call × 30,534 calls = ~3 ms
aggregate worker self-time across the entire 70-ledger trace, which
divided across 8 parallel apply workers and across 19.6 s of total apply
time is well below 0.01% — orders of magnitude below the noise floor.
The change also touches the deterministic Soroban host dispatch path,
which would require careful protocol-version observation review and
host-event fingerprint regeneration to confirm there is no observable
metering or error-ordering change. The risk:reward ratio is wholly
unfavorable.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Failed At**: hypothesis
**Novelty**: PASS — adjacent to fail/transactions/006-cache-module-import-protocol-check
(which focuses on caching the *instantiation-time* import check), but
distinct: this hypothesis targets the *per-host-call* protocol bound
checks inside the dispatch shim, not the linker-side check.

### Why It Failed

Below objective severity threshold by orders of magnitude. The per-call
protocol bound check is too cheap to remove for a measurable win, even
though it is structurally redundant. The change also crosses the
deterministic host boundary, requiring observation/event-fingerprint
work disproportionate to the benefit.

### Lesson Learned

Per-call host-side guards in the wasmi dispatch shim are individually
sub-microsecond and even cumulatively land below benchmark noise. Apply-
path optimizations targeting Soroban host hot paths must either (a)
collapse work that runs millions of times per ledger close (e.g.,
`charge`, `visit host object`) by *protocol-gated metering changes*
that genuinely skip expensive sub-work, or (b) restructure a
*dominant phase* of close-ledger (e.g., redesign cluster setup,
finalization, or BucketList write coalescing). Defensive-guard removal
on its own is never a viable optimization here.
