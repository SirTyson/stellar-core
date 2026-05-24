# H009: Skip `check_contract_imports_match_host_protocol` for cached `ParsedModule` instances

**Date**: 2026-05-24
**Subsystem**: soroban (parallel apply — VM instantiation in stellar-core's
soroban dispatch path, observed via the soroban-env-host import-check zone)
**Severity**: Low (sub-Low, below objective threshold)
**Impact**: per-`Vm::new` redundant HOST_FUNCTIONS import-symbol scan
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ParsedModule::check_contract_imports_match_host_protocol`
(`src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454`)
verifies that every host-function symbol imported by a contract module is
supported under both the module's stored `proto_version` and the current
`ledger_proto`. Both inputs are loop-invariant within a given ledger
(`proto_version` is fixed at parse time, `ledger_proto` is fixed per close),
so the check result should be computed once per `(ParsedModule, ledger_proto)`
and reused across every `Vm::instantiate_wasmi` call that reuses that
`ParsedModule` from the `SorobanModuleCache`.

## Mechanism

The function is called from `Vm::new`
(`src/rust/soroban/p26/soroban-env-host/src/vm.rs:171`) on every Vm
instantiation. It iterates the full `HOST_FUNCTIONS` table (~200 entries)
and, for every entry whose `(mod_str, fn_str)` appears in the module's
imported-symbol set, performs the `min_proto`/`max_proto` comparisons. The
result depends only on `(self.proto_version, ledger_proto, module_symbols)` —
all stable for the lifetime of a `ParsedModule` within a single ledger — yet
the work is repeated on every reuse of the cached `ParsedModule` for every
contract call within that ledger.

## Trigger

Soroswap apply-load benchmark: every transaction's swap path causes multiple
`Vm::new` calls (router, pair, and underlying SAC token wasms when not on the
native-emulation fast path). Each call re-walks the imports table and
re-checks protocol bounds despite the inputs being unchanged across calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` —
  `check_contract_imports_match_host_protocol` is invoked on every `Vm::new`
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:171` — `Vm::new` call site
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` —
  candidate cache: `OnceCell<u32>` (last-checked ledger_proto) on
  `ParsedModule` storing the verified `ledger_proto`; check is a single
  compare-and-skip when reused within the same ledger

## Evidence

Tracy soroswap trace shows zone
`ParsedModule::check_contract_imports_match_host_protocol`
(`parsed_module.rs:423`) with `total_ns = 91,303,086`, `counts = 7,956`,
`mean_ns ≈ 11,476`. The proto_version and ledger_proto are both effectively
constant across the benchmark (same protocol throughout) so the check returns
the same result on every call.

## Anti-Evidence

The `ParsedModule` is shared across worker threads through the
`SorobanModuleCache` (`src/rust/src/soroban_module_cache.rs`), so a per-module
cache field would require interior mutability and synchronization — but a
`OnceCell<u32>` or `AtomicU32` suffices since the verified-ledger-proto value
is monotonic within a ledger and idempotent under races. The check is also
deliberately performed every time as defense-in-depth against future
multi-proto host scenarios (see code comment at lines 407-422 explaining the
link-time vs run-time tradeoff).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — this specific cache target (the protocol-gating import
walk) has not been previously hypothesized; distinct from rejected
`009-cache-per-vm-export-function-handle.md` (which targets export-symbol
lookup, not import-protocol gating) and from the InstancePre meta-pattern
(`Meta-Pattern 3`).

### Why It Failed

Total Tracy self-time for the zone is 91.3 ms across the full process trace.
Normalizing to per-ledger apply-window impact, with 8 cluster workers and
43 ledgers covered by the trace:

    91.3 ms / 8 workers / 43 ledgers ≈ 0.265 ms/ledger ≈ 0.12% of 218 ms

Even with full elimination of the function (returning `Ok(())` unconditionally
after the first call per ledger), the recoverable wall-clock saving is
~0.12%/ledger — an order of magnitude below the 1% Low floor and well below
the 3% Medium objective threshold. This matches the established pattern that
per-Vm-instantiation sub-zones inside `Vm::instantiate_wasmi`
(total 460 ms / 8 / 43 = 1.34 ms/ledger ≈ 0.6%, itself sub-Low) cannot host
Medium-tier wins after cluster normalization — see also retained fail
`016-wasmi-linear-memory-vec-allocation.md` which establishes that sub-cost
breakdowns of `Vm::instantiate_wasmi` are individually sub-Medium without a
per-sub-zone Tracy breakdown demonstrating otherwise.

Additionally, the cache-design complications (synchronized mutation of a
shared `Arc<ParsedModule>` across cluster worker threads, monotonic
ledger-proto invalidation across protocol-upgrade ledgers, preserving the
diagnostic-event semantics on rejection) carry non-trivial review risk in a
pinned `soroban-env-host` crate. The combined risk/reward inverts the
proposal.

### Lesson Learned

Per-Vm-instantiation sub-cost zones in soroban-env-host must each clear the
Low floor on their own normalized per-ledger contribution before being
considered viable. The accepted rule of thumb is:

    apply_window_ms/ledger = total_zone_ns_in_trace
                             / NUM_CLUSTERS
                             / N_ledgers_covered

For the soroswap trace at hand, NUM_CLUSTERS=8 and N_ledgers≈43, so any
parallel-apply Vm-instantiation sub-zone with total_zone_ns < ~2.3 s
(≈ 3% × 218 ms × 8 × 43) cannot individually be Medium. This extends
Meta-Pattern 14 to per-Vm-instantiation sub-zones inside the parallel apply
phase, and complements Meta-Pattern 3 (InstancePre not reusable) by ruling
out import-check elision as a separate Medium-tier path.
