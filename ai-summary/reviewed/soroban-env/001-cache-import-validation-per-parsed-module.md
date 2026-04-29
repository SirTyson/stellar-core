# H001: Cache `check_contract_imports_match_host_protocol` validation per ParsedModule

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Apply-time reduction by eliminating per-invocation BTreeSet construction and HOST_FUNCTIONS scan inside `Vm::instantiate_wasmi`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Per-host-invocation VM instantiation should re-validate that the contract's
imported host functions are protocol-compatible with the *current* ledger
protocol, but should not redo work whose answer cannot have changed since the
contract module was first parsed and cached. Specifically: for a given
`(ParsedModule, ledger_proto)` pair, the
`check_contract_imports_match_host_protocol` outcome is a pure function of
immutable inputs (the module's import section, the module's
`proto_version`, the constant `HOST_FUNCTIONS` table, and the ledger
protocol). Within a single `closeLedger` window the ledger protocol is
constant for *all* invocations, and the module's import section never
changes after parsing. So after the first successful validation under the
ledger's protocol, every subsequent invocation should re-charge the
protocol-visible budget for symbol enumeration (`Vec::charge_bulk_init_cpy`)
and otherwise short-circuit; it should not re-walk
`wasmi_module.imports()`, re-build a `BTreeSet<(&str, &str)>`, or re-iterate
the ~200-entry `HOST_FUNCTIONS` array doing one `BTreeSet::contains` per
entry.

## Mechanism

`Vm::instantiate_wasmi` (vm.rs:155-187) calls
`parsed_module.check_contract_imports_match_host_protocol(host)?`
unconditionally on every host invocation, even on the cache-hit path where
the same `Arc<ParsedModule>` is used many times within a single ledger
close. That function (parsed_module.rs:403-454) calls
`with_import_symbols`, which iterates `wasmi_module.imports()`, allocates a
fresh `BTreeSet<(&str, &str)>` of imported `(module, name)` symbols (with
the protocol-visible
`Vec::<(&str, &str)>::charge_bulk_init_cpy(symbols.len() as u64, host)?`
charge), then iterates the entire `HOST_FUNCTIONS` array doing
`module_symbols.contains(...)` for each entry. The actual answer cannot
change for the cached `(ParsedModule, ledger_proto)` pair, but the work is
repeated 10,061 times in the soroswap apply window. By caching the
already-computed BTreeSet (or the validation outcome itself) on
`ParsedModule` after first construction and re-charging the same per-call
budget without rebuilding the set, we remove the BTreeSet allocation/sort,
the wasmi imports iteration, and the HOST_FUNCTIONS scan from every
subsequent invocation while preserving exact protocol-visible budget
totals.

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, scenario `soroswap, TX=2000, T=8`) and
inspect the longest `applyLedger` interval in the diagnostic Tracy trace
referenced from `ai-summary/CURRENT_STATE.md`. Inside that window
`ParsedModule::check_contract_imports_match_host_protocol`
(`soroban-env-host/src/vm/parsed_module.rs:423`) appears 10,061 times for
112.584 ms self-time, called from `Vm::instantiate_wasmi`
(`soroban-env-host/src/vm.rs:160`) which itself appears 10,061 times — i.e.
once per host invocation, all during apply.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` —
  `Vm::instantiate_wasmi` calls `check_contract_imports_match_host_protocol`
  unconditionally per invocation; replace with a fast-path that uses cached
  validation state.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:149-152` —
  `ParsedModule` struct: add a small per-module cache (e.g.
  `validated_imports: OnceLock<Arc<BTreeSet<(String, String)>>>` plus
  `validation_proto: AtomicU32` initialized to `u32::MAX`).
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-263` —
  `with_import_symbols` rebuilds the BTreeSet on every call; cache it on
  first build and reuse. Preserve the protocol-visible
  `Vec::charge_bulk_init_cpy(symbols.len() as u64, host)?` charge by storing
  `symbols.len()` and re-charging it from the cached value.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` —
  `check_contract_imports_match_host_protocol`: add a fast-path check
  `if self.validated_imports.get().is_some() && cached_proto == ledger_proto
  { recharge_budget_only_and_return_ok }`. The HOST_FUNCTIONS scan only needs
  to run once per `(self, ledger_proto)`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` —
  `parse_and_cache_module`: optionally pre-warm the validation here (the
  cache build path) so the very first invocation is also fast.

## Evidence

- Tracy scope check: the cited 112.584 ms self-time / 10,061-call zone is a
  descendant of `applyLedger`. `Vm::instantiate_wasmi` (10,061 calls) is
  called from `Vm::from_parsed_module_and_wasmi_linker` (vm.rs:191-218) →
  `Host::instantiate_vm` (frame.rs:787-901, the cache-hit branch at
  lines 789-803) → contract-call `with_frame` (frame.rs:760-784) →
  `invoke_host_function` → `parallelApply` → `applyLedger`.
- All 10,061 invocations in the trace go through the module cache (the
  benchmark uses `--enable-tracy` with the standard `ModuleCache` populated
  from `add_stored_contracts`); the cache-hit path at frame.rs:789-803 is
  the dominant code path.
- The work being repeated is provably constant: `wasmi_module.imports()` is
  immutable for an `Arc<ParsedModule>`; `HOST_FUNCTIONS` is a `static`
  array; the only varying input within a `closeLedger` is `ledger_proto`,
  which is also constant within a single ledger close.
- The protocol-visible budget charge is just
  `Vec::<(&str, &str)>::charge_bulk_init_cpy(symbols.len() as u64, host)`
  (parsed_module.rs:261), a `MemCpy` charge with input
  `n_imports * size_of::<(&str, &str)>()`. We can preserve it bit-exactly
  by storing `symbols.len()` once and re-charging `MemCpy` with the same
  input on every subsequent call.
- Per-call cost is ~11.2 µs (112 ms / 10k calls). Removing the BTreeSet
  build, wasmi imports walk, and HOST_FUNCTIONS scan should drop this to
  the cost of one `MemCpy` charge plus a handful of pointer/atomic
  comparisons — order-of-magnitude reduction. Wall-clock impact at
  `NUM_CLUSTERS=8` parallelism: ~14 ms saved per ledger close, ~4.6 % of
  the 305 ms soroswap baseline → clears the Medium 3 % floor.
- The same `with_import_symbols` is also called from `make_wasmi_linker`
  (parsed_module.rs:265-269) on the cache-miss path, so caching helps the
  rare upload-and-run case as well, but the soroswap win is dominated by
  the cache-hit per-invocation savings.

## Anti-Evidence

- The protocol-visible `Vec::charge_bulk_init_cpy` charge must be
  re-applied on every call to preserve `cpu_insns`/`mem_bytes` totals;
  any cached-fast-path implementation must store `symbols.len()` and
  re-charge identically. Tests `budget_metering::*` and `e2e_tests::*` will
  fail otherwise.
- `OnceLock` adds a small atomic load on every fast-path call. The
  expected per-call savings (~10 µs) dwarf an atomic acquire (~1 ns), so
  this is a non-issue.
- `ParsedModule` is wrapped in `Arc` and shared across worker threads
  (the module cache uses `Arc<Mutex<BTreeMap<Hash, Arc<ParsedModule>>>>`).
  Any added cache field must be `Send + Sync`. `OnceLock<Arc<BTreeSet<...>>>`
  satisfies this; an `AtomicU32` for the validated-protocol marker also
  works. Avoid `RefCell` — it is not `Sync`.
- The fast-path must still detect protocol mismatch. The validated-protocol
  marker (default `u32::MAX`) ensures the slow path runs whenever
  `cached_proto != ledger_proto`, so a hypothetical replay against a
  different protocol still re-validates correctly.
- A naive cache that stores `BTreeSet<(&'static str, &'static str)>` from
  borrowed wasmi module slices will not compile (lifetime tied to module
  imports). Use `BTreeSet<(String, String)>` or store import-symbol indices
  into a `Vec<(String, String)>` once at construction.
- Non-Tracy builds will still show real savings: the work is *not*
  Tracy-instrumentation overhead — `wasmi_module.imports()` walks heap
  data, `BTreeSet::insert` does real allocations and comparisons, and the
  HOST_FUNCTIONS loop does real string comparisons. Per the meta-pattern
  on Tracy zones, this is a heavy-real-work zone (11 µs/call), not a
  sub-microsecond instrumentation zone.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The cache-hit contract call path in `Host::instantiate_vm` retrieves an `Arc<ParsedModule>` from the shared `ModuleCache` and immediately calls `Vm::from_parsed_module_and_wasmi_linker`, which calls `Vm::instantiate_wasmi`. `instantiate_wasmi` unconditionally invokes `ParsedModule::check_contract_imports_match_host_protocol` before every wasmi instantiation, even though the module's import section and `proto_version` are immutable and the ledger protocol is constant during one `closeLedger`. The validation currently rebuilds a fresh import-symbol `BTreeSet`, charges the same bulk-init metering, and scans the static `HOST_FUNCTIONS` table on every invocation.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — contract calls instantiate a VM for Wasm executables before pushing the `ContractVM` frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-901` — module-cache hits clone the cached `Arc<ParsedModule>` and call `Vm::from_parsed_module_and_wasmi_linker`; cache misses parse a throwaway module.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` — `Vm::instantiate_wasmi` charges instantiation costs and always calls `check_contract_imports_match_host_protocol` before linker instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:149-153` — `ParsedModule` stores only immutable `wasmi_module`, `proto_version`, and cost inputs today, so there is no existing import-validation cache.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-263` — `with_import_symbols` walks `wasmi_module.imports()`, builds a new `BTreeSet<(&str, &str)>`, and charges `Vec::<(&str, &str)>::charge_bulk_init_cpy` for every caller.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` — import protocol validation reads `ledger_proto`, uses the freshly built symbol set, and scans every `HOST_FUNCTIONS` entry for min/max protocol gating.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:160-183` and `src/rust/src/soroban_proto_any.rs:723-737` — reusable module caches store `Arc<ParsedModule>` values across invocations, making per-module cached immutable data safe to reuse.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:102-129` — minimal linkers also scan `HOST_FUNCTIONS` against import symbols, while the cache-hit path uses the maximal linker already stored in `ModuleCache`.

### Findings

The inefficiency exists on the stated hot path. Cached contract execution still performs the import-validation pass once per VM instantiation, and soroswap invokes this path thousands of times inside apply. The repeated physical work is not protocol-visible except for the explicit `Vec::<(&str, &str)>::charge_bulk_init_cpy(symbols.len() as u64, host)` call; a fast path can preserve exact budget totals by reissuing that charge from a cached import-symbol count before returning the cached successful validation result.

The optimization is correctness-preserving if the cache is keyed by the ledger protocol and is only populated after successful validation. `wasmi_module.imports()`, `ParsedModule::proto_version`, and `HOST_FUNCTIONS` are immutable for a given protocol-specific host binary; the only runtime input is `ledger_proto`. The proposed implementation must use `Send + Sync` storage such as `OnceLock`/atomics because `ParsedModule` is shared via `Arc` across the module cache, and it should avoid changing the externally observable error behavior for first validation under a new protocol.

The projected impact clears this objective's Medium threshold. The cited trace attributes 112.584 ms self-time to this validation over 10,061 apply-window calls; even after accounting for parallelism, skipping the BTreeSet rebuild, import iteration, and table scan after first validation plausibly saves roughly 3-5% of the current soroswap apply baseline. This is distinct from the prior failed `InstancePre` caching investigation: that attempted to reuse per-store wasmi instantiation state, while this caches only immutable module import metadata and a pure validation result.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs` for the `ParsedModule` fields and validation/import-symbol helpers; `src/rust/soroban/p26/soroban-env-host/src/vm.rs` should continue to call the validation entry point; update `make_wasmi_linker`/`make_minimal_wasmi_linker_for_symbols` only as needed to consume the cached symbol representation.
- **Change description**: Cache owned import-symbol metadata on `ParsedModule` once, store the import count needed to reproduce the existing `Vec::<(&str, &str)>::charge_bulk_init_cpy` charge, and record the last ledger protocol that successfully passed `check_contract_imports_match_host_protocol`. On fast-path hits for the same ledger protocol, re-charge the bulk-init cost and return without rebuilding the `BTreeSet` or scanning `HOST_FUNCTIONS`.
- **Correctness check**: Existing Soroban host tests that assert budget totals and e2e invocation behavior should continue to pass, especially `budget_metering::*`, `e2e_tests::*`, lifecycle/module-cache tests, and hostile/invalid-Wasm tests that exercise missing, unsupported, or protocol-gated imports.
- **Benchmark focus**: Run non-Tracy `scripts/run_apply_load_matrix.py` multiple times and compare soroswap median apply time; the expected signal is removal of nearly all physical self-time from `ParsedModule::check_contract_imports_match_host_protocol` after the first invocation per `(ParsedModule, ledger_proto)`, translating to an estimated 3-5% soroswap apply-time reduction if the trace attribution holds.
