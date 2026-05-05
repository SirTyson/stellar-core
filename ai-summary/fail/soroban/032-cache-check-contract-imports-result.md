# H032: Cache `check_contract_imports_match_host_protocol` result and `with_import_symbols` BTreeSet on `ParsedModule`

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Low
**Impact**: per-VM-instantiation CPU on the apply hot path (Soroban host VM construction)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ParsedModule::check_contract_imports_match_host_protocol`
(`src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454`)
is a pure function of the immutable `wasmi_module` it owns plus the
ledger protocol version. For a given `ParsedModule` cached in the
`ModuleCache` (each `ParsedModule` is wrapped in `Arc<Self>` and
the proto_version inside it is fixed at parse time), the answer is
deterministic and identical for every invocation that targets the
same ledger protocol. After the first successful check, subsequent
calls in the same ledger should be O(1) cache lookups, not a
full HOST_FUNCTIONS × wasm-imports cross product re-scan.

Likewise, `ParsedModule::with_import_symbols`
(`parsed_module.rs:230-263`) builds a fresh
`BTreeSet<(&str, &str)>` from `wasmi_module.imports()` on every
invocation. For a cached `ParsedModule`, this set is also fixed
and could be computed once and reused.

## Mechanism

`Vm::new` (`vm.rs:169`) calls
`parsed_module.check_contract_imports_match_host_protocol(host)?` on
every VM instantiation. The check iterates every entry of `HOST_FUNCTIONS`
(~250 host functions in p26), probes a freshly-built `BTreeSet` with
`module_symbols.contains(&(hf.mod_str, hf.fn_str))`, and on each match
evaluates protocol gating. `make_wasmi_linker` (`parsed_module.rs:265`)
also calls `with_import_symbols`, so each VM instantiation rebuilds the
import set twice. For soroswap, the same handful of contract modules
(swap router + a few token contracts) is reused across ~2000
transactions per ledger, so this work is structurally redundant.

A `OnceCell<()>` for the check result and a `OnceCell<BTreeSet<(String,String)>>`
(or `OnceCell<Arc<BTreeSet<...>>>` to preserve borrow semantics) for the
symbols on `ParsedModule` would reduce both checks to single
relaxed-atomic loads after the first call.

## Trigger

Run the soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on a
next-protocol build. Each successful swap constructs at least one
`Vm` per Soroban op, and each construction re-runs the import check
plus two `with_import_symbols` rebuilds.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:149-228` —
  `ParsedModule` struct: needs to gain `OnceCell` fields for the cached
  results.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:230-263` —
  `with_import_symbols`: candidate to short-circuit via cached set.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-454` —
  `check_contract_imports_match_host_protocol`: candidate to short-circuit
  via cached `Ok(())` after first successful call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::new`
  call site that invokes the check on every instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:54-95` —
  `ModuleCache` ownership of `Arc<ParsedModule>` confirms the same
  instance is reused across ledgers.

## Evidence

The current accepted soroswap trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`)
shows `ParsedModule::check_contract_imports_match_host_protocol` consuming
**224,014,414 ns total / 20,389 calls (≈11 µs/call), 2.17 % of total Tracy
time**. The Tracy trace also shows ~20,389 `Vm::instantiate_wasmi` calls,
matching one `check_contract_imports` call per VM instantiation.

The check is structurally redundant: for the soroswap workload there are
only a handful of distinct contract modules but each is invoked thousands
of times per ledger, and each `Vm::new` re-runs the same protocol gating
calculation against the same imports.

## Anti-Evidence

The Tracy total is 224 ms across 71 ledgers and 8 worker threads.
Worker-normalized wall-clock contribution is roughly
`224 ms / 71 ledgers / 8 workers ≈ 0.4 ms/ledger`, or
**~0.14 % of the 272 ms baseline** — below the 1 % noise floor and
far below the 3 % Medium threshold. Even adding the
`with_import_symbols` BTreeSet rebuild work (which appears to be a
small additional cost not visible as a separate Tracy zone) cannot
plausibly push the savings above 1 % of apply time. Caching also
introduces a `Sync` requirement on the cache fields and risks
breaking metering boundaries if the charge for `Vec::charge_bulk_init_cpy`
on line 261 was relied on as a per-call observation point.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in retained Soroban fail/success records

### Why It Failed

The optimization is correctness-plausible but the worker-normalized
wall-clock impact is well below the optimize-soroswap Medium floor
(3 %), and indeed below the 1 % objective noise floor. Per the
SEVERITY_SCALE provided in the objective context, only Medium and
High severity hypotheses are accepted at the hypothesis stage.
Caching this specific check is a clean Low-to-imperceptible
improvement that does not justify the metering-surface risk.

### Lesson Learned

Per-VM-instantiation cleanup work in `ParsedModule` looks attractive
(11 µs/call × 20,389 calls in Tracy) but normalizes to sub-1 % when
divided by `NUM_CLUSTERS=8` worker threads and 71 ledgers, because
the work is fully parallelized across Soroban apply workers and the
absolute Tracy total is small. Future hypotheses targeting per-VM
overheads must clear ≥ 2.3 s of total parallel-worker Tracy time
before they can plausibly reach the 3 % Medium threshold (since
2.3 s / 8 / 71 ≈ 4 ms/ledger ≈ 1.5 % wall, and additional factors
typically halve realistic savings).
