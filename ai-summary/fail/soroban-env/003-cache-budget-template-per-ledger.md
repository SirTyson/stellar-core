# H003: Cache Parsed Budget Template Per-Ledger to Skip Per-Invoke Cost-Param Decode and BudgetDimension Rebuild

**Date**: 2026-04-27
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing repeated XDR cost-param decode and BudgetDimension construction on every Soroban invocation

**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ContractCostParams` are part of the network configuration and are constant
within a single ledger close (and across many ledgers, since they only change
when the network config is upgraded). For a soroswap apply ledger that runs
~4,000 Soroban invocations in the same `closeLedger`, the host should
deserialize the cpu/mem cost params at most once per ledger (or once per
config change), reuse the parsed `BudgetDimension` cost-model arrays as a
template, and only allocate per-invocation the small mutable Budget state
(per-cost-type tracker counters, remaining/limit, shadow flag). The 80
`MeteredCostComponent::try_from(ContractCostParamEntry)` conversions and the
two XDR decodes of `ContractCostParams` should not be on the per-tx hot path.

## Mechanism

`invoke_host_function_or_maybe_panic` calls `Budget::try_from_configs`
unconditionally for every invocation, which (a) calls
`non_metered_xdr_from_cxx_buf::<ContractCostParams>` on
`ledger_info.cpu_cost_params` and `ledger_info.mem_cost_params`, then (b)
constructs two fresh `BudgetDimension`s by iterating all
`ContractCostParams.0` entries and converting each to a
`MeteredCostComponent`, and (c) calls `load_calibrated_fuel_costs()`. The
cpu and mem `CxxBuf`s are already cached per-ledger per-thread on the C++
side via `getCachedLedgerInfo` (see `InvokeHostFunctionOpFrame.cpp:75-94`),
so the underlying bytes are bit-identical for every invocation in a ledger.
Despite that, the Rust side re-decodes them and rebuilds 2 × ~40 cost models
on every invoke. Replacing this with a per-ledger cached parsed Budget
template (e.g. cached on `SorobanModuleCache` or in a thread-local keyed by
the cost-params byte hash / ledger seq, with per-invoke cloning of just the
mutable counters and limits) eliminates this redundant work without
changing protocol-visible budget semantics, since the deterministic cost
models and limits are unchanged.

## Trigger

Run the current `soroswap, TX=4000, T=8` apply-load benchmark from
`ai-summary/CURRENT_STATE.md`. The trigger is a high-volume Soroban
apply ledger where each of ~4,000 invoke-host-function operations
re-decodes the same cpu/mem cost-param XDR and rebuilds both
`BudgetDimension` cost-model arrays from scratch.

## Target Code

- `src/rust/src/soroban_proto_any.rs:412-420` — `Budget::try_from_configs`
  is called per-invocation with two `non_metered_xdr_from_cxx_buf`
  decodes of `ContractCostParams`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1263-1289` —
  `Budget::try_from_configs` wraps `BudgetImpl::try_from_configs` in a
  fresh `Rc<RefCell<…>>`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:208-224` —
  `BudgetImpl::try_from_configs` builds two fresh `BudgetDimension`s.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:73-94` —
  `BudgetDimension::try_from_config` iterates all cost-param entries and
  calls `MeteredCostComponent::try_from(cp)` on each (~40 per dimension).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-94` — C++ caches the
  full `CxxLedgerInfo` (including cpu/mem cost-params CxxBufs) per
  `ledgerSeq` in a `thread_local`, so the input bytes are already
  guaranteed identical within a ledger.
- `src/rust/src/soroban_module_cache.rs:54-60` — `SorobanModuleCache`
  already crosses the bridge by reference and is the natural place to
  attach a per-protocol parsed-budget template that survives across
  invocations.

## Evidence

The current soroswap Tracy trace
(`/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`)
reports `applyLedger` total time 4,591,086,908 ns over 65 ledgers and
`invoke_host_function_or_maybe_panic` total time 4,809,566,233 ns over
1,562 calls. The `invoke_host_function` (e2e) zone reports 186,583,657 ns
self-time across 1,562 calls (~119 µs of self-time per call), which
captures the wrapper work done outside of named child zones: budget
construction, XDR decodes, host setup, and result encoding. The
`Budget::try_from_configs` path is performed unconditionally on every one
of those 1,562 invocations and is structurally O(num cost types) =
~40 `MeteredCostComponent` constructions per dimension, twice per call,
plus two non-metered XDR decodes.

The C++ side already evidences that the input bytes are constant within a
ledger: `getCachedLedgerInfo` caches the full `CxxLedgerInfo`
(including the cpu/mem cost-param `CxxBuf`s) per `ledgerSeq` in a
`thread_local`, only rebuilding when the ledger sequence changes. The
Rust bridge is the asymmetric end of the cache and is the location where
the per-invocation work can be eliminated. Soroswap's 4,000 invocations
per ledger amplifies this fixed-cost work into the apply path.

## Anti-Evidence

- `Budget` is held inside `Host` as `Rc<RefCell<BudgetImpl>>`, so a
  cached "template" cannot be shared by reference across simultaneous
  invocations on different threads without cloning. The per-invoke
  payoff therefore depends on cloning the precomputed cost-model arrays
  being meaningfully cheaper than rebuilding them from an XDR decode.
- Cost-params XDR is small (~40 entries × ~16 bytes ≈ 640 bytes per
  dimension), and `MeteredCostComponent::try_from(ContractCostParamEntry)`
  is a few `i64`/`u64` field copies. Each per-invoke savings is on the
  order of single microseconds; the Medium threshold (3-10% apply-time
  reduction) requires this to multiply out to ~15-60 ms across ~4,000
  invocations per soroswap ledger. PoC must measure and reject if the
  delta is below noise.
- The cache must invalidate cleanly when the network config upgrades
  cost params (rare, but happens at protocol bumps). Keying the cache
  by a hash of the cost-param bytes is the safest invariant.
- Budget construction also calls `load_calibrated_fuel_costs()`, which
  is already a constant table; that part is essentially free and not
  the optimization target.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The per-invocation waste exists: every `InvokeHostFunctionOpFrame` apply path calls the Rust bridge, and `invoke_host_function_or_maybe_panic` decodes both cost-param buffers and constructs a fresh `Budget` before entering `e2e_invoke`. The C++ side caches the serialized `CxxLedgerInfo` per ledger sequence, so the Rust decode/build input is indeed stable across invocations in a ledger. However, the hypothesis's own trace places all un-nested wrapper self-time, including budget construction plus unrelated host setup and result encoding, at only 186.6 ms out of 4.59 s apply time (~4.1%). The targeted cost-param decode and budget-dimension rebuild are only a subset of that wrapper work and therefore do not clear the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-94` — `buildLedgerInfo` serializes CPU/memory cost params into `CxxBuf`s, and `getCachedLedgerInfo` caches the full `CxxLedgerInfo` per `ledgerSeq` in thread-local storage.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — each operation apply calls `rust_bridge::invoke_host_function` with the cached ledger info and shared module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1260-1279,1358-1377` — the parallel Soroban apply path reaches the same helper and bridge call during `closeLedger`.
- `src/rust/src/soroban_proto_any.rs:310-341,391-420` — the bridge wrapper catches panics, then unconditionally decodes CPU and memory `ContractCostParams` and calls `Budget::try_from_configs` before `e2e_invoke`.
- `src/rust/src/soroban_proto_any.rs:136-147` — `non_metered_xdr_from_cxx_buf` reads XDR from the C++ byte buffer with fixed limits, so the per-call decode is real.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:197-224,1261-1275` — `Budget::try_from_configs` allocates a fresh `Rc<RefCell<BudgetImpl>>`; `BudgetImpl::try_from_configs` builds CPU and memory dimensions, a default tracker, fuel costs, and depth limit.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:73-94` — each `BudgetDimension` starts from default cost models and overwrites them by iterating the decoded cost-param entries.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:88-113` — each `MeteredCostComponent` conversion is a small validation and field copy.
- `src/rust/soroban/p26/soroban-env-host/src/budget/wasmi_helper.rs:104-115` — `load_calibrated_fuel_costs` is a tiny constant initialization, not a meaningful optimization target.
- `src/rust/src/soroban_module_cache.rs:22-60` — `SorobanModuleCache` is shared across invocations and could carry a cache, but using it would not change the impact bound.

### Why It Failed

The optimization target is real but below the objective severity threshold. Even an impossible best case that removed all `invoke_host_function` wrapper self-time would be roughly 4.1% in the cited trace, while the proposed change can only remove the two small XDR decodes and cost-model construction inside that wrapper. A correct implementation would still need fresh per-invocation mutable budget state (`Rc<RefCell<BudgetImpl>>`, `BudgetTracker::default`, limits, totals, shadow state, and likely cloned or separately owned cost-model arrays), so the realizable top-line apply-time reduction is projected below Medium and likely Low or sub-noise.

### Lesson Learned

For optimize-soroswap, a repeated per-invocation allocation/decode is not enough by itself: the removable subset must be large enough relative to `applyLedger`. When the entire enclosing self-time zone barely reaches the 3-10% acceptance band, a small sub-operation inside it should be rejected unless profiling isolates that sub-operation as most of the zone.
