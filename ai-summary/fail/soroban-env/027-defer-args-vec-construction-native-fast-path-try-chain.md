# H027: Defer `args_vec` Construction Past Native Soroswap Fast-Path Try Chain

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Low (sub-noise after parallelism)
**Impact**: Allocator-pressure micro-reduction in `Host::call_contract_fn`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::call_contract_fn` (p26 `host/frame.rs:783-838`) should physically
allocate the owned `Vec<Val>` of call arguments exactly once, in the branch
that actually consumes it (the matching native Soroswap pool getter, the
native pool swap path, or the fall-through `Frame::ContractVM`). Calls that
do not match a native fast-path (e.g., the Soroswap router Wasm and any
non-pool contract) should pay only the one metered
`Vec::<Val>::charge_bulk_init_cpy` charge and the single `args.to_vec()`
allocation that the `Frame::ContractVM` branch ultimately needs.

## Mechanism

The current implementation calls
`Vec::<Val>::charge_bulk_init_cpy(args.len(), self.as_budget())?` once
(line 793) and then performs `args.to_vec()` (line 794). It then passes
`args_vec.clone()` into `try_call_native_soroswap_pool_getter` (line 801)
and `args_vec.clone()` into `try_call_native_soroswap_pool_swap` (line 811).
Both `.clone()` calls allocate a fresh backing buffer and `memcpy` the args
*before* the cheap gate inside each `try_call_*` (protocol gate, wasm-hash
compare, symbol/arg-shape check) has the chance to short-circuit. For every
non-pool contract call (router Wasm, non-Soroswap Wasm) the `wasm_hash !=
SOROSWAP_POOL_WASM_HASH` early-out at line 855 / equivalent in swap rejects
the call after both clones have already been heap-allocated and dropped.
The actual budget is only charged once, so the two extra clones are
*unmetered physical work* — removable without touching protocol-visible
budget accounting.

## Trigger

Apply-load `soroswap` scenario (`TX=2000,T=8`): every per-swap call chain
includes a router Wasm invocation whose `wasm_hash` is not the pool hash,
producing two wasted `Vec<Val>::clone()` allocations and frees per call.
The pair `swap` call (which does match) also pays one wasted clone for the
getter probe that precedes the swap probe.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838`
  (`call_contract_fn`) — the two `args_vec.clone()` sites at lines 801 and 811.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-871`
  (`try_call_native_soroswap_pool_getter`) — could accept `&[Val]` and
  build the owned `Vec` only on a confirmed match.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:797-816`
  (the dispatch call sites that pre-clone).

## Evidence

`add_host_object` and small `Vec` heap allocations dominate ~100K-event
zones in the soroswap Tracy trace; the structure of the code clearly does
2 extra (unmetered) `Vec<Val>` clones per non-matching contract dispatch
and 1 extra per matching `swap` dispatch.

## Anti-Evidence

The actual per-call physical cost of a `Vec<Val>::clone` over 3–8 elements
is small (≈50–100 ns including allocation + memcpy + drop): the args slice
is small for the Soroswap call shapes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not present in existing fail/hypothesis/reviewed/poc directories

### Why It Failed

Per-swap wasted-clone count is 3 (router: 2, pair-swap: 1; SAC calls take
the `StellarAssetContract` branch at line 830 and bypass the try-native
sites entirely). With ~7000 swaps per benchmark window, 8-way cluster
parallelism, and ~71 measured ledgers:

  3 clones × 7000 swaps × ~85 ns/clone = ~1.8 ms aggregate self-time.
  Wall: 1.8 ms / 8 workers / 71 ledgers ≈ 0.003 ms/ledger ≈ 0.0015 % of the
  211 ms soroswap apply baseline.

This is roughly three orders of magnitude below the 1 % benchmark-noise
floor and four orders of magnitude below the 3 % Medium threshold this
objective requires. Even adding allocator-pressure side effects (cache
churn, malloc arena traversal) cannot plausibly close that gap.

### Lesson Learned

Native-fast-path try-chains that pre-allocate per-call owned arguments
"just in case" the cheap gate succeeds are a real but tiny inefficiency:
unmetered `Vec` clones for small arity (3–8 elements) cost ≈100 ns
including alloc/memcpy/drop and rarely accumulate to even 0.01 % of
soroswap apply after the standard `count × cost / parallelism / ledgers`
normalization. Future "defer the clone past the gate" hypotheses should
not be proposed for sub-microsecond per-call work unless the call count is
in the tens of millions per ledger, well above the call-chain volume of a
single 7000-swap benchmark window.
