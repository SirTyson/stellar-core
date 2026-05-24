# H008: Cache Native Soroswap Swap Event Topic Symbols And Static Key Symbols Across Swaps

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-swap host object allocation for constant event topic and data-key symbols
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`call_native_soroswap_pool_swap`
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1336-1373`) emits a
single `SwapEvent` per swap whose topics are the two fixed symbols
`Symbol("SoroswapPair")` and `Symbol("swap")`, and whose data map uses five
fixed string keys (`"amount_0_in"`, `"amount_0_out"`, `"amount_1_in"`,
`"amount_1_out"`, `"to"`). Both `SoroswapPair` and `swap` exceed the
nine-character `SymbolSmall` limit / are encoded as `SymbolObject`s
(`SoroswapPair` is 12 chars), so each call to `symbol_new_from_slice`
allocates a new `ScSymbol` host object via `add_host_object`.

The expected behavior for a hot, statically-known event shape is to
precompute these constant host-side symbol objects once per host invocation
(or once per process) and reuse the same `Val` handles per swap, instead
of reallocating them on every swap.

## Mechanism

Each native swap calls:

- `self.symbol_new_from_slice(b"SoroswapPair")` — 12 bytes, allocates
  `ScSymbol` host object (charges `MemCmp(12)`, validates each byte,
  charges `MemCpy(12)`, pushes onto `Host.objects`).
- `self.symbol_new_from_slice(b"swap")` — 4 bytes, fits `SymbolSmall` so
  this one is small-encoded with no host-object allocation.
- `self.vec_new_from_slice(&[topic_pair.to_val(), topic_swap.to_val()])`
  — allocates a 2-element `HostVec`.
- `self.map_new_from_slices(&keys, &vals)` — the 5 string keys are each
  passed through `Symbol::try_from_val` (`host.rs:1057`), which dispatches
  to small/object encoding. Keys `"amount_0_in"` etc. are 11-12 chars and
  exceed `SymbolSmall`'s nine-char limit, so each allocates a new
  `ScSymbol` host object. The 5-element `(Val, Val)` vector is then sorted
  and used to construct a `HostMap`.

So per swap, the event-emission path performs at minimum 6 host-object
allocations (1 for `SoroswapPair`, 5 for the data keys, 1 for the topics
`HostVec`, 1 for the data `HostMap` — 8 total host objects, of which the
6 symbol/topic objects carry constant byte content). At 2,000 swap txs
per ledger, that's ~12,000 redundant host-object allocations / ledger
that could be served by precomputed handles.

## Trigger

Run the protocol-27 soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`). Each accepted native pool swap
that reaches the K-invariant check emits a SwapEvent through this code
path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1344-1373` —
  per-swap event topic / data key allocation.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1021-1066` —
  `symbol_new_from_slice` and `map_new_from_slices` implementations.

## Evidence

Source reading confirms 6 symbol allocations and 2 container allocations
per swap. The 6 symbol byte contents are identical across all swaps in
all ledgers, making the work structurally redundant.

## Anti-Evidence

All allocations are metered: `MemCmp`, `MemCpy`, and the
`charge_heap_alloc` invocations inside `add_host_object` are
protocol-visible. Removing them changes the per-tx CPU and memory
budget consumed, which is a consensus-relevant observation. Per
Meta-Pattern #12 (metering is protocol-visible), any change that drops
charges must be protocol-gated.

The constant symbols would need to live somewhere with a lifetime
broader than a single `Host`, since per-invocation `Host` instances
are constructed fresh per tx. A static `OnceCell<Val>` is not viable
because `Val` is a per-`Host` handle into that host's object table —
the handle is not portable across hosts. A per-`Host` cache built at
`Host::new` time pays the same allocation cost up-front; net saving
is zero unless the cache is amortized across multiple host
invocations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a swap-event-specific
optimization. Fail `012-pre-intern-native-pair-event-symbols.md` covers
swap-event symbol pre-interning broadly; this hypothesis is the same
optimization family at a finer call-site granularity. Treat as a duplicate
sub-class of fail #012.

### Why It Failed

Sizing:

- Per swap: 6 symbol-allocation events (5 data-key symbols + 1 topic
  symbol `SoroswapPair`; `swap` is `SymbolSmall`). The two container
  allocations (`HostVec` of topics, `HostMap` of data) cannot be reused
  because they hold per-swap data values.
- Per-allocation cost: ~50 ns (charge + push to `objects` Vec; the
  `metered_slice_to_vec` for ≤12-byte symbols hits the small-buffer
  fast path).
- Per ledger: 2,000 swaps × 6 = 12,000 redundant allocations × ~50 ns
  = ~0.6 ms aggregate worker CPU.
- After 8-way cluster parallelism normalization: ~0.075 ms / ledger
  = ~0.035 % of the 211 ms soroswap median baseline.

Even the most optimistic per-allocation cost estimate (~200 ns including
the byte-validate loop) tops out at ~0.3 ms / ledger after parallelism
normalization — three orders of magnitude below the 3 % Medium floor.

Adjacent fail records that bound this conclusion:

- Fail `012-pre-intern-native-pair-event-symbols.md` rejected pre-interning
  for the parent swap event family with the same sizing logic (~0.1 ms /
  ledger ceiling, sub-Low).
- Fail `022-sac-cache-datakey-balance-val.md` rejected `DataKey::Balance`
  Val caching for similar reasons, noting that any optimization changing
  host-side allocation count or budget-charge count is constrained by
  metering being protocol-visible.

The container allocations (`HostVec` of 2 topics, `HostMap` of 5 entries)
cannot be reused across swaps because their `vals` hold per-swap amounts
(`amount_0_in_val`, `amount_0_out_val`, etc.) and the `to` address. Only
the symbol byte contents are constant; the small-symbol fast path
(`SymbolSmall`) and the cheap per-key allocation already make this work
cheap in absolute terms.

### Lesson Learned

For Soroban event-emission micro-optimizations on the apply path:
quantify `swap_count × per-swap_allocs × per-alloc_ns / NUM_CLUSTERS /
N_ledgers` against the 3 % Medium floor before drafting. For native
soroswap swaps with 6 constant symbol allocations per swap, ~50 ns each,
2,000 swaps / ledger, 8-way parallelism — total ceiling is sub-0.1 ms /
ledger ≈ sub-0.05 % of apply. This extends fail #012's per-swap-event
ceiling to the data-key sub-slice and confirms that any in-host symbol
interning for native pool swaps cannot exceed the Low floor on this
workload, even before accounting for metering-preservation overhead.
