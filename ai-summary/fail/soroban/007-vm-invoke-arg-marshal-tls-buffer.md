# H007: Avoid per-invocation `Vec<wasmi::Value>` allocation in `Vm::invoke_function_raw` via a per-VM scratch buffer

**Date**: 2026-05-03
**Subsystem**: rust-bridge / soroban-host / wasmi
**Severity**: Low
**Impact**: Eliminate the per-invocation `Vec<wasmi::Value>` allocation + `metered::charge_bulk_init_cpy` charge round-trip on the host→wasmi argument path (Tracy: `Vm::invoke_function_raw` 696.9 ms self / 20 313 calls = 34.3 µs/call).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Vm::invoke_function_raw` (`src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412`) is the
entry point for every host→guest call — including the outer `Host::invoke_function` and every
sub-contract `call` host fn. It must, for each invocation:

1. Translate each absolute object handle in `args: &[Val]` to its relative equivalent.
2. Marshal each relative `Val` into a `wasmi::Value` (an `enum {I32, I64, ...}`).
3. Pass a slice of `wasmi::Value` into `metered_func_call` → `wasmi::Func::call`.

Expected behavior: arguments are typically 0-4 short integer-like values (Soroswap's hot path
is `transfer(from, to, amount)` — three `Val`s); the marshalling buffer should be a small
inline / stack-resident object reused across invocations, not a heap `Vec<wasmi::Value>`
allocated per call. The host/wasmi boundary should not pay a heap allocation + budget charge
for every contract call.

## Mechanism

The current implementation builds a fresh `Vec<wasmi::Value>` from the `args` iterator on every
invocation:

```rust
Vec::<wasmi::Value>::charge_bulk_init_cpy(args.len() as u64, host.as_budget())?;
let wasm_args: Vec<wasmi::Value> = args
    .iter()
    .map(|i| host.absolute_to_relative(*i).map(|v| v.marshal_from_self()))
    .collect::<Result<Vec<wasmi::Value>, HostError>>()?;
```

This:
1. Calls `charge_bulk_init_cpy` (a metered budget charge, protocol-visible).
2. Allocates a fresh `Vec` on the heap (default `Vec::with_capacity(args.len())` via
   `collect()`'s `FromIterator` impl).
3. Drops the `Vec` after `metered_func_call` returns (deallocation work).

Per-call wall cost is small but call count is high: 20 313 invocations across 71 ledgers
(286/ledger). A per-VM `RefCell<Vec<wasmi::Value>>` scratch buffer (or a `SmallVec<[wasmi::Value; 4]>`
that elides the heap allocation for 0-4 arg calls, which is ~99% of cases) would remove the
allocation entirely. Note: the budget charge cannot be removed without protocol gating; only
the heap allocation work would shrink.

## Trigger

Soroswap apply-load benchmark; observe `Vm::invoke_function_raw` self-time in Tracy. Soroswap's
swap path performs ~3-4 contract→contract calls per swap (router → factory → pair token → SAC),
each going through `invoke_function_raw`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `invoke_function_raw` body.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-391` — `metered_func_call` (consumer of
  the slice; can switch from `&[wasmi::Value]` to anything that exposes a `&[wasmi::Value]`).
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:39-95` — `Vm` struct (would need a new
  `args_scratch: RefCell<Vec<wasmi::Value>>` field or equivalent).
- `wasmi-0.31.1`'s `Func::call` signature accepts `&[Value]` so any slice source works.

## Evidence

- `Vm::invoke_function_raw` self-time: 696.9 ms / 20 313 calls = 34.3 µs/call. The self-time
  does NOT include `metered_func_call` (which is not a Tracy zone but is itself called from
  within this zone — actually IS in self because the inner function isn't zoned).
- The visible `tracy_span!("Vm::invoke_function_raw")` covers the whole function, but the
  inner `metered_func_call` (which dominates) has no own zone, so its work is in
  `Vm::invoke_function_raw` self too.
- Allocation cost in the `collect::<Result<Vec<_>>>()` is well under 1 µs (tcmalloc/jemalloc
  small-block allocation is ~50 ns).
- Budget `charge_bulk_init_cpy` is metered and cannot be removed without breaking protocol
  semantics on p26.

## Anti-Evidence

1. **Self-time is dominated by `metered_func_call`** (fuel-transfer round-trip into wasmi +
   `wasmi::Func::call` setup), not by the visible `Vec` allocation. Removing the allocation
   saves at most ~50 ns/call × 20 313 = 1 ms total CPU = 0.018 ms/ledger wall after dividing
   by NUM_CLUSTERS=8 — totally insignificant.
2. **Budget charge cannot be removed** on p26: `charge_bulk_init_cpy` is part of the protocol
   budget shape. The optimization can only target the *implementation* of the alloc.
3. **Per-VM scratch buffer doesn't compose with reentrancy**: a contract that calls into
   another contract (e.g., router → pair) creates a new VM frame; sharing scratch across
   reentrancy is a correctness hazard. Must be per-`invoke` rather than per-`Vm`, defeating
   the savings.
4. **SmallVec already-elided savings**: `Vec::with_capacity(N)` for N=3 from `collect()` is
   already a single small heap allocation; replacing with `SmallVec<[_;4]>` saves the alloc
   but most allocators handle 32-byte allocs in ~30 ns.
5. **Sub-Low even at 100 % allocation removal.**

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior wasmi-side investigations (InstancePre, ModuleCache
mutex, check_imports, Linker minimal, linear-memory mmap, dispatch fuel-refill coalescing);
none targeted the host-side argument marshalling path.

### Why It Failed

Self-time decomposition rules the optimization out before quantification. The
`Vm::invoke_function_raw` 34.3 µs/call self-time is overwhelmingly inside `metered_func_call`
(fuel transfer to wasmi, `Func::call` execution dispatch, fuel transfer back), not inside the
3-line `Vec` allocation that this hypothesis would replace. Even an idealized 100 % removal of
the visible alloc work (~50 ns × 20 313 calls = ~1 ms total CPU = ~0.02 ms/ledger wall)
falls far below the Low (1-3 %, ~3 ms/ledger) and Medium (3-10 %, ~8 ms/ledger) thresholds.

### Lesson Learned

When a Tracy zone wraps a non-zoned heavy inner call (e.g., `metered_func_call` here, or
`xdr_size` inside `toCxxBuf`), do not attribute the zone's self-time to the small visible
operations alone. Decompose the inner call structurally first; only target the inner call if
its structural cost is itself attackable. For host→wasmi boundary work, the dominant
non-metered cost is fuel transfer and wasmi `Func::call` dispatch — not Rust-side argument
allocation.
