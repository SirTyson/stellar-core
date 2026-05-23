# H012: Pre-Intern Native-Pair Swap Event Symbol Objects

**Date**: 2026-05-23
**Subsystem**: soroban-env, soroban
**Severity**: Low (sub-threshold)
**Impact**: Avoid per-swap `SymbolObject` allocations for the static event
topics/keys emitted by the native Soroswap pair `swap` body
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the native Soroswap pair `swap` runs, it emits a contract event
whose topics and data-map keys are a fixed set of Symbols longer than 9
characters (so they cannot be `SymbolSmall`): `"SoroswapPair"`,
`"amount_0_in"`, `"amount_0_out"`, `"amount_1_in"`, `"amount_1_out"`,
`"to"`, plus the topic discriminator `"swap"` (small) and a couple of
addresses. Each long-symbol topic/key is currently allocated as a fresh
`HostObject::Symbol` (a `ScSymbol(StringM)` in
`soroban-env-host/src/host_object.rs`) every swap, despite being a
compile-time constant.

A correct, efficient implementation would either (a) pre-intern these
constant symbols once per `Host` (or once per native-frame entry) and
reuse the resulting `SymbolObject` handles for every native pair swap
in the apply, or (b) construct the event topic/data structure directly
from `&'static str` slices via the existing slice-aware helpers
(`map_new_from_slices` etc.) without ever materializing per-swap
`SymbolObject`s in the object table.

## Mechanism

The native pair swap event-emission block (in `frame.rs` inside
`call_native_soroswap_pool_swap`) calls
`Host::add_host_object(HostObject::Symbol(...))` ≈ 6–9 times per swap to
build the topics tuple and the data map keys. Each allocation grows the
`HostImpl.objects` Vec, charges allocation budget, and clones a
`StringM<32>` into the table. The same constants are re-built ≈ 140,000
times across the soroswap benchmark — the only thing that varies per
swap is the address pair and the amounts. Pre-interned handles (a
`OnceCell<[SymbolObject; N]>` populated on first native-pair frame
entry, or static slices that bypass the object table via the existing
`*_from_slice` helpers) would eliminate every redundant allocation.

The ACTUAL deviation: the native-pair event-emission path materializes
fresh `SymbolObject`s for compile-time constants every swap, exhausting
object-table slots and allocator/budget cycles on values that are
provably identical across all swaps.

## Trigger

Run the soroswap apply-load benchmark. The Tracy zone covering
`add_host_object` + `Symbol`-related object construction visible inside
the native pair `swap` body is exercised ≈ 9 × 140k ≈ 1.26 M times
across the 70-ledger run.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` —
  `call_native_soroswap_pool_swap` event-emission block (added by
  accepted commit `03d78248`, refined by `fbbea0d9`); the topic/data
  construction calls that allocate `SymbolObject`s.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs` —
  `HostObject::Symbol` allocation path and `add_host_object`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` —
  `EnvBase::symbol_new_from_slice` and `map_new_from_slices`
  alternatives that already exist for trusted callers.

## Evidence

- The 6+ long-symbol allocations per native pair swap are visible by
  inspection of the native swap implementation.
- `add_host_object` is on the metered budget path: each call charges
  `HostMemAlloc` and pushes to `HostImpl.objects`, even when the
  payload is a compile-time constant.
- The accepted "bulk-build storage maps" optimization (in the success
  stack) established that bypassing the object table for known-static
  inputs is a valid pattern within the protocol gate that already
  covers native-pair behavior.

## Anti-Evidence

- The savings per allocation are small. Rough budget for
  `HostObject::Symbol` allocation: a single `metered_clone` of a
  `StringM<32>` is in the 200–400 ns range (allocator path + budget
  charge + Vec push). At 1.26 M removed allocations, total worker CPU
  saved ≈ 360 ms.
- More importantly, the budget charges are protocol-visible: removing
  the per-swap `HostMemAlloc` charges changes the metered fee/refund
  schedule for native-pair swaps. A behaviour-preserving variant has to
  replay the charges, shrinking the saving to just the physical
  allocator + Vec push (sub-100 ns/call → ≈ 100 ms aggregate worker
  CPU). A charge-eliminating variant requires a protocol-27 gate, and
  Meta-Pattern #16 already documents that residual charge-coalescing
  cannot clear Medium.
- The pre-intern handle lifetime question is non-trivial: object
  handles live in `HostImpl.objects` for the lifetime of the host, so
  cached handles must be re-minted per host instance (one-time cost is
  amortizable) and invalidated if the host is reset between
  invocations.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail file targets event-symbol allocations
specifically on the native pair swap path.

### Why It Failed

Arithmetic puts the recoverable wall time below the Low floor, and the
metering-preserving variant pushes it well below benchmark noise.

- 1.26 M allocations × ≈ 286 ns/alloc removable (metering-changing
  variant) ≈ 360 ms aggregate worker CPU.
- After 8-way cluster parallelism normalization: ≈ 45 ms total
  wall-clock saved across the whole 70-ledger benchmark run.
- Per ledger: ≈ 0.64 ms.
- Against the 218 ms soroswap baseline: ≈ 0.29%.

This is below the 1% Low floor and well below the 3% Medium severity
threshold required by the optimize-soroswap objective. The
metering-preserving variant (only the allocator + Vec push, retaining
all budget charges) drops the recoverable surface to roughly one third
of the above (~0.1%), pushing the optimization deep into noise. The
charge-removing variant requires a protocol-27 gate and is governed by
Meta-Pattern #16, which has already documented that residual
post-VisitObject/ValSer `BudgetImpl::charge` self-time is structurally
incapable of clearing Medium via per-call elimination.

Additionally, although no prior fail entry targets event symbols
specifically, the broader pattern (caching/interning constants used by
native paths) is bounded by the same call-count × per-call ceiling as
TTL-extend coalescing (fail 003) and similar per-swap micro-allocations
— none clear the Medium threshold once parallelism normalization is
applied.

### Lesson Learned

Per-swap constant-symbol allocations in the native pair path appear
attractive (1.26 M removable allocations sounds large) but are bounded
in wall-time impact to <1% of soroswap apply time after 8-way
parallelism normalization, the same arithmetic ceiling that defeats
TTL-extend coalescing (fail 003) and other per-swap micro-allocation
hypotheses. Use the framework `N_swaps × per_call_µs / NUM_CLUSTERS /
N_ledgers / baseline_ms` to gate any future native-pair micro-allocation
hypothesis before deep investigation; only constructs whose per-swap
cost is >50 µs (>>typical allocation cost) can clear the Medium floor.
