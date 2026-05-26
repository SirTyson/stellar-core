# H008: Scratch-Buffer Reuse for Sub-Call Argument `Vec<Val>` in Native Pair Swap

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Apply-time reduction via eliminated per-sub-call `Vec<Val>` allocations inside the native pair swap helper
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The native pair swap helper (accepted in
`success/native-pair-swap.md`) should perform sub-calls (token transfer,
balance reads, refund transfer) without repeatedly allocating fresh
small `Vec<Val>` argument buffers per sub-call. A single
thread-local or per-frame scratch buffer reused across the bounded set
of sub-calls would avoid the per-sub-call alloc/free + (potentially) a
`metered_clone` charge for the argument vector.

## Mechanism

The native pair swap implementation issues an inner sequence of host
sub-calls (typically: source-token `transfer_from`/`transfer`, pool
balance reads, destination-token `transfer`, optional refund). Each
sub-call constructs a fresh small `Vec<Val>` of arguments before
dispatch through `Host::call_n_internal`. The allocations are
short-lived (drop at sub-call return) and dominated by the Vec's heap
allocation + a `metered_clone` charge against the budget. A scratch
buffer (e.g. a `RefCell<Vec<Val>>` on `HostImpl` reused with `clear() +
extend`) would amortize these allocations across the four-or-so sub-calls
per swap.

## Trigger

Every soroswap-style swap that takes the native pair-swap path produces
~4 sub-calls (transfer, transfer_from, two `balance` peeks, optional
refund). soroswap drives ~7000 swaps per benchmark window.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/soroswap_pair/native_swap.rs` (the native pair swap entry point introduced by the accepted optimization)
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:call_n_internal` — sub-call entry that consumes the argument slice
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:HostImpl` — would gain a `RefCell<Vec<Val>>` scratch field

## Evidence

Tracy shows `new map` 350 ms self-time at 170k calls and `add host object`
280 ms at 926k calls — both indicate that small per-sub-call Vec/Map
allocations are a real-but-modest contributor to host residual time. The
native pair swap is the dominant frame on the soroswap benchmark, so a
proportional fraction of small-vector churn is attributable to its
sub-call argument buffers.

## Anti-Evidence

Per-sub-call cost is dominated by `Host::call_n_internal`'s mandatory
work: frame push/pop, authorization-tree advance, event emission, budget
charges for argument cloning, and (for non-native callees) Wasm
invocation. The `Vec<Val>` allocation residual is small: a fresh
`Vec::with_capacity(N)` for N ≤ 4 in jemalloc is on the order of 30–60 ns
amortized; the `metered_clone` charge for the argument vector survives
regardless because protocol-visible metering must observe the same
`cpu_insns`/`mem_bytes` across nodes. So scratch-buffer reuse removes
only the unmetered alloc/dealloc cycle, not the charge.

Quantitatively: 7000 swaps × 4 sub-calls × ~50 ns per Vec allocation =
1.4 ms aggregate self-time per benchmark window. After 8-way cluster
parallelism and 71 ledgers: `1.4 ms / 8 / 71 ≈ 2.5 µs/ledger ≈ 0.001 %`
of the 207 ms soroswap baseline. Three orders of magnitude below the
1 % Low floor.

Additionally, the existing `metered_clone` budget charges on argument
slices would still need to fire on every sub-call, leaving no
protocol-visible behavior change to exploit even if reuse were
implemented across protocol versions.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — prior fail entries covered map/snapshot reuse
(`014-lazy-init-storage-map-snapshot.md`,
`027-argument-vec-reuse-call-n-internal.md`) but not scratch-buffer
reuse scoped specifically to the native pair swap sub-call sequence.
Distinct in scope; identical in conclusion.

### Why It Failed

Per-sub-call removable physical work (`Vec` alloc/dealloc, unmetered
residual of cloning the argument slice) is ~50 ns. Multiplied by the
~28k sub-calls per benchmark window driven by 7000 swaps, the
aggregate is ~1.4 ms — after parallelism this is ~0.001 % of apply
time, two-plus orders of magnitude below the objective's Low floor.
The dominant per-sub-call costs (frame management, auth advance, event
buffer growth, budget charges for arg cloning) are unchanged by buffer
reuse.

### Lesson Learned

Small-allocation reuse inside hot dispatch paths must be evaluated as
`removable_ns × call_count / NUM_CLUSTERS / N_ledgers` against the
207 ms soroswap budget. For p26 with NUM_CLUSTERS=8 and N_ledgers=71,
the per-call removable-ns × call-count product must clear roughly
`6 ms × 8 × 71 / call_count = 3.4 / call_count seconds` to hit Medium —
i.e. ~120 µs/call at the 28k-call scale of pair-swap sub-call args, or
~480 ns/call at the ~7M-call scale of `charge()`. Sub-100 ns per-call
optimizations at sub-million call counts cannot reach Medium and
should be deprioritized at hypothesis time.
