# H018: Pre-reserve `Host.objects` Vec capacity to skip per-invocation regrowth

**Date**: 2026-05-05
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: apply-time (host-object allocation)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`HostImpl::objects` is a `Vec<HostObject>` that starts empty (via
`#[derive(Default)]`) and grows on every `add_host_object`. With
~135 host objects per soroswap invocation (≈ 935,719 objects /
6,776 invocations), the vec follows the Rust default growth schedule:
0 → 4 → 8 → 16 → 32 → 64 → 128 → 256, i.e. ≈ 8 reallocations and
8 memcpy steps per invocation.

A correct host should pre-reserve capacity for the expected
host-object count at frame-zero entry (e.g.
`objects.reserve(EXPECTED_OBJECTS)` at `Host::with_storage_and_budget`
or at the top of `e2e_invoke::invoke_host_function`), eliminating
those reallocations. The metered cost of allocation is *already*
paid via `metered_clone::charge_heap_alloc` — only the unmetered
implementation overhead (libc realloc, memcpy of moved `HostObject`
discriminants) is removable.

## Mechanism

Each `Vec` regrowth is a `realloc` plus a `memcpy` of all current
`HostObject` entries (each is `enum HostObject` with `Vec<HostObject>::push`
moving 1 element of `size_of::<HostObject>()` bytes — the enum
discriminant plus the largest variant payload, ~80 bytes after
alignment). For a 135-object invocation the regrowth cost is roughly
`memcpy(0+4+8+16+32+64+128) * 80 bytes = 252 * 80 ≈ 20 KB` of moved
data per invocation, plus 7 allocator round-trips.

Pre-reserving capacity once eliminates those allocator round-trips
and memcpy steps without changing observable metering: the
`metered_clone::charge_heap_alloc::<HostObject>` charge inside
`add_host_object` is per-element and already accounts for the
*logical* allocation cost.

## Trigger

Any soroban invocation. Soroswap is the worst case in this benchmark
because each pair-contract call wraps many `Val`s into host objects
during balance reads/writes and event emission.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs` —
  `HostImpl` struct definition; `objects: RefCell<Vec<HostObject>>`.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-458`
  — `add_host_object` push site.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:407-521`
  — top of `invoke_host_function` where a one-shot reserve could
  happen on a freshly-created host.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs::with_storage_and_budget`
  — Host construction; default capacity initialization.

## Evidence

- `add host object` zone self-time: 270,971,092 ns / 935,719 calls /
  289 ns mean (soroswap baseline trace).
- Default Rust `Vec::push` regrowth schedule produces 7
  reallocations to reach 256 capacity, which covers the typical
  per-invocation object count.
- Aggregate moved-bytes per benchmark: 7 reallocs × ~10 KB mean copy
  × 6,776 invocations ≈ 475 MB of memcpy work, plus 47,432
  realloc round-trips.

## Anti-Evidence

- Modern allocators (jemalloc/tcmalloc/glibc malloc) reuse the
  same arena class for sequentially growing Vecs, so realloc often
  becomes an in-place expansion (no memcpy). Measured per-realloc
  cost is therefore well under the worst case implied by the byte
  count.
- Even at the worst case, per-invocation removable work is
  ≈ 7 reallocs × ~200 ns + 252 element moves × ~5 ns each = 2.7 µs.
  Multiplied by 6,776 invocations = 18.3 ms aggregate CPU per
  benchmark.
- After 8-way parallel-apply normalization: 18.3 ms / 8 = 2.3 ms
  wall across 71 ledgers ≈ 0.032 ms per ledger ≈ 0.012 % of the
  273 ms soroswap apply baseline.
- This is two orders of magnitude below the 1 % benchmark-noise
  floor and three orders below the 3 % Medium severity threshold
  required by this objective.
- Pre-reserving a fixed capacity also wastes memory for invocations
  that produce few host objects (e.g. trivial `View` calls), and
  allocating a too-small reserve still leaves the regrowth path on
  the hot path. A per-frame stack of vecs is more invasive than the
  apparent payoff justifies.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — `HostImpl::objects` Vec preallocation is not
mentioned in any prior fail, hypothesis, reviewed, or poc record.

### Why It Failed

The removable work is unmetered allocator overhead, which is small in
practice because allocators reuse arenas for sequentially growing
vecs. Aggregate per-benchmark savings ≈ 18 ms CPU; after 8-way
parallelism, ≈ 2.3 ms wall over 71 ledgers, ≈ 0.012 % of the soroswap
apply baseline. Far below benchmark noise (1 %) and the objective's
3 % Medium severity floor.

### Lesson Learned

Vec-preallocation hypotheses for hot per-invocation buffers should be
quantified at the *implementation* level (allocator round-trips and
memcpy bytes), not at the *call-count* level. In practice, the
default Vec growth schedule (geometric, factor 2) and modern
allocator arena reuse mean that per-invocation vec growth contributes
in the low tens of microseconds — too small to clear the Medium
floor on this benchmark even with millions of pushes.

A more productive variant of this hypothesis would target a
*per-host* arena pool — allocate one slab once per Host, reuse across
the invocation — but only for objects whose lifetimes are bounded by
the host frame. That redesign is much larger in scope and is not
warranted by the projected savings.
