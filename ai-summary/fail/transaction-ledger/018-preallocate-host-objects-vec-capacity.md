# H018: Pre-reserve `Host::objects` Vec capacity to eliminate per-invocation reallocations during soroswap apply

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host object arena
**Severity**: Low
**Impact**: Skip a handful of `Vec` re-allocations and copies in `Host::objects` during each Soroban host invocation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a Soroban host invocation pushes thousands of `HostObject` values
into the per-invocation arena `Host::objects`, the underlying
`Vec<HostObject>` should be sized once up-front (or grown geometrically
with a sensible initial capacity) so that `add_host_object` never
triggers a re-allocate-and-copy for the steady-state size of a soroswap
swap, eliminating the `O(N)` memcpy work of doubling-grow reallocations
inside the parallel apply hot loop.

## Mechanism

`Host::add_host_object` (`src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-458`)
does `self.try_borrow_objects_mut()?.push(HOT::inject(hot, self)?);`
where `objects` is `RefCell<Vec<HostObject>>`.  The `Vec` starts empty
(default capacity 0) per host invocation and grows via `push`'s standard
geometric doubling, which means roughly `log2(N_steady)` reallocations
per invocation, each copying all currently-allocated `HostObject`
entries (~size 40-80 bytes each).  The actual deviation from optimal
behavior is just the unnecessary log-N reallocations; reserving an
appropriate up-front capacity removes them entirely without changing
semantics, budget, or any observable behavior.

## Trigger

Run the soroswap apply-load benchmark
(`soroswap, TX=2000, T=8`).  The Tracy zone `add host object`
(`host_object.rs:450`) fires 554,102 times across the trace at a self-time
of 152.5 ms (1.49% of trace).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-458` -
  `add_host_object` push site.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` - `Host::new` /
  the Soroban host constructor that initializes the per-invocation
  `objects` arena.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs` -
  the `MemAlloc` budget dimension that already accounts for the
  amortized cost of object allocation; preserving its charge is required
  for protocol compatibility.

## Evidence

- Tracy soroswap trace (`ai-summary/CURRENT_STATE.md`):
  - `add host object` self-time 152.5 ms / 554,102 calls (1.49% of
    trace, ~275 ns/call).
  - `visit host object` self-time 1.23 s / 2,689,616 calls (~455 ns/call).
- Soroswap workloads create thousands of host objects per invocation
  (storage map entries, address objects, vector arguments, SAC balance
  values), so the steady-state size of `Host::objects` is large enough
  to traverse multiple `Vec` reallocations during host execution.

## Anti-Evidence

- The `add host object` zone is guarded by `let _span = tracy_span!(...)`
  inside a `#[cfg(feature = "tracy")]` macro; the 152 ms self-time is
  Tracy emission overhead, NOT production allocator work
  (this is exactly the soroban-env meta-pattern #1).  Production builds
  do not pay this 275 ns/call.
- The actual amortized cost of `Vec::push` reallocations is `O(N)`
  total (not `O(N log N)`); for `N=13.5k` host objects per invocation
  and ~50-byte `HostObject`, the total reallocation work is on the order
  of a single ~675 KB memcpy, taking single-digit microseconds at most.
- Soroswap critical-path savings are bounded by:
  - aggregate physical reallocation work / (8 clusters x 41 stages) =
    well under 25 us / ledger,
  - which is ~0.008% of the 313 ms median bench result.
- `Host::objects` is a budget-charged structure; any pre-reservation
  cannot affect `MemAlloc` dimension accounting (which charges per-object
  allocation, not per-Vec-grow), so the change is correctness-preserving.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS - `Host::objects` Vec preallocation was not in any
existing fail/hypothesis/reviewed/poc file at the time of writing.

### Why It Failed

(1) The 152.5 ms `add host object` self-time is Tracy instrumentation
overhead, not production allocator work; eliminating it does not change
the production critical path at all.  The same lesson is recorded in
`ai-summary/fail/soroban-env/summary.md` meta-pattern #1 ("Tracy zones
guarded by `#[cfg(feature = "tracy")]` measure profiling instrumentation
cost, not soroswap apply-path work").
(2) Even the actual production `Vec::push` reallocation work is well
under 25 us / ledger (~0.008% of apply time), far below the 1% noise
floor and the 3% Medium floor.

### Lesson Learned

Do not target `add host object` self-time as production overhead - it
is Tracy-only.  More broadly, do not propose Vec capacity hints when the
amortized reallocation cost is bounded by a handful of memcpys per
invocation; for soroswap host objects this is single-digit microseconds
per ledger and structurally cannot reach Medium severity.
