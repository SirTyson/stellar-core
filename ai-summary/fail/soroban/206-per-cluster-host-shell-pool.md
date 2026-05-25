# H206: Per-Cluster Host Shell Pool to Amortize Per-Tx Host Construction

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Medium (claimed; investigated and rejected)
**Impact**: amortize per-tx `Host::default()` / object-table / storage / budget / auth-manager construction across all Soroban txs in a cluster
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Every Soroban transaction's apply path constructs a fresh `Host` via
`Host::default()`, populates `Storage` with footprint entries, allocates a
`Vec<HostObject>` for the object table, builds a fresh `BudgetImpl`,
`AuthorizationManager`, `InternalEventsBuffer`, and small per-host
`RefCell`-wrapped sub-maps. Within a single cluster (sequential within a
worker), all of these allocations are independent and freed after each tx
completes. A correct optimization would lazily reuse the previous tx's
`Host` shell, clearing only the mutable state (object vec, storage map,
event buffer, auth manager, frame stack) while preserving the allocated
capacity of each owned `Vec`/`RefCell` so that the next tx avoids the
allocator round-trip. This is analogous to the
`Vec::clear()` (preserves capacity) vs `Vec::new()` distinction.

Expected savings: removing the per-tx allocator churn for ~6 fields in
`HostImpl` could shave ~5-15µs per Soroban invocation; for soroswap's
~125 invocations per cluster per ledger, that totals 600-1900µs per
ledger per worker = 0.3-0.9% with full elimination, BEFORE 8-way
cluster normalization.

## Mechanism

`invoke_host_function` in `soroban-env-host/src/e2e_invoke.rs:639` calls
`Host::default()` per invocation. `HostImpl` (host.rs) owns ~15
`RefCell`-wrapped fields including `objects: Vec<HostObject>` (typical
grow path: 0 → ~150 entries via repeated `Vec::push`), `Storage`
(itself owning a `MeteredOrdMap` for footprint and storage), a
`Budget` (`Rc<RefCell<BudgetImpl>>`), an `AuthorizationManager` with its
own internal `Vec`s, `InternalEventsBuffer`, and a `context_stack:
Vec<Context>`. Each per-tx construction triggers ~6-8 allocator
acquires/releases.

The ACTUAL behavior is per-tx alloc/free churn. The DEVIATION is that
within a single cluster-worker, allocations could be reused.

## Trigger

Run soroswap apply-load. Each cluster worker processes ~125 SAC + native
pool swap invocations sequentially. Trace shows
`add host object` at 308M ns self / 1M calls = 308 ns/call (much of which
is metering: ~243 ns is the `charge_heap_alloc` three-charge triplet from
`charge_bulk_init_cpy`). The remaining ~65 ns/call is the actual
`Vec::push` cost, which includes occasional realloc as the vec grows from 0.
At 1M calls / 8 / 71 = ~1760 vec pushes per ledger per worker, of which
some fraction triggers realloc.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:639` — top-level
  `invoke_host_function` constructs `Host::default()`
- `src/rust/soroban/p26/soroban-env-host/src/host.rs` — `HostImpl` struct
  and `Host::default()` implementation
- `src/rust/src/soroban_proto_any.rs:408` — `invoke_host_function_or_maybe_panic`
  C++/Rust bridge wrapper that creates one Host per call
- `src/rust/src/lib.rs` — module cache exposes shared Rust state per cluster
  worker; a host-shell pool could live alongside

## Evidence

- 8,705 Soroban invocations × per-host construction cost
- `add host object` total 308M ns / 1M calls indicates ~1M vec pushes
- The `objects` Vec grows from 0 each invocation, requiring power-of-two
  reallocations as it climbs to ~150 entries
- `invoke_host_function` self time is 977M ns / 8705 calls = 112µs/call;
  some of this is unwrapped setup, panic handling, and bridge work

## Anti-Evidence (and why this fails)

1. **Most of the visible cost is metering, not allocation.** The "add host
   object" zone's 308M ns is dominated by 3× `Budget::charge` calls per
   push (~243 ns) which CANNOT be removed without changing protocol-visible
   metering (fail #202 explicitly examined this). The remaining ~65 ns
   per push is the actual `Vec::push`. After 8-way cluster normalization
   and 71 ledgers: 65ns × 1M / 8 / 71 = 0.114 ms/ledger = **0.055% of the
   207 ms baseline**. The MAXIMUM achievable saving from object-table
   capacity reuse alone is far below the 1% Low floor.

2. **Storage map metering cannot be preserved across reuse.** The
   `MeteredOrdMap`-based storage map is rebuilt per tx from the footprint
   entries supplied by C++. Reusing a "pre-allocated" `MeteredOrdMap`
   shell would either skip the metering charges (protocol-visible
   regression) or replay them — at which point the metering charges
   dominate the allocation savings, and the net is sub-noise.

3. **Per-tx state contracts conflict with reuse.** `Host::try_finish()`
   consumes the host (requires refcount=1) and extracts `(Storage,
   Events)`. The current refcount discipline requires that no clones
   leak after invocation; a pool design must reset every `Rc` chain
   without leaving live observer references. The retained fail
   `001-cluster-rust-invoke-batching.md` and meta-pattern #15
   already capture the per-tx isolation blocker (auth, events, budget,
   rollback, metadata output all per-tx).

4. **Allocator amortization is already significant.** Modern
   `jemalloc`/`tcache` retains freed `Vec` buffers in per-thread caches
   so sequential same-thread allocations of similar size hit the cache
   directly. Fail #006 (`006-host-objects-vec-pre-reserve.md`) explicitly
   tested host-objects-vec pre-reservation and found it sub-Low for this
   reason.

5. **`BudgetImpl` reuse blocked by metering reset semantics.** Each tx
   gets a fresh budget pool sized from network config. Reuse would
   require an exact `reset()` that re-initializes every counter to its
   per-tx limit — same work as fresh construction.

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — Host-shell pooling (as distinct from cluster-batched
invocation, fail #077, and pre-reserved object vec, fail #006) was not
previously written up. However, the underlying blockers are the same set
already captured under per-tx state isolation (meta-pattern #15) and
metering preservation (meta-pattern #11/#16).

### Why It Failed

Per-tx state isolation (auth, events, budget, storage, rollback) requires
either full reset (matches construction cost) or risks protocol-visible
metering changes. The pure allocation reuse fraction — the only piece
not already covered by per-tx semantic work — is sub-0.1% of apply after
8-way normalization, far below the 1% Low floor and well below the 3%
Medium threshold.

### Lesson Learned

For per-invocation Host construction optimizations in the Soroban host:
the metering and per-tx isolation requirements absorb almost all of the
visible cost. Capacity-reuse hypotheses must isolate the
allocator-churn-only slice (after subtracting all metering charges and
mandatory per-tx semantic reset work) and project against the 3% Medium
floor BEFORE writing up. Modern allocators (jemalloc tcache) already
amortize freed-Vec reuse on hot threads, further deflating the
recoverable slice.
