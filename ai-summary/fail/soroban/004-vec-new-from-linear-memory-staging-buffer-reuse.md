# H004: Per-Worker Staging Buffer Reuse for `vec_new_from_linear_memory`

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low (sub-threshold)
**Impact**: Per-call Val[] staging allocation in the
`vec_new_from_linear_memory` host function dispatch path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`vec_new_from_linear_memory(vals_pos, len)` is a hot Soroban host function
used by Wasm contracts (notably Soroswap router/pool entry paths) to lift
a contiguous Val array from linear memory into a `HostVec`. The current
implementation calls `metered_vm_read_vals_from_linear_memory::<VAL_SZ, Val>`,
which allocates a transient `Vec<Val>` of length `len`, populates it from
linear memory, then transfers ownership into a `MeteredVector` for the
resulting `HostVec`. A staging-buffer reuse design would keep a per-worker
thread-local `Vec<Val>` reused across invocations (cleared, never deallocated
between calls), avoiding the per-call `Vec::with_capacity(len)` allocation
and final drop, while preserving every metering charge.

## Mechanism

The current path performs a fresh heap allocation per call (allocator
fast-path through tcmalloc/jemalloc thread cache, but still a malloc+free
pair). A per-worker TLS staging buffer would amortize allocator cost across
all calls in a cluster. All `Budget::charge` calls (`MemAlloc`, `VmMemRead`,
`MemCpy`, `VecNew`) would be replayed identically so protocol-visible
metering is unchanged.

## Trigger

Run the soroswap apply-load matrix. The `vec_new_from_linear_memory`
Tracy dispatch zone shows 40,566 calls across the 71-ledger soroswap window
totalling 110.886 ms self-time (parallel-worker aggregate).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs` — `vec_new_from_linear_memory`
  host function impl (lives near other linear-memory readers).
- `src/rust/soroban/p26/soroban-env-host/src/vm/mod.rs` (or `vm.rs`) —
  `metered_vm_read_vals_from_linear_memory` helper; the allocation site
  for the staging `Vec<Val>`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — generic
  dispatch wrapper where Tracy zone `vec_new_from_linear_memory` is recorded.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:107` —
  `MeteredVector::new`/`from_vec`, the eventual sink of the staging buffer.

## Evidence

Tracy `vec_new_from_linear_memory` self-time from the accepted-baseline
soroswap diagnostic trace
(`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`):

- 110.886 ms aggregate worker-CPU self-time / 40,566 calls = 2.73 µs/call
- Per-ledger aggregate worker CPU: 110.886 ms / 71 ledgers = 1.56 ms/ledger
- After NUM_CLUSTERS=8 parallelism normalization (this is parallel worker
  work): 1.56 / 8 ≈ **0.20 ms/ledger of critical-path**
- Fraction of 207 ms soroswap baseline: 0.20 / 207 ≈ **0.094% of apply time**

This is over 10× below the 1% Low floor and over 30× below the 3% Medium
floor.

## Anti-Evidence

- The allocator allocation (tcmalloc thread cache fast path) is already a
  few hundred ns/call; the actual *recoverable* portion of the 2.73 µs/call
  is the malloc+free pair only — likely 200-400 ns at most. The remaining
  ~2.3 µs is mandatory `Budget::charge` calls, linear-memory bounds checks,
  per-Val byte copy, and the `MeteredVector::from_vec` construction, none
  of which a staging buffer can remove.
- Realistic recoverable saving: ~300 ns × 40,566 calls / 8 workers / 71
  ledgers ≈ 21 µs/ledger ≈ 0.01% of apply.
- Existing prior fails:
  - `fail/soroban/002-specialized-linear-memory-map-constructor.md` —
    `map_new_from_linear_memory` specialization (252.9 ms, similar shape,
    sub-Medium after normalization).
  - `fail/soroban-env/002-one-pass-linear-memory-val-import.md` — one-pass
    Val import (not behavior-preserving due to error-phase ordering).
  - `fail/soroban-env/002-cache-linear-memory-map-shapes.md` — shape cache
    (sub-Medium).
  - The Val-vector variant has not been individually targeted, but its
    aggregate is roughly 44% of the already-rejected map variant.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — `vec_new_from_linear_memory` Val-vector staging buffer
reuse is not individually covered in the existing fail set. Closely related
work targets `map_new_from_linear_memory` (different host function, different
construction path).

### Why It Failed

After 8-way cluster normalization, the entire `vec_new_from_linear_memory`
Tracy zone contributes only ~0.20 ms/ledger ≈ **0.09% of the 207 ms soroswap
baseline**. Even 100% elimination cannot clear the 1% Low floor, and the
realistic recoverable subset (allocator malloc/free pair only, after
preserving all `Budget::charge` calls and the `MeteredVector::from_vec`
ownership transfer) is roughly an order of magnitude smaller still (~0.01%).

### Lesson Learned

- For any "staging buffer reuse" or "TLS scratch allocator" hypothesis on
  a per-host-function dispatch path inside parallel Soroban apply, compute
  `zone_total_ms / NUM_CLUSTERS / N_ledgers / baseline_ms` first; for any
  zone with aggregate self-time below ~3.5 s in apply windows, the answer
  is structurally sub-Medium (Meta-Pattern #14).
- Soroswap-shaped linear-memory host-function zones (`vec_new_from_*`,
  `map_new_from_*`, `bytes_new`, `bytes_append`) cluster around 30–250 ms
  aggregate self-time and individually all sit sub-Low after normalization.
  A combined "all linear-memory dispatch buffer reuse" proposal still
  totals well under the Medium floor and runs into Meta-Pattern #14.
- Adds to Meta-Pattern #14: `vec_new_from_linear_memory` joins the
  exhausted set of sub-1% parallel-worker dispatch wrappers; any
  individually-targeted Val-vector or Val-map linear-memory allocator
  reuse is structurally sub-threshold for this objective.
