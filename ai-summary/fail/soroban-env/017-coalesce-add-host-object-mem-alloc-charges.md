# H017: Coalesce per-`add_host_object` MemAlloc charges in next protocol

**Date**: 2026-05-05
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: apply-time (host-object allocation metering)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The accepted baseline already extends "protocol-gated host metering
coalescing" (`success/soroban/001-protocol-gated-host-metering-coalescing.md`)
to `VisitObject` and per-chunk `ValSer`. A symmetrical opportunity is
the per-call `metered_clone::charge_heap_alloc::<HostObject>(1, self)?`
that runs inside every `Host::add_host_object` (the parent of every
`HostMap` / `HostVec` / wrapped numeric / address / bytes / string / symbol
allocation). For a coalesced next-protocol mode, the host should be able
to track total `HostObject` allocations cheaply and emit a single bulk
`MemAlloc` charge at frame pop / `try_finish` while preserving the same
total `cpu_insns` / `mem_bytes` accounting, exactly as the accepted
`ValSer` coalescing does.

## Mechanism

Every `add_host_object` call (`host_object.rs:446-458`) does:

1. `try_borrow_objects()?.len()` — RefCell borrow + len.
2. `index_to_handle(self, index, false)?` — handle conversion.
3. `metered_clone::charge_heap_alloc::<HostObject>(1, self)?` — calls
   `Budget::charge(MemAlloc, Some(N * size))`, which charges both
   `cpu_insns` and `mem_bytes` dimensions. Two dimension-charge calls
   per host-object allocation.
4. `try_borrow_objects_mut()?.push(...)`.
5. `HOT::inject(hot, self)?`.

In the soroswap baseline trace `add host object` zone has self-time
270,971,092 ns over 935,719 calls (≈ 289 ns mean). The `charge`
dimension zone fires twice per call (cpu + mem) — that is roughly
1.87M extra dimension charges per benchmark just for object
allocation. A coalesced bulk-charge mode would replace those with one
end-of-frame charge whose totals match.

## Trigger

Any soroban invocation that allocates host objects — i.e. all soroswap
swaps, every SAC transfer, anything that wraps a `Val` in a host
object, builds a `HostMap` / `HostVec`, or pushes auth-frame contract
addresses.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-458` —
  `add_host_object` per-call `charge_heap_alloc<HostObject>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:53-110`
  — `charge_shallow_copy` / `charge_heap_alloc` charge sites.
- `src/rust/soroban/p26/soroban-env-host/src/budget/mod.rs` and
  `host.rs:576-582` — existing protocol-gated coalesced mode flag
  installed by the accepted success #001-soroban.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188`
  — `BudgetDimension::charge`, which fires twice per
  `charge_heap_alloc`.

## Evidence

- `add host object` zone in the soroswap baseline: 270,971,092 ns / 935,719
  calls / 289 ns mean.
- The accepted protocol-gated coalescing demonstrated that per-call
  `VisitObject` and `ValSer` charges can be replaced with bulk totals
  on next protocol with measurable apply-time savings (2.10% soroswap).
- Per-call `charge_heap_alloc<HostObject>` is structurally identical
  (constant size, fixed cost, no lin term needed when iteration count
  is summed): a single end-of-frame `MemAlloc(N_objects * sizeof(HostObject))`
  preserves totals exactly.

## Anti-Evidence

- Per-call `charge_heap_alloc` cost is dominated by the two
  `BudgetDimension::charge` calls (cpu + mem). Each is ~30–60 ns of
  total work — adding to `total_count`, comparing limit, returning.
  Per `add_host_object`: ~60–120 ns of charge-only overhead, of which
  only the call/dispatch overhead is removable; the arithmetic
  (`saturating_add`, limit compare) must still run once, in bulk.
- Removable per-call work ≈ 60 ns × 935,719 calls = 56 ms aggregate
  CPU per benchmark, before the parallel-apply 8-way parallelism factor.
- Wall-clock estimate: 56 ms / 8 = 7 ms across 71 benchmark ledgers,
  ≈ 0.10 ms per ledger, ≈ 0.04 % of the 273 ms soroswap apply
  baseline.
- This is far below the 1 % benchmark-noise floor and well below the
  3 % Medium severity floor required by this objective.
- Engineering risk is non-trivial: the coalesced path must also
  preserve early-exit budget-limit semantics (a transaction that runs
  out of budget partway through should fail at the same `add_host_object`
  index in p26 and in coalesced p27). A purely-deferred bulk charge
  changes the budget-exceeded transition point and is observable from
  contract code that tries to recover from `BudgetExceeded`.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS — the accepted success entry coalesces `VisitObject`
and `ValSer` only. Coalescing `HostObject`-allocation charges
(`charge_heap_alloc<HostObject>`) is a distinct charge site that has
not been explicitly investigated and is not in any prior fail or
success record.

### Why It Failed

Below the objective's 1 % benchmark-noise floor and far below the 3 %
Medium severity threshold. Per-call charge overhead is in the tens of
nanoseconds; aggregate removable work is ≈ 56 ms CPU per benchmark
(≈ 7 ms wall after 8-way parallelism, ≈ 0.04 % of the 273 ms soroswap
apply baseline). The structural design is feasible (mirroring the
accepted `ValSer` coalescing) but the leverage in this benchmark is
too small.

In addition, deferring per-allocation charges to a frame-end bulk
charge risks changing the *position* at which a budget-exceeded
transaction fails — observable behaviour for contracts that catch and
recover, and a correctness concern that needs to be dealt with even if
the totals match.

### Lesson Learned

Future per-call charge-coalescing hypotheses should pre-quantify the
per-call removable overhead in nanoseconds, multiply by the per-ledger
call count, then divide by the apply-load parallelism factor before
proposing. For host-object allocation (`add_host_object`) the per-call
cost is too low and the call count too modest after parallelism
normalization to clear the Medium floor on this benchmark, even though
the same coalescing pattern was viable for `VisitObject` and per-chunk
`ValSer` (which fired millions of times more).

A second-order lesson: a coalesced charge path must preserve not only
the *total* `cpu_insns` / `mem_bytes` but also the *order* at which
limits are crossed, since contracts can observe budget-exceeded errors
via `try_call`. Charge coalescing is therefore safe only for charges
that are guaranteed to pass under the configured limit *or* that can
be eagerly checked against the limit without per-call dispatch
overhead.
