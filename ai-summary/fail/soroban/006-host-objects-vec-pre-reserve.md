# H006: Pre-allocate `HostImpl.objects` Vec to Eliminate Per-Invocation Growth Reallocations

**Date**: 2026-05-23
**Subsystem**: soroban-env-host
**Severity**: Low
**Impact**: per-invocation allocator churn
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a Soroban invocation that allocates ~128 host objects (router swap path
on soroswap), the `HostImpl.objects: Vec<HostObject>` should not require
repeatedly doubling its backing buffer. Construction of `Host` should
`reserve()` a capacity estimate (e.g., 256) so that `add_host_object` runs
in amortized-O(1) without copying old `HostObject` enum entries during
growth re-allocations.

## Mechanism

`HostImpl::default()` creates `objects: Vec::new()` with capacity zero.
`add_host_object` is called ~1M times across 7891 soroswap invocations
(~127 objects per invocation). With doubling growth from 0, each invocation
performs `log2(127) ≈ 7` Vec reallocations, each copying all prior
`HostObject` enum entries (each ~48 bytes). Cumulatively this is ~55k
reallocations + memcopies per benchmark run, none of which is metered.
Pre-reserving on `Host` construction eliminates all but the initial
allocation.

## Trigger

Run `apply-load` soroswap. `add host object` zone shows 2.79% trace time
across 1M calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs::HostImpl::default`
  — `objects` field initialized to empty `Vec`
- `src/rust/soroban/p26/soroban-env-host/src/host.rs::add_host_object`
  — push site
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:380-520`
  — per-invocation `Host` construction

## Evidence

- 1M `add_host_object` calls with mean ~9µs (2.79% of 10.3s trace).
- Each invocation creates a fresh `Host`, so the Vec restarts at capacity 0.
- Pre-sizing is a one-line change with no semantic impact.

## Anti-Evidence

- The `add_host_object` cost is dominated by `Budget::charge(VisitObject, 1)`,
  not by Vec push. Budget charge is metered and protocol-visible — exhausted
  by meta-pattern 16.
- Even if Vec reallocation contributes ~10% of `add_host_object` self time,
  that's 0.28% of trace = ~0.5ms per ledger non-Tracy, far below 1% noise floor.
- Per meta-pattern 25, sub-µs Tracy zones are over-measured; the real
  Vec-growth cost in production is even smaller.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — not previously investigated

### Why It Failed

Quantitative sizing puts the upper bound far below the 1% noise floor
and well below the Medium 3% threshold required by the objective:

- Vec growth from 0→256 with 48-byte HostObject enum: 7 reallocations,
  ~6KB cumulative memcpy. Allocator + memcpy cost ~1µs total per invocation.
- 7891 invocations × 1µs = 8ms total work.
- Divided across 8 parallel workers in apply: ~1ms wall-clock saving per
  benchmark run.
- Soroswap apply baseline is 218ms; 1ms = 0.46% which is below the 1%
  Low threshold and well below the 3% Medium threshold this objective
  requires.

Additionally, the dominant cost in `add_host_object` is the metered
`Budget::charge(VisitObject, 1)` call, not the Vec push. The Vec push
is a small minority of the zone's time, and reducing it doesn't change
the metering work.

### Lesson Learned

Sub-Medium-tier allocator/capacity tunings inside the host should be
deprioritized unless they appear in a serial pre/post-apply phase or
they aggregate to a clearly visible delta. For per-invocation parallel
work, divide measured impact by `NUM_CLUSTERS` (8) before sizing against
the Medium 3% bar.
