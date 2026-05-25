# H202: Coalesce per-container charge_bulk_init_cpy charges into one fused charge

**Date**: 2026-05-25
**Subsystem**: soroban
**Severity**: Low
**Impact**: apply time reduction via fewer per-call budget charges in container construction paths
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::add_host_object`, `HostMap::new`, `HostVec::new`, and any path going
through `MeteredContainer::charge_bulk_init_cpy` should perform the minimum
number of `Budget::charge` calls necessary to account for the construction
cost. A single fused charge with the precomputed combined cost preserves
metering semantics while halving the per-construction charge call count.

In the protocol-27-only `coalesced_host_metering` mode (success #001), the
same coalescing principle was applied to `VisitObject` and `ValSer`; an
analogous protocol-gated coalescing applied to container construction
charges (`MemCpy` + `MemAlloc` + `MemCpy` triplet in
`charge_bulk_init_cpy`) would extend the pattern to the hot
"new map"/"new vec"/"add host object" paths visible in Tracy.

## Mechanism

`charge_bulk_init_cpy` (host/metered_clone.rs:117-121) calls
`charge_shallow_copy`, then `charge_heap_alloc`, then `charge_shallow_copy`
again — three `Budget::charge` calls per container construction. Each
`Budget::charge` is metered at ~81ns self in the trace (`charge` zone:
1710ms / 21,078,947 calls). Coalescing into a single fused charge would
remove 2/3 of these calls in the container-construction path, similar to
the success #001 pattern. The actual budget total stays identical — just
the per-call dispatch overhead is reduced.

## Trigger

Run the soroswap apply-load benchmark on the next-protocol build. New
`HostMap`/`HostVec` allocations during host function dispatch (e.g.,
`new map` at 183,555 calls = 393ms self in trace, `new vec` at 121,758
calls = 109ms self) currently each emit 3 distinct `Budget::charge`
calls. The coalesced path would emit 1.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:117-121` —
  `MeteredContainer::charge_bulk_init_cpy` three-step charge sequence
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` —
  call sites for `charge_bulk_init_cpy` (HostMap)
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs` —
  call sites for `charge_bulk_init_cpy` (HostVec)
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs` —
  `Budget::charge` (per-call overhead site)

## Evidence

- Success #001 demonstrates the `coalesced_host_metering` flag pattern is
  viable and accepted for protocol-27-only charge coalescing.
- Tracy `charge` zone: 1710ms total / 21M calls / ~81ns mean — small per
  call but huge call count, with container construction contributing
  several million.
- `new map` (393ms) + `new vec` (109ms) + `add host object` (308ms) =
  ~810ms self-time aggregate (~7.9% of total trace) — the surrounding
  Rust dispatch is unavoidable but the metering call overhead is reducible.

## Anti-Evidence

- Per-call `Budget::charge` overhead is ~81ns. With ~550,000
  container-bulk-init charge calls in the trace, eliminating 2/3 yields
  367,000 × 81ns = ~30ms aggregate trace savings.
- After 8-worker parallelization and per-ledger normalization (70 ledgers),
  this is 30 / 8 / 70 = ~0.05ms wall per ledger ≈ **0.025% of apply** —
  three orders of magnitude below the 3% Medium threshold.
- The remaining work in `new map`/`new vec`/`add host object` zones is
  actual allocation + Rust vec push + object table push — those costs
  dominate and are not reducible without weaker metering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — extends the success #001 coalescing pattern to a
distinct code path (container bulk-init), not previously investigated.

### Why It Failed

Below objective severity threshold (Low not accepted at hypothesis
stage). The hot container-construction paths
(`new map`/`new vec`/`add host object`) are dominated by actual
allocation/push work, not by the `Budget::charge` dispatch overhead.
Even fully eliminating 2/3 of charge calls along the
`charge_bulk_init_cpy` path saves ~0.025% of apply wall time — well
inside benchmark noise and far below the Medium 3% threshold. This
matches Meta-Pattern #14 (per-call host micro-opts × N_calls /
NUM_CLUSTERS / N_ledgers are systematically sub-Low).

### Lesson Learned

Success #001's 2.10% win on `VisitObject` + `ValSer` coalescing came from
those charges being called even more frequently (millions per ledger) AND
the eliminated work including the Tracy span emission, not just the
charge dispatch itself. Container-construction charges already lack Tracy
spans and have a much smaller per-call multiplier, leaving no room for
a Medium-tier win on this surface. Future coalescing proposals on host
charges should first compute the (trace_self_ms × coalesce_fraction) /
(NUM_CLUSTERS × N_ledgers) wall-impact bound before writing up.
