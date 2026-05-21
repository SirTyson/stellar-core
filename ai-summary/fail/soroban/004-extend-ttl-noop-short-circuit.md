# H004: Short-circuit `extend_ttl` when current TTL exceeds extend_to

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Low
**Impact**: redundant MeteredOrdMap lookup on TTL-extend host calls
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Storage::extend_ttl` (`storage.rs:532-574`) extends a key's
`live_until_ledger_seq` to be `extend_to` ledgers in the future, *only if*
`current_ttl <= threshold`. When the entry's existing TTL is already past
the requested extension target (a common case for hot soroswap pool
entries whose TTL was bumped by an earlier call in the same ledger or stage),
the call SHOULD be a fast no-op: a cheap comparison of cached/known TTL
metadata against `extend_to`, returning `Ok(())` without doing the
`MeteredOrdMap` probe or the per-call `TtlExtensionInfo` materialization.

## Mechanism

The ACTUAL implementation unconditionally calls `prepare_extend_ttl` first,
which does a `get_with_live_until_ledger` probe (MeteredOrdMap binary
search + budget metering) and constructs a `TtlExtensionInfo` clone, *only
then* checks `current_ttl <= threshold` to decide whether to call
`apply_ttl_extension`. The lookup and info clone happen on every call,
including the no-op path. For workloads with high `extend_ttl` call counts
(soroswap: 94908 `extend key` calls across the trace), the lookup cost on
the no-op path is wasted work.

## Trigger

Soroswap benchmark. The `extend key` span at `storage.rs:540` fires on every
TTL extend, of which a large fraction are no-ops because the same TTL was
bumped by an earlier call against the same key.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:532-574` —
  `extend_ttl` body, threshold-check after probe
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:433-498` —
  `prepare_extend_ttl` does the unconditional MeteredOrdMap probe
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:594-643` — v2
  variant has different control flow (probe before min_extension check)

## Evidence

Tracy: `extend key` 50.4ms self / 94908 calls / 8 clusters / 71 ledgers
= 88µs/ledger Tracy. Total Tracy time 115ms / 71 / 8 ≈ 203µs/ledger.

## Anti-Evidence

(1) The probe also serves correctness: it validates the key is in the
footprint and the entry is live; skipping it requires hoisting these
checks elsewhere or adding a fast-path that still enforces them. (2)
Per-ledger Tracy time of ~88µs (self) or ~200µs (total) translates to
roughly 0.3-0.7ms per real-benchmark ledger after Tracy scaling — i.e.
0.1-0.3% of the 273ms soroswap median. Even eliminating the probe entirely
on every no-op call cannot reach the 1% Low threshold, much less 3% Medium.
(3) The MeteredOrdMap probe cost is metered against the contract budget;
skipping it would require also skipping the budget charge, which has
correctness implications (fail meta-pattern #11: budget charge accumulator
needs exact rounding).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail #005 (`extend-instance-and-code-ttl-redundant-per-call`),
which targeted *eliminating redundant calls* from SAC `transfer`. This
hypothesis instead targets making each call *cheaper* via a no-op
short-circuit; both angles independently fail the objective threshold.

### Why It Failed

The `extend key` Tracy total (115ms / 94908 calls) is structurally below
the Medium floor: even an optimistic 100% elimination of the probe on the
no-op path saves at most ~0.3% of soroswap apply time after Tracy-to-real
scaling. Additionally, the probe carries mandatory budget metering and
footprint enforcement that cannot be skipped without semantic changes.

### Lesson Learned

For Soroban host-function no-op short-circuit hypotheses, size the
target span's total Tracy time against the benchmark median first.
Anything below ~1ms/ledger Tracy total cannot clear Medium. Also remember
that host-side storage probes carry budget metering that must be preserved
for determinism (meta-pattern #11), so "skip the probe" optimizations
require redesigning the budget interaction, not just the probe call.
