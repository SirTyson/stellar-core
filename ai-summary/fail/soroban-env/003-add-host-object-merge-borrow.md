# H003: Merge Dual `objects` `RefCell` Borrows in `add_host_object`

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Save one `RefCell::borrow` round-trip per `add_host_object`
call by computing the new index from the same mutable borrow used to push
the object
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::add_host_object` should perform a single mutable borrow of the
`HostImpl.objects` `RefCell` per call: read `len()` to derive the new
absolute handle, then push the injected `HostObject`. The current
implementation takes a shared borrow to read the length, drops it, then
takes a fresh mutable borrow to push — performing two independent
`RefCell` operations and an extra dynamic borrow-check on every call.

## Mechanism

`add_host_object` (`host_object.rs:446-458`) executes
`self.try_borrow_objects()?.len()` (shared borrow + drop), then
`index_to_handle`, then `metered_clone::charge_heap_alloc::<HostObject>`,
then `self.try_borrow_objects_mut()?.push(...)` (mutable borrow + drop).
Merging into a single `try_borrow_objects_mut()?` whose `len()` is read
before `push()` removes one full borrow cycle. The borrow-cycle saving
is purely structural — no charge calls or observable side effects are
removed, so budget accounting and behavior are preserved. With 1,002,406
`add_host_object` invocations recorded in the diagnostic soroswap trace,
removing one ~10 ns `RefCell::borrow` per call aggregates to ~10 ms of
self time inside `applyLedger`.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current accepted next-protocol
soroswap baseline. Every host-object allocation (vec/map creation, bytes
construction, SAC asset metadata access, balance read materialization,
auth payload assembly) enters `add_host_object` and pays both borrows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-458` —
  `add_host_object` performs two borrows; replace with a single
  `borrow_mut` whose `len()` is read before `push`.
- `src/rust/soroban/p26/soroban-env-host/src/host/error.rs` —
  `TryBorrowOrErr` provides `try_borrow_or_err` and
  `try_borrow_mut_or_err`; the merge requires only the latter.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:430-440` —
  `absolute_to_relative` has the symmetric two-borrow pattern on the
  relative-objects table; merging both is a natural pair.

## Evidence

- Diagnostic soroswap trace
  (`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/...`):
  `add host object` records 286,504,185 ns self time across 1,002,406
  calls (mean ~285 ns). RefCell `borrow` / `borrow_mut` round-trips are
  ~5–10 ns each in optimized builds.
- The two borrow operations are not separated by any code that depends on
  the borrow being released; `index_to_handle(self, index, false)?` does
  not touch `self.0.objects`, and `metered_clone::charge_heap_alloc`
  charges budget but does not access the objects table.
- `try_borrow_objects_mut()?` already implies `try_borrow_objects()?`
  semantically — merging is metering-neutral.

## Anti-Evidence

- The saving per call is at most ~10 ns (one `RefCell` shared-borrow
  cycle); across 1,002,406 calls this is ~10 ms of CPU self time.
- Tracy totals sum across 8 worker threads. Wall-clock per-ledger saving
  is ~1.25 ms, or ~0.6% of the 218 ms soroswap baseline — below the 1%
  noise floor and three times below the 3% Medium threshold.
- Most of the 285 ns per-call mean is dominated by mandatory work:
  `charge_heap_alloc` budget charge, `HOT::inject` (which for many
  variants allocates a `Vec`/`Rc`), and the `Vec::push` itself
  (which may reallocate). The borrow round-trip is a small fraction.
- The non-Tracy production path lacks the `tracy_span!("add host object")`
  zone overhead, narrowing the realistic saving further.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. The adjacent fail
`018-prereserve-host-objects-vec-capacity` targets `Vec::push` regrowth
amortization, a different concern; this hypothesis targets the borrow
round-trip overhead inside `add_host_object` itself.

### Why It Failed

Projected impact is Low (~0.6% wall-clock at 8-thread parallelism),
below the objective's Medium 3% threshold and inside the ≤1%
benchmark-noise band. The borrow round-trip is structural overhead but
each individual borrow is too cheap (~5–10 ns) for the aggregate across
1M+ events to clear the noise floor once divided by `NUM_CLUSTERS`. The
same class of conclusion was reached in `011-eliminate-is-clean-fuel-check.md`
for similarly-shaped per-dispatch defensive `RefCell` checks.

### Lesson Learned

Defensive `RefCell::borrow` round-trips on hot Rust paths look attractive
in million-event Tracy zones because of the call count, but the per-call
cost (~5–10 ns) places the aggregate well below the apply-time Medium
floor after dividing by `NUM_CLUSTERS` parallelism. Before promoting
hypotheses of this shape, compute `(saved_ns_per_call * calls) /
NUM_CLUSTERS / soroswap_median_ms` and require the result to clear 3%.
