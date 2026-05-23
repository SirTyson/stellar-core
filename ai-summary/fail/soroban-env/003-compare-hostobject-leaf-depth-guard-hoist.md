# H003: Hoist Depth-Guard Out of Leaf-Type `Compare<HostObject>` Cases

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Reduce per-call overhead in `Compare<HostObject>::compare` for non-recursive (leaf) variant pairs by skipping the `budget_cloned()` + `with_limited_depth` `RefCell` enter/leave guard
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Compare<HostObject>::compare` should bound recursion depth only when the
input pair can actually recurse — i.e., `Vec` vs `Vec` and `Map` vs `Map`,
which in turn delegate to `MeteredVector::compare` /
`MeteredOrdMap::compare` and ultimately back into `Compare<Val>` /
`Compare<HostObject>` on nested element values. For leaf variant pairs
(`U64`, `I64`, `TimePoint`, `Duration`, `U128`, `I128`, `U256`, `I256`,
`Bytes`, `String`, `Symbol`, `Address`, `MuxedAddress`, and the
discriminant-fallback mismatched-tag cases) the comparison is non-recursive
and cannot exhaust the depth budget. The depth guard should be wrapped only
around the cases that can recurse, not around every comparison.

## Mechanism

`Compare<HostObject>::compare` (`host/comparison.rs:46-96`) wraps every
comparison — leaf and recursive alike — in
`self.budget_cloned().with_limited_depth(|_| { ... })`. Each call therefore
performs an `Rc<RefCell<BudgetImpl>>::clone` (atomic refcount bump) plus
two `RefCell::borrow_mut` round-trips against the budget's interior cell
(`enter` decrements `depth_limit`; `leave` increments it back). The
`enter`/`leave` calls do not charge any protocol-visible budget — they only
mutate the internal `depth_limit: u32` counter — so removing them on
provably-non-recursive paths is metering-neutral. With 473,419 leaf-heavy
`Compare<HostObject>` calls in the diagnostic soroswap trace, even ~30–50 ns
of saved per-call `RefCell`/`Rc` overhead aggregates to ~15–25 ms of self
time inside `applyLedger`.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current accepted next-protocol
soroswap baseline. Every `MeteredOrdMap` lookup / insert / sortedness scan
whose `K` resolves to `HostObject` (instance storage maps, host
`HostMap`s, `MeteredOrdMap<Val, _, Host>` after the `LedgerKey` fast path
fallback) triggers a leaf-case `Compare<HostObject>::compare`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:46-96` —
  `Compare<HostObject> for Host` wraps all match arms in
  `with_limited_depth`; restructure so that only the `Vec(_) vs Vec(_)`,
  `Map(_) vs Map(_)`, and discriminant-mismatch arms enter the depth guard.
- `src/rust/soroban/p26/soroban-env-host/src/budget/limits.rs:106-114` —
  `DepthLimiter for Budget` performs `try_borrow_mut_or_err` per
  enter/leave; these are the operations skipped on the leaf fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:630-632` —
  `Host::budget_cloned` performs the `Rc<RefCell<BudgetImpl>>::clone`
  bypassed on the leaf fast path.

## Evidence

- Diagnostic soroswap trace
  (`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/...`):
  `Compare<HostObject>` records 191,293,240 ns self time across 473,419
  calls (mean ~404 ns). Soroswap calls are dominated by leaf-type keys
  (`Symbol`, `Bytes`, `Address`, `U64`) used in instance/persistent
  storage maps and SAC balance lookups, so the leaf fast path covers the
  large majority of the 473k calls.
- The depth-guard `enter`/`leave` operations do not call `Budget::charge`
  and therefore are not protocol-visible budget work; removing them on
  leaf paths preserves exact budget accounting and contract behavior.
- The `with_limited_depth` machinery exists specifically to bound
  recursion through nested `Val` containers (see comments in
  `budget/limits.rs:34-41`: "guards recursion paths involving the `Env`
  and `Budget`, particularly during operations like conversion,
  comparison, and deep cloning"). Leaf variants cannot recurse.

## Anti-Evidence

- The realistic per-call savings (`Rc::clone` ≈ 5–10 ns; two
  `RefCell::borrow_mut` cycles ≈ 20–40 ns combined) total ~30–50 ns per
  call. Across 473,419 leaf-case calls this is ~15–25 ms of CPU self time.
  Spread over the 8-thread `parallelApply` window the saved wall time is
  ~2–3 ms per ledger.
- Soroswap baseline median apply is ~218 ms; ~2–3 ms / 218 ms ≈ 0.9–1.4%
  wall-clock improvement, which is below the objective's 3% Medium floor
  and inside the benchmark-noise band (≤1%).
- The trace's 473k call count is summed across all 8 worker threads and
  many ledgers; per-ledger per-thread savings are even smaller than the
  aggregate suggests.
- Even an optimistic projection treating every call as a leaf save
  ~80 ns/call (e.g., if `tracy_span!` also disappears in non-Tracy
  builds) still tops out at ~38 ms CPU / ~5 ms wall — well below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a focused
`Compare<HostObject>` depth-guard hoist; adjacent fails
(`002-specialize-val-key-metered-map-lookups`,
`011-eliminate-is-clean-fuel-check`) treat broader `map lookup` /
per-dispatch checks but do not target this specific guard.

### Why It Failed

Projected impact is Low (sub-1% wall-clock at 8-thread parallelism after
accounting for actual `RefCell` and `Rc` micro-costs), below the
objective's required Medium severity floor for promotion. Even a
maximally optimistic ~80 ns/call saving across all 473,419 trace events
yields ~5 ms wall-time per soroswap-ledger window, which sits inside the
≤1% benchmark-noise band the objective explicitly excludes. The same
class of optimization was rejected for adjacent dispatch-defensive checks
in fail `011-eliminate-is-clean-fuel-check.md` for the same reason: small
individual per-call savings on millions of events cannot reliably clear
the noise floor.

### Lesson Learned

Per-call `RefCell` / `Rc` micro-overhead on hot Rust paths is real but
typically nets <0.5% wall-clock improvement on the soroswap apply window
because (a) the work is small (~30–80 ns per call), (b) Tracy
self-time totals sum across 8 worker threads, and (c) the
non-Tracy production path already lacks the `tracy_span!` overhead the
trace measures. Before proposing similar micro-hoist hypotheses,
project (mean_ns × calls) / NUM_CLUSTERS / soroswap_median_ms and
require ≥3% before promotion.
