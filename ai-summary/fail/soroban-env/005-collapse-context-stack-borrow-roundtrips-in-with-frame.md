# H005: Collapse Repeated `context_stack` RefCell Borrow Round-Trips in `with_frame`

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: Apply-time reduction via removed `RefCell::try_borrow` round-trips on every contract frame push
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`Host::with_frame` (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-498`)
should perform the minimum bookkeeping necessary to push a `Context` onto the
context stack: one depth check, one auth-frame push (via `push_context`), one
storage map clone (for the rollback point), one trace-hook lookup, and (under
`testutils`) one cycle of coverage/contract-invocation hook bookkeeping. Any
RefCell access to `context_stack` along that path should be a single borrow
held just long enough to read or mutate the underlying `Vec<Context>`.

## Mechanism

`with_frame` currently performs five independent `try_borrow_context_stack()`
round-trips on the hot path **before** invoking the frame closure (lines 440,
450, 467, 475, 476). Each `RefCell::try_borrow` does a relaxed atomic check
of the borrow flag (~3–5 ns on contended hardware), a length read on the
inner `Vec<Context>`, and drops the guard at scope exit. These round-trips
exist because the code is written defensively for the testutils/coverage hook
and trace-hook layers, but the runtime layout means a single borrow plus a
saved `last_index` would suffice. The actual deviation from expected
behavior: ~5 redundant borrow guards per `with_frame` call.

Soroswap apply pushes ~48,000 contexts per benchmark window
(`push context` zone counts = 48,381). Collapsing five borrows to one would
remove ~20 ns of RefCell work per call × 48,381 calls = ~970 µs aggregate per
benchmark window across all 71 ledgers and 8 worker threads. Normalized by
8-way parallelism: ~120 µs wall total = ~1.7 µs per ledger wall = sub-0.001%
of the 207 ms soroswap apply baseline.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the soroswap workload. Every contract
frame entry — pool getter native frames, pair swap native frames, router
Wasm frames, SAC transfer frames — passes through `with_frame` and pays the
five borrow round-trips.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-498` —
  `with_frame` body with five `try_borrow_context_stack()` calls before the
  closure invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:222-237` —
  `push_context` body which itself performs additional borrows on
  `authorization_manager` and `storage`.

## Evidence

- Five distinct `try_borrow_context_stack()` round-trips on the pre-closure
  hot path (lines 440, 450, 467, 475, 476).
- 48,381 `push context` events per benchmark window (Tracy zone counts).
- The borrows are independent and could be collapsed without changing
  semantics: the depth check, the testutils v-to-v scoreboard, the trace
  hook context lookup, and the top-contract-invocation hook all read the
  same `context_stack` length and last-element snapshot.

## Anti-Evidence

- Each `RefCell::try_borrow` is unmetered Rust internal bookkeeping
  (~3–5 ns). The aggregate savings ceiling is far below the 1% Low floor.
- Three of the five borrows are gated behind `#[cfg(any(test, feature =
  "testutils"))]` and only execute in test builds — production benchmark
  builds pay only two of the five borrows.
- The `RefCell` pattern is intentional defensive coding; collapsing the
  borrows requires holding a guard across closures that themselves may
  attempt to borrow other host fields, which risks panicking the borrow
  checker in adjacent diagnostic paths.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a discrete hypothesis
(adjacent fail/003-add-host-object-merge-borrow targets `add_host_object`,
not `with_frame`)

### Why It Failed

Quantitative ceiling: ~5 borrows × ~5 ns × 48,381 calls = ~1.2 ms aggregate
per benchmark window, normalized to ~150 µs wall after 8-way parallelism
across 71 ledgers = ~2 µs/ledger wall = ~0.001% of the 207 ms soroswap
apply baseline — four orders of magnitude below the 3% Medium floor and
three orders below the 1% Low noise floor. Even in test builds the savings
do not change order of magnitude.

The objective accepts only Medium (≥3%) and High (≥10% or dominant-phase
redesign) findings. This hypothesis is below the objective's severity
threshold, matching Meta-Pattern #15 (C++ Apply-Path Bookkeeping Has a
Strict Parallel-Worker Normalization Ceiling) applied to the Rust side.

### Lesson Learned

`RefCell::try_borrow` micro-optimization on `with_frame`-class entry points
is sub-Low even at ~48K events per benchmark window. Future per-frame
bookkeeping hypotheses must clear `(removable_ns × call_count) / parallelism
/ ledger_count / baseline_ns ≥ 3%` before promotion. For a 207 ms baseline
soroswap workload with 8-way parallelism and ~50K hot-path entries, the
per-call removable ns must be ≥4 µs to clear Medium — far above the
~20 ns ceiling for collapsible RefCell borrows.
