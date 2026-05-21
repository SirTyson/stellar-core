# H046: Stack-allocate `SignatureChecker` on the Soroban apply path instead of `std::make_unique`

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban pre-parallel-apply signature check
**Severity**: Low
**Impact**: Sub-noise — projected ≤30 µs/ledger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::commonPreApply` (line ~1209) and
`TransactionFrame::commonParallelPreApplyReadOnly` (line ~2154) construct a
`SignatureChecker` for every transaction during apply. The expected efficient
path is that the per-tx `SignatureChecker` lives on the caller's stack for the
duration of `commonValid` + `processSignatures`/`processSignaturesReadOnly` and
the operation `checkValid` pass, and is destroyed without involving the global
allocator.

## Mechanism

Today both call sites use `std::make_unique<SignatureChecker>(...)`
(`TransactionFrame.cpp:2164`, and the analogous site in the sequential
`commonPreApply` path) and return the `unique_ptr` to the caller, which uses
`*signatureChecker` and discards it at scope end. The deviation from expected
behavior is that this introduces one heap allocation + one heap free per
Soroban transaction in the apply window, plus an extra layer of pointer
indirection on every `SignatureChecker` method call. The `unique_ptr` return
shape is only there to express "nullptr means failure"; a `std::optional` or a
`bool` + by-value stack object would express the same contract without the
allocator round-trip.

## Trigger

Run the current soroswap apply-load benchmark per `ai-summary/CURRENT_STATE.md`.
Each parallel Soroban transaction enters `commonParallelPreApplyReadOnly` once
on a worker thread, which heap-allocates a `SignatureChecker` and then frees it
at the end of the per-tx pre-apply phase.

## Target Code

- `src/transactions/TransactionFrame.cpp:2154-2197` — `commonParallelPreApplyReadOnly` constructs `std::unique_ptr<SignatureChecker>` and returns it
- `src/transactions/TransactionFrame.cpp:2282-2298` — caller `preParallelApplyReadOnly` dereferences and discards
- `src/transactions/TransactionFrame.cpp:~1209` — sequential `commonPreApply` uses the same pattern
- `src/transactions/SignatureChecker.h/.cpp` — base type plus `AlwaysValidSignatureChecker` subclass (under `BUILD_TESTS`)

## Evidence

- Soroswap apply-window Soroban tx count: ~2,000 tx/ledger × 71 ledgers =
  ~142,000 per-tx `SignatureChecker` constructions in the trace.
- Each `make_unique<SignatureChecker>` + matching `unique_ptr` free is a
  malloc/free pair; on modern glibc this is ~50–100 ns per pair for a
  ~64-byte allocation.

## Anti-Evidence

- `BUILD_TESTS` swaps in an `AlwaysValidSignatureChecker` subclass via
  polymorphism (`TransactionFrame.cpp:2158`), so converting to a by-value
  return requires either (a) `std::variant<SignatureChecker, AlwaysValidSignatureChecker>`,
  (b) a `LIKELY` runtime branch with two stack objects, or (c) refactoring
  `AlwaysValidSignatureChecker` into a flag on the base class. All add code
  complexity for a sub-threshold win.
- The cost of `verifySig` and the underlying ed25519 verification (cached or
  not) dwarfs the allocator round-trip by several orders of magnitude.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not present in any existing fail/hypothesis/reviewed/poc
record. Distinct from `011-cache-apply-signature-results.md` (which caches the
*result* of signature verification across calls) and from
`010-cache-tx-stateless-validation-on-frame.md` (which caches the *outcome* of
`commonValidPreSeqNum` on the TransactionFrame). This hypothesis targets the
per-tx heap-allocation of the SignatureChecker *object*.

### Why It Failed

Quantitative ceiling is far below the objective threshold:

- Apply-window Soroban tx count per ledger: ~2,000.
- Per-tx allocator round-trip for `SignatureChecker` (~64-byte object):
  ~75 ns including matching free.
- Aggregate per-ledger removable cost on a worker thread: 2,000 × 75 ns ≈
  150 µs. After cluster parallelism (8 workers) the critical-path ceiling is
  ~19 µs/ledger ≈ 0.007% of the 272 ms soroswap median.
- The Medium floor is 3% (~8.2 ms/ledger). The removable saving is more than
  three orders of magnitude below threshold.

Additionally, `BUILD_TESTS` polymorphism (`AlwaysValidSignatureChecker`) makes
the obvious refactor non-trivial. Any benefit is invisible relative to
benchmark noise, while the change adds code complexity to a critical
correctness path.

### Lesson Learned

Per-tx heap allocations on the apply path that involve small (<128-byte)
objects with simple lifetimes are individually bounded at sub-millisecond
removable cost per ledger after cluster parallelism. Heap-vs-stack
micro-optimizations on the transactions subsystem cannot reach the Medium
floor in isolation, and `BUILD_TESTS` polymorphism often blocks the
straightforward refactor. Future allocation-elision hypotheses must either
(a) target a per-host-call or per-host-import allocation that runs millions
of times per ledger, or (b) bundle multiple small allocations into a single
arena-style change that is measurable against benchmark noise.
