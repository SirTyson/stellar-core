# H033: Cache `getTTLKey(rwKeys[j])` hash to avoid per-output SHA256 in `recordStorageChanges`

**Date**: 2026-05-25
**Subsystem**: soroban-env / transactions (InvokeHostFunctionOpFrame write-side)
**Severity**: Low
**Impact**: Apply-time micro-reduction on Soroban write-side post-invoke bookkeeping
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::recordStorageChanges` should match each
post-invoke output entry against the operation's RW-footprint TTL keys in
amortized constant time per output, with at most one SHA256 evaluation per
RW key over the whole operation. The matching key (and its hashed
`LedgerKey`) is fully known when the footprint is built in `addReads` —
nothing new is learned during `recordStorageChanges`, so a precomputed
side-table keyed on `uint256` should suffice.

## Mechanism

In the current code, `recordStorageChanges` iterates the host-returned
output entries and, for each one that looks like a TTL extension, walks the
RW footprint vector recomputing `getTTLKey(rwKeys[j])` (a SHA256-based
`LedgerKey -> LedgerKey -> Hash` chain) inside the inner loop. The deviation
from expected behavior is that the hashed TTL key is recomputed `O(R × W)`
times per operation (R = RW footprint, W = TTL output entries) instead of
the `O(R)` lower bound. The redundant SHA256s are pure-CPU and happen
synchronously on the apply critical path inside the parallel Soroban
stage worker threads.

## Trigger

Replay the soroswap apply-load benchmark (`scripts/run_apply_load_matrix.py`,
soroswap TX=2000 T=8). Every Soroban invoke that extends or rewrites at
least one persistent entry executes `recordStorageChanges` with R ≈ 6–10
RW keys and W ≈ 2–4 TTL outputs.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:641-740`
  — nested loop computing `getTTLKey(rwKeys[j])` inside the per-output
  matcher.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:380-535` —
  the call site where RW footprint TTL hashes could be precomputed once.
- `src/transactions/TransactionUtils.cpp` (`getTTLKey`) — SHA256 producer
  being called redundantly.

## Evidence

- Structural inspection: inner-loop recomputation is visible directly in
  the source; no caching of `getTTLKey` result across iterations.
- Tracy `sha256` self-time totals 6.9% of the trace (a non-trivial share),
  but most of that is host-side `Bytes::sha256` from contract execution,
  not C++ `getTTLKey`. The `recordStorageChanges` share of `sha256` is
  un-measured because the zone is not instrumented.
- Soroswap invocations average ~6 RW keys × ~3 TTL outputs ≈ 18 redundant
  SHA256s per swap. At 122 invocations/ledger × 18 ≈ 2.2k redundant
  SHA256s/ledger.

## Anti-Evidence

- Each `getTTLKey` SHA256 hashes ~40 bytes; at ~200 ns/op this is
  ~440 µs/ledger total before parallelism, or ~55 µs/ledger wall after
  the 8-way Soroban parallel stage divides the work.
- 55 µs of a ~207 ms soroswap median ledger is ≈ 0.027% — three orders
  of magnitude below the Low threshold (1%) and 100× below Medium (3%).
- The cache would add either a `flat_hash_map<size_t, Hash>` per
  operation or a parallel `std::vector<Hash>` sized to the RW
  footprint. Either adds a small allocation that may *cost* more than
  the saved SHA256s for very small footprints.
- `recordStorageChanges` already does substantial XDR re-encoding work
  that dominates the function's runtime; SHA256 caching does not move
  the dominant cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (closest is H003
`compare-hostobject-leaf-depth-guard-hoist`, which addressed a different
pattern in Rust comparison; this is C++ write-side post-invoke).

### Why It Failed

Quantitative ceiling: with ~2.2k redundant SHA256s per ledger at ~200 ns
each, the total reclaimable serial CPU is ~440 µs/ledger. Once divided
by the 8-way Soroban parallel stage, the wall-clock reduction is
~55 µs/ledger ≈ 0.027% of a 207 ms soroswap ledger — well below the
1% objective noise floor and ~100× below the Medium 3% threshold. Per
the objective context, anything sub-1% is benchmark noise and "do not
produce slop PRs that don't actually improve performance" applies.

### Lesson Learned

When sizing SHA256-related micro-optimizations: each `getTTLKey` call
hashes only ~40 bytes (vs the multi-KB `Bytes::sha256` contract calls
that dominate the `sha256` zone). Small hashes at low call counts
amortized across 8 parallel threads are structurally incapable of
clearing the Medium 3% floor on the soroswap benchmark. Multiply
out (call count × per-call cost ÷ thread count ÷ median ledger ms)
before opening any "deduplicate SHA256" hypothesis on the write-side
bookkeeping path.
