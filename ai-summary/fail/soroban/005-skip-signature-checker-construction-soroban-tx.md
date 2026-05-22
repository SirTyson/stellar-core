# H005: Skip `SignatureChecker` Construction for Single-Signature Soroban Tx

**Date**: 2026-05-22
**Subsystem**: soroban (transactions / pre-parallel-apply)
**Severity**: Low
**Impact**: per-tx allocation/cleanup overhead in `commonParallelPreApplyReadOnly`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::commonParallelPreApplyReadOnly`
(`src/transactions/TransactionFrame.cpp:2146`) is called from the
read-only pre-parallel-apply worker pool for every Soroban tx on every
ledger. Inside it, a `std::unique_ptr<SignatureChecker>` is constructed
unconditionally before any signature work is performed. The `SignatureChecker`
constructor takes the ledger version, the contents hash, and the envelope's
signature vector by value, and initializes an internal "used signatures"
bitset/vector keyed by signature count.

For a Soroban tx whose envelope contains a single source-account signature
and whose operations are all `InvokeHostFunctionOp` (which do not require
operation-level account signatures), the `SignatureChecker` does work that
is partly redundant with the existing single-signature fast path inside
`checkSignature` (`src/transactions/OperationFrame.cpp:221`). The expected
correct behavior is that the per-tx cost of `SignatureChecker` construction
plus `processSignaturesReadOnly` is the minimum required to (a) verify the
source signature and (b) detect `txBAD_AUTH_EXTRA`.

A correct optimization would either (a) lazily construct `SignatureChecker`
only when the source-signature fast path fails, or (b) replace the
heap-allocated `unique_ptr<SignatureChecker>` with a stack `SignatureChecker`
to remove the allocation/free pair.

## Mechanism

The per-tx work in `commonParallelPreApplyReadOnly` includes a `std::make_unique`
allocation, an envelope-signature vector copy into the checker, and a
`unique_ptr` destruction at function return. For soroswap workloads with
2000 txs/ledger × 71 ledgers = 142,000 tx invocations, even a sub-microsecond
per-call savings would accumulate. The deviation from optimal is that the
allocator and the signature-vector copy are paid even on the (overwhelmingly
common) happy path where one source signature succeeds.

## Trigger

Run `scripts/run_apply_load_matrix.py` soroswap scenario. The function is
invoked from the `readOnlyPreParallelApply` worker pool
(`src/transactions/ParallelApplyUtils.cpp:526+`) for every Soroban tx.

## Target Code

- `src/transactions/TransactionFrame.cpp:2146-2197` —
  `commonParallelPreApplyReadOnly`
- `src/transactions/TransactionFrame.cpp:2201-2248` —
  `processSignaturesReadOnly`
- `src/util/SignatureChecker.h` — `SignatureChecker` constructor cost
- `src/transactions/OperationFrame.cpp:221` — `checkSignature`

## Evidence

- Trace zone `commonValid,transactions/TransactionFrame.cpp,1675` =
  99.4 M ns self over 155,782 calls = 638 ns/call.
- Trace zone `checkSignature,transactions/OperationFrame.cpp,221` =
  74.3 M ns over 224,146 calls = 332 ns/call.
- The `make_unique<SignatureChecker>` + envelope-sig copy + destructor
  is in the per-tx hot path of every pre-parallel-apply worker.
- The worker pool is already parallelized across `NUM_CLUSTERS`, so any
  per-tx win multiplies by the cluster count for wall-time gain.

## Anti-Evidence

- The read-only worker pool already shards across `NUM_CLUSTERS=8`, so
  wall-time savings are `(per_tx_savings × N_txs) / NUM_CLUSTERS`.
- The signature checker is required for `txBAD_AUTH_EXTRA` detection,
  which must run; the construction cost is at most a few hundred
  nanoseconds.
- `checkAllSignaturesUsed` requires the per-signature-index state, so a
  full removal is not possible.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. Prior fails on the
pre-parallel-apply path
(`H001-fused-soroban-fee-preapply-state.md`,
`001-detached-copy-parallel-process-fees.md`,
`001-skip-requires-sequential-pre-parallel-apply-when-classic-clean.md`)
target fee processing or the sequential-requirement predicate, not the
`SignatureChecker` allocation itself.

### Why It Failed

Sizing against the authoritative baseline:

- The whole `preParallelApply` zone (the wrapper that includes both
  `readOnlyPreParallelApply` worker work and the `commitBuffered...`
  serial writeback) is **173 M ns total wall-clock** across 71 ledgers
  = **2.44 ms / ledger** = **1.06% of the 230.225 ms baseline**.
- The `SignatureChecker` construction + signature-vector copy + destruction
  is at most a small fraction of that 1.06% — realistic optimistic
  per-call savings of ~300 ns × 142,000 calls / NUM_CLUSTERS=8 = ~5.3 ms
  **total** across the entire 71-ledger run, ≈ 0.075 ms/ledger ≈
  **0.033% of apply** — well below the **1% noise floor** stated in the
  objective, and orders of magnitude below the **Medium (≥3%)** threshold.
- This matches **Meta-Pattern #14** from `fail/soroban/summary.md`: serial
  apply-thread sub-millisecond paths combined are already <0.5% of apply
  and individually unimprovable to Medium.

### Lesson Learned

The pre-parallel-apply path is a parallelized worker pool already capped
near 1% of apply for soroswap; removing any individual per-tx allocation
inside the worker body cannot clear the Medium threshold. Future
investigations of `commonParallelPreApplyReadOnly` should focus on
**reducing the count of txs that enter the read-only worker** (e.g.,
skipping eligibility entirely for purely-Soroban-clean txs) or on
**fusing the entire pre-parallel-apply phase into a different ledger
stage**, not on micro-optimizing inside the worker body.
