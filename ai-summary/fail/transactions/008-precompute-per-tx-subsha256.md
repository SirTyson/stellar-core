# H008: Precompute Per-Tx subSha256 Sub-Seeds Out of applyThread Worker Loop

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: Per-tx worker setup
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyThread` (src/ledger/LedgerManagerImpl.cpp:2483) should call `TransactionFrame::parallelApply` for each `TxBundle` in a cluster without performing any tx-specific work that is independent of the cluster ordering. Concretely, the per-tx `Hash txSubSeed = subSha256(sorobanBasePrngSeed, txBundle.getTxNum())` at line 2500 depends only on the cluster-invariant `sorobanBasePrngSeed` and the bundle's tx number, both known during the serial bundle-build phase. The expected behavior is to compute `txSubSeed` once per tx in the serial bundle-build loop (in `applyParallelPhase`, lines 2966–3032) and store it inside the `TxBundle` so the worker simply reads it.

## Mechanism

The current implementation computes `subSha256` on every worker thread for every tx in the cluster (`applyThread` at line 2500). `subSha256` does one SHA256 init, one 32-byte seed feed, one 8-byte `xdr_to_opaque(uint64_t)` allocation+feed, and one `finish()`. That is hot-path-allocating cryptographic work executed inside the parallel worker, even though the result is fully determined by inputs known at serial bundle build time. Hoisting it to the build loop would remove cryptographic work from the worker critical path and replace it with a single load of a precomputed Hash.

## Trigger

Run the soroswap apply-load benchmark; each parallel-apply ledger executes ~197 txs through 8 workers, each tx executes `subSha256` once.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2521` — `applyThread`
- `src/ledger/LedgerManagerImpl.cpp:2500` — `Hash txSubSeed = subSha256(...)` per-tx worker call
- `src/ledger/LedgerManagerImpl.cpp:2966-3032` — `applyParallelPhase` serial bundle-build loop where the precomputation would land
- `src/transactions/ParallelApplyStage.h` — `TxBundle` would need an extra `Hash mTxSubSeed` field
- `src/crypto/SHA.cpp:41-48` — `subSha256` implementation

## Evidence

- `applyThread` calls `subSha256` per tx inside the worker loop; for the soroswap apply-load configuration there are ~14,036 parallel-apply tx invocations across 71 ledgers, T=8 workers.
- `subSha256` performs cryptographic work plus a small allocation for `xdr::xdr_to_opaque(uint64_t)`; this is not amortized in any way today.
- The serial bundle-build loop already iterates every tx and could compute the sub-seed at zero marginal cost.

## Anti-Evidence

The Tracy trace has no dedicated `subSha256` zone, but the parent `sha256` zone (crypto/SHA.cpp:33) aggregates 634,332,540 ns across 458,062 calls (mean 1,384 ns per call), and `add` (crypto/SHA.cpp:65) aggregates 292,106,493 ns across 1,513,960 calls. The subSha256 share is a small fraction of these globals — the per-tx soroswap subSha256 calls are 14,036 / 458,062 = ~3% of global SHA256 invocations. Bounding optimistically:

- ~14,036 subSha256 calls × ~5 µs each ≈ 70 ms aggregate worker time across the trace.
- Critical-path savings: 70 ms / 8 workers / 71 ledgers ≈ 123 µs/ledger ≈ 0.05% of soroswap close time.

This is far below the 1% Low floor and well under benchmark noise. The optimization also moves the work from the parallel phase (which can absorb some non-critical-path microseconds when workers are not load-bound) to the serial bundle-build phase (which is on the critical path), so the net soroswap apply-time benefit may be even smaller or zero.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from fail records 009-hoist-loadheader-out-of-bundle-build-loop, 016-pool-allocate-per-tx-state-objects (per-tx allocation in serial loop), and 003-precompute-modified-classic-keys-hashset.

### Why It Failed

The per-tx subSha256 call is real worker-path work, but its addressable cost (~123 µs/ledger critical-path even under the most optimistic bound) is sub-1% of soroswap close time and well below benchmark noise. Hoisting also transfers the work from parallel worker time to serial bundle-build time, which is itself on the apply critical path; for T=8 the transfer is not a net win unless workers are otherwise CPU-saturated and balanced, which the soroswap trace does not demonstrate. Per Meta-Pattern 9 (Pre-Parallel-Apply Phase Is Thin), the serial setup phase has no slack to absorb additional per-tx work either.

### Lesson Learned

Worker-side per-tx cryptographic helpers like `subSha256` look hoistable in principle, but they need both (a) a per-ledger critical-path bound that clears the noise floor and (b) confirmation that hoisting to the serial phase does not just shift the cost. For soroswap, the per-tx subSha256 fails (a) by an order of magnitude and would also fail (b). Future per-tx worker-hoist hypotheses must compute the post-hoist critical-path cost in both phases before promotion.
