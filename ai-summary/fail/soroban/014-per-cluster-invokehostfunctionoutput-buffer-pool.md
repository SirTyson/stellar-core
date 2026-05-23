# H014: Per-Cluster-Worker `InvokeHostFunctionOutput` Buffer Pool

**Date**: 2026-05-23
**Subsystem**: soroban (apply path — Rust/C++ bridge)
**Severity**: Low (sub-threshold)
**Impact**: Amortize per-tx `rust::Vec`/`std::vector` allocator churn
in the parallel-apply worker bridge by pooling output buffers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each invocation of `InvokeHostFunctionOpFrame::doParallelApply` in a
parallel-apply cluster worker constructs a fresh
`InvokeHostFunctionOutput { modified_ledger_entries: rust::Vec<RustBuf>,
contract_events: rust::Vec<RustBuf>, diagnostic_events:
rust::Vec<RustBuf>, ... }` and the C++ side likewise creates fresh
`mLedgerEntryCxxBufs`, `mTtlEntryCxxBufs`, and `authEntryCxxBufs`
`std::vector<CxxBuf>` members. All these vectors start empty and grow
via `push_back`/`emplace_back` as the tx is processed; capacity is
released when the per-tx scope ends. An efficient design would keep
a per-worker pool of pre-allocated buffer vectors and `clear()` (rather
than `~Vec()` + `new Vec()`) them between txs, so each cluster worker
amortizes vector storage allocations across its tx run instead of
paying allocator round trips per tx.

## Mechanism

A cluster worker processes ~110/8 ≈ 14 soroswap txs per ledger × 71
ledgers ≈ 1,000 txs over the benchmark. Each tx constructs and
destroys ~6 `Vec`/`std::vector` containers across the bridge
(`modified_ledger_entries`, `contract_events`, `diagnostic_events`,
`mLedgerEntryCxxBufs`, `mTtlEntryCxxBufs`, `authEntryCxxBufs`). With
NUM_CLUSTERS=8 that's ~48k vector construct/destruct cycles across the
run. Each cycle is one or two reallocations (start at capacity 0,
grow to ~10) plus a final free — bounded by jemalloc tcache so per
cycle ≈ 200–400 ns of allocator path. Pooled per-worker buffers
would `clear()` instead, dropping the allocator cost to a refcount
decrement on the held capacity.

The ACTUAL deviation: vector capacity that is identically-sized
across the worker's tx run is freed and re-allocated per tx, when it
could be retained across the worker's lifetime.

## Trigger

Run the soroswap apply-load benchmark. The construct/destruct pairs
for these vectors execute on the parallel-apply worker hot path
inside `applyThread`/`applyOp`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:540-590` —
  `invokeHostFunction` per-call construction of `authEntryCxxBufs`
  and consumption of `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:484-497` — per-tx
  `mLedgerEntryCxxBufs.emplace_back` / `mTtlEntryCxxBufs.emplace_back`
  growth from default capacity.
- `src/rust/src/contract.rs` (`InvokeHostFunctionOutput` struct) —
  the `rust::Vec` output fields that are constructed per call.
- `src/ledger/LedgerManagerImpl.cpp:2537-2620` —
  `applySorobanStageClustersInParallel` worker loop, the natural
  scope for a per-worker buffer pool.

## Evidence

- Each tx allocates and frees the same vector shapes (output entries
  ≈ footprint RW count ≈ 6, event count ≈ 3, diagnostic count = 0
  in production mode, auth entries ≈ 1 for SAC, etc.) — a textbook
  reuse pattern.
- The pool would be per-worker (thread-local), so no cross-thread
  synchronization is required; the per-cluster worker structure
  already exists (`TxParallelApplyLedgerState`, `applyThread`).
- Soroban diagnostic/event vectors are accessed via stable APIs that
  could accept a non-owning `clear()` semantic without changing the
  bridge contract.

## Anti-Evidence

- jemalloc's tcache makes small-vector allocator round trips
  extremely cheap (sub-200 ns for the empty-and-small case).
- The Rust-side `rust::Vec<RustBuf>` is constructed inside the host
  call frame and ownership is transferred across FFI — pooling
  requires either an out-parameter convention change to the cxx
  bridge function or a separate per-worker context struct passed
  through `InvokeHostFunctionOutput`. The current `cxx::Bridge`
  layout returns the struct by value.
- Per-tx capacity is not stable across the run: a tx that emits 10
  diagnostic events would balloon the pooled vector, then leave it
  oversized for the next tx. Net memory waste is small but
  non-zero.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail record targets cross-tx buffer
pooling for the parallel-apply worker bridge specifically. The
closest fails (006 `host-objects-vec-pre-reserve`, 042
`txparallelapplyledgerstate-per-tx-construction`, 043
`host-function-metrics-stack-fields-reorder`) target adjacent but
distinct allocation sites.

### Why It Failed

Arithmetic puts the recoverable wall time deep below the 1% Low
floor and matches Meta-Pattern #14 (sub-millisecond apply-thread
serial paths are exhausted):

- ~6 vector construct/destruct cycles × ~7,900 tx ≈ 47k cycles.
- Per cycle cost (under jemalloc tcache, empty-then-small Vec): ≈ 300
  ns of allocator + initial grow path.
- Aggregate worker CPU saved: ~47k × 300 ns ≈ 14 ms across the
  benchmark.
- After 8-way cluster parallelism normalization: ~1.8 ms wall-clock
  total across 71 ledgers.
- Per ledger: ~25 µs.
- Against the 218 ms soroswap baseline: ~0.012%.

This is roughly three orders of magnitude below the 1% Low floor and
~250× below the 3% Medium threshold. The cross-FFI changes required
to safely retain `rust::Vec` capacity across calls (out-parameter
convention plus a per-worker pool context plumbed through the cxx
bridge) are not worth the recoverable surface.

The C++-side `std::vector<CxxBuf>` members could in principle be
pre-reserved with `reserve(footprint.size())` (a one-line change) at
the start of `addReads`, but this captures only ~0.001% of apply time
— the underlying `std::vector` growth is already amortized by
geometric doubling, and tcache makes the freed-and-reallocated
capacity essentially free.

### Lesson Learned

Per-tx vector construct/destruct cycles on the parallel-apply worker
bridge are bounded by tcache allocator cost (~300 ns/cycle) and worker
tx count (~1k/worker), capping total recoverable wall-time at
~0.02% of soroswap apply time after 8-way parallelism normalization.
Any future "pool/pre-reserve vector storage on the bridge" hypothesis
must demonstrate either (a) the allocation count per tx is much higher
than 6 (e.g., dozens of small allocs proven from Tracy `add_host_object`
or jemalloc histogram), or (b) the per-allocation cost is much higher
than 300 ns (e.g., a Vec that grows past tcache size). Otherwise it
falls under Meta-Pattern #14 and should not be written up as a hypothesis.
