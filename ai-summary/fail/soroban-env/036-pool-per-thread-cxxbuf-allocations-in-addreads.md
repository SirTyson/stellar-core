# H036: Pool Per-Thread `CxxBuf` Allocations Across `addReads` In Parallel Workers

**Date**: 2026-05-25
**Subsystem**: soroban-env / transactions (InvokeHostFunctionOpFrame ingress bridge)
**Severity**: Low (projected sub-Medium after parallelism)
**Impact**: Reduce per-op heap allocations on the C++→Rust XDR ingress path
in parallel-apply worker threads
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:484-497`) constructs a
`CxxBuf` for every footprint LedgerEntry by calling
`toCxxBuf(*entryOpt)`. Each `toCxxBuf` (`TransactionUtils.h:370-376`)
performs `std::make_unique<std::vector<uint8_t>>(xdr::xdr_to_opaque(t))`
— two heap allocations per call (the `unique_ptr` control and the inner
`vector` backing buffer) plus the XDR write.

SHOULD: the parallel-apply worker thread should reuse a pool of
already-allocated `std::vector<uint8_t>` backing buffers across the
~hundreds of `addReads` calls it executes per cluster, sized once to the
typical footprint entry XDR size (~200–800 bytes), avoiding the
allocator round-trip per entry. The `CxxBuf` would still own its
`unique_ptr<vector>` but the vector itself would come from a per-thread
freelist whose contents survive across ops in the same cluster.

## Mechanism

Every Soroban op in the cluster pays:

```cpp
auto leBuf = toCxxBuf(*entryOpt);          // line 484
auto ttlBuf = ttlEntry ? toCxxBuf(*ttlEntry)
                       : CxxBuf{std::make_unique<std::vector<uint8_t>>()};  // 491-494
mLedgerEntryCxxBufs.emplace_back(std::move(leBuf));   // 496
mTtlEntryCxxBufs.emplace_back(std::move(ttlBuf));     // 497
```

After the Rust invoke returns, the `CxxBuf`s drop and free their
backing `vector`s. Per Soroban op with ~5 footprint entries this is
~10 `vector<uint8_t>` heap free events, plus ~10 fresh allocations on
the next op in the same worker. Modern allocators reuse arenas but
still pay metadata + small-block-list maintenance per call. The
deviation: the worker thread could amortize allocations across all
~250 ops it executes per cluster by maintaining a small per-thread
freelist of `unique_ptr<vector<uint8_t>>`.

## Trigger

Run the soroswap apply-load benchmark. Instrument `toCxxBuf` to count
calls per cluster worker; expect ~5,000–10,000 calls per cluster per
ledger across 8 workers (250 ops × 5 entries × 2 buffers each + auth
entries + ingress params). Add a thread-local
`small_vector_freelist<vector<uint8_t>>` (e.g., 64 slots, 1 KiB
preallocated each), patch `toCxxBuf` to consume from / return to the
freelist, and re-benchmark.

## Target Code

- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` template
- `src/transactions/InvokeHostFunctionOpFrame.cpp:484` — `leBuf` per entry
- `src/transactions/InvokeHostFunctionOpFrame.cpp:491-494` — `ttlBuf` per entry
- `src/transactions/InvokeHostFunctionOpFrame.cpp:564` — authEntries
- `src/transactions/InvokeHostFunctionOpFrame.cpp:579-581` — hostFunction / resources / sourceID
- `src/rust/src/bridge.rs` — `CxxBuf` shared type (would need a
  thread-local destructor hook on the Rust→C++ return path to recycle
  buffers; complex)

## Evidence

- Trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`:
  `addReads` self-time 262 ms / 17,504 events (~14,977 ns mean per op).
  A non-trivial fraction is XDR serialization + allocation for ~5
  `leBuf`s + ~5 `ttlBuf`s per op.
- Soroswap baseline ~207 ms/ledger; addReads is one of the largest C++
  apply-path zones not yet trimmed.
- Modern arenas reuse memory but the unique_ptr → vector → small-buffer
  chain still touches at least 2 cachelines per allocation/free pair.

## Anti-Evidence (and Self-Rejection)

Quantifying the allocator overhead:

- ~17,504 ops × 10 buffers/op = 175,000 `vector<uint8_t>` alloc/free
  pairs per benchmark window (~70 ledgers).
- Per pair: ~50–150 ns of pure allocator work in a tuned glibc/jemalloc
  arena (small-block-list pop/push + metadata bookkeeping).
- Total allocator-only saving (perfect freelist): 175,000 × 100 ns
  ≈ 17.5 ms aggregate.
- Per ledger after 8-way parallelism: 17.5 / 8 / 70 ≈ 0.031 ms/ledger
  ≈ 0.015% of the 207 ms baseline.

Even if the freelist also avoids the 2 cacheline misses per alloc/free
pair (~100 ns each on top of allocator work), the upper bound becomes
~50 ms aggregate / 8 / 70 ≈ 0.09 ms/ledger ≈ 0.04% — still
three orders of magnitude below the 3% Medium floor and two orders
below the 1% noise floor.

The dominant cost in `toCxxBuf` is the `xdr::xdr_to_opaque(t)` XDR
serialization itself (~hundreds of ns to ~µs per call depending on
LedgerEntry size and depth), not the heap allocation. A freelist
leaves the XDR serialization fully intact and only removes the small
allocator tail.

Additionally, threading the freelist through the `CxxBuf` lifetime
across the Rust FFI boundary is non-trivial: `CxxBuf` is the shared
cxx::bridge type owned by Rust during the invoke, and recycling its
`vector<uint8_t>` requires a coordinated destructor pathway that does
not currently exist in the cxx-generated wrapper — implementation
risk is high for sub-noise-floor benefit.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — `CxxBuf` allocation-pooling has not been explored
in prior hypotheses (H018 covered `Host.objects` Vec preallocation, a
different code path on the Rust side)

### Why It Failed

The allocator-only saving from pooling `CxxBuf` backing vectors across
`addReads` is bounded by ~0.04% of apply wall-clock time after 8-way
worker parallelism. This is three orders of magnitude below the 3%
Medium floor required by the objective, and two orders below the 1%
benchmark-noise floor. The dominant per-call cost in `toCxxBuf` is XDR
serialization, which a freelist cannot remove. Implementation also
requires coordinating buffer lifetime through the cxx FFI boundary,
which adds correctness risk well out of proportion to the saving.

This matches the well-established meta-pattern: per-call
micro-optimizations on the apply path consistently produce sub-Low
wall-clock savings after parallel-worker normalization. The same
quantification rule that rejected H018 (pre-reserve Host.objects Vec
capacity, ~0.012% of baseline) applies here.

### Lesson Learned

C++-side allocator-pooling hypotheses on the parallel-apply ingress
path are bounded by `per_call_ns × call_count / parallelism /
ledger_count`. For toCxxBuf at ~100 ns recoverable allocator cost
× 175K calls / 8 workers / 70 ledgers ≈ 0.03 ms/ledger, the ceiling is
~0.015% — well below all severity floors. Future allocator-pooling
hypotheses for the C++↔Rust XDR bridge must isolate the allocator-only
subset (excluding XDR serialization) and confirm the ceiling clears
1% before promotion.
