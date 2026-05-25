# H034: Replace `unique_ptr<AbstractEntry>` polymorphic wrapper in `InMemorySorobanState` with heterogeneous `uint256` lookup

**Date**: 2026-05-25
**Subsystem**: soroban-env / ledger (InMemorySorobanState read path)
**Severity**: Low
**Impact**: Apply-time micro-reduction on Soroban read-side `addReads` path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InMemorySorobanState::get` (and the `unordered_set` that backs it) should
look up an entry by its TTL `keyHash` (a `uint256`) using a single hash
table probe with no heap allocation. The `LedgerKey -> keyHash` SHA256 is
already computed once by the caller in `addReads`; the lookup itself
should be O(1) hash equality on a 32-byte digest.

## Mechanism

The current `InternalContractDataMapEntry` wraps each stored entry behind
a `std::unique_ptr<AbstractEntry>` with a virtual `keyHash()` and a
virtual `operator==` that itself recomputes a SHA256 in some code paths.
The deviation from expected behavior is that each `get(key)` lookup
constructs a heap-allocated `QueryKey` wrapper (`std::make_unique`),
dispatches `keyHash()` through a vtable, then on collision dispatches
`operator==` through another vtable — incurring per-lookup allocation,
indirection, and pointer-chasing the prefetcher cannot foresee. A
C++20 transparent (`is_transparent`) heterogeneous `unordered_set` keyed
directly on `uint256` would eliminate all three costs.

## Trigger

Replay the soroswap apply-load benchmark. Each Soroban invocation calls
`InvokeHostFunctionOpFrame::addReads` which performs one
`InMemorySorobanState::get` per RW + RO footprint key — roughly
~15 lookups/invocation × ~122 invocations/ledger ≈ ~1.8k lookups/ledger.

## Target Code

- `src/ledger/InMemorySorobanState.h:InternalContractDataMapEntry:88-300`
  — polymorphic `unique_ptr<AbstractEntry>` wrapper and virtual `keyHash()`
  / `operator==`.
- `src/ledger/InMemorySorobanState.cpp` — the `unordered_set` lookup
  call sites that would adopt the heterogeneous lookup hash/eq.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:380-535` —
  caller producing the SHA256 `keyHash` that would feed the heterogeneous
  lookup directly.

## Evidence

- The polymorphic indirection is structurally visible in the header:
  every `get(key)` materializes a `unique_ptr<QueryKey>` on the heap
  and reaches the stored entry through a vtable. C++20
  `unordered_set<T, Hash, Eq>` with `is_transparent` would skip the
  wrapper allocation entirely.
- Per-lookup overhead estimate: ~50–150 ns (heap alloc + indirection +
  potential `operator==` SHA256). With ~1.8k lookups/ledger that is
  ~90–270 µs/ledger of CPU.

## Anti-Evidence

- Even at the upper bound (270 µs/ledger CPU), the `addReads` work is
  performed inside the 8-way parallel Soroban apply stage, so the
  wall-clock reduction is ~34 µs/ledger ≈ 0.016% of a 207 ms soroswap
  ledger.
- A heterogeneous-lookup refactor touches every call site and every
  insertion path of `InternalContractDataMapEntry`, with non-trivial
  risk of subtle key-collision or equality semantics drift. The
  cost-benefit ratio is heavily negative.
- The fail summary's Meta-Pattern #14 explicitly excludes per-lookup
  micro-optimizations whose per-op savings are below ~10 µs at this
  call frequency.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated for the InMemorySorobanState
read path (closest is H023 `deduplicate-instance-lookup` which targeted a
different lookup site and failed on budget preservation).

### Why It Failed

Quantitative ceiling: ~1.8k lookups/ledger × ~150 ns/lookup ≈ 270 µs of
CPU per ledger before parallelism; after 8-way Soroban-stage division
≈ 34 µs/ledger wall = ~0.016% of a 207 ms soroswap ledger. This is
~60× below the 1% noise floor and ~180× below the Medium 3% threshold.
The objective's severity scale rejects anything below 1% as benchmark
noise.

### Lesson Learned

Heap-alloc + vtable indirection per lookup is structurally suspect, but
on the soroswap apply path the absolute call count (~1.8k/ledger) is
too low to clear even the Low floor after parallelism. Pre-check
`(call_count × per_call_overhead_ns) / NUM_CLUSTERS / median_ledger_ns`
against the 1% noise floor before opening a refactor hypothesis. The
applicable rule of thumb at the current soroswap median: hot-path
micro-optimizations below ~26 ms per ledger of reclaimable CPU
(≈ 3.3 ms wall after 8-way parallelism) cannot reach Medium.
