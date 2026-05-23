# H014: Pre-Reserve TxParallelApplyLedgerState::mTxEntryMap Capacity from Footprint

**Date**: 2026-05-23
**Subsystem**: transaction-ledger (parallel apply)
**Severity**: Low (below objective threshold)
**Impact**: per-tx allocator + unordered_map rehash overhead
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TxParallelApplyLedgerState` (`transactions/ParallelApplyUtils.cpp`) is
constructed once per Soroban transaction inside a cluster worker. Its
`mTxEntryMap` (UnorderedMap<InternalLedgerKey, LedgerEntryPtr>) starts
empty and is populated during tx apply with entries equal to the size of
the tx's footprint (~8 keys for soroswap swap txs: RW pair contract data,
RO token instances, RW SAC balances, RO router instance, classic source
trustline). Because the map starts at default bucket count (usually 0 or
1), populating to 8 entries forces at least one rehash. Pre-reserving the
map to the known footprint size at construction would eliminate the
rehash and reduce allocator churn per tx.

## Mechanism

Each rehash performs a heap allocation for the new bucket array, walks
the existing entries, recomputes hashes, and inserts into the new bucket
array. For an UnorderedMap growing from 0 → 8 entries, libstdc++ typically
triggers rehashes at bucket counts 1, 2, 5, 11 (or similar primes
depending on the implementation), i.e. ~3 rehashes per tx. Each rehash on
a small map is sub-microsecond but cumulative across 2000 txs/ledger × 3
rehashes = 6000 small allocations/ledger.

## Trigger

Soroban-dominated soroswap workload: 2000 Soroban txs/ledger, each with
~8 footprint entries.

## Target Code

- `transactions/ParallelApplyUtils.cpp:TxParallelApplyLedgerState`
  constructor (per-tx instantiation site).
- `transactions/ParallelApplyUtils.cpp:upsertEntry` and
  `commitChangesFromSuccessfulTx` — sites that drive the map growth.

## Evidence

- Tracy `upsertEntry` self-time 48.77 ms total / 71 ledgers / 8 clusters
  = 86 µs/cluster/ledger. Modest but real.
- Soroswap footprint is bounded and known at tx construction time
  (`TransactionFrame::sorobanResources().footprint`).
- libstdc++ `unordered_map` allocator and rehash cost is well-documented
  per-rehash overhead in the 100–500 ns range for small maps.

## Anti-Evidence

- Upper bound on saving: 2000 txs × 3 rehashes × 500 ns = 3 ms/ledger
  ÷ 8 clusters (parallel) = 375 µs/cluster/ledger critical path = ~0.17%
  of 218 ms soroswap median. Far below the 3% Medium floor and below
  the 1% noise floor.
- tcmalloc_minimal (already enabled per `configure.ac:444-461`)
  amortizes small allocation cost in thread-local caches, further
  reducing the per-rehash cost vs the naive estimate.
- Meta-pattern #6 (aggregate worker time ÷ cluster count) applies:
  rehash work happens inside cluster workers, so the critical-path
  share is 1/8 of the per-ledger aggregate.
- This is a structural variant of fail/063-arena-allocate-txbundle-
  txeffects.md, which established that per-tx small-allocation
  elimination cannot reach Medium on soroswap-shaped workloads
  because the per-tx host-execution time (60–100 µs) dwarfs the
  allocator slice.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — not previously investigated for the specific
`mTxEntryMap` reserve target, but closely related to fail/063 (arena
allocation) and fail/088 (flatten point timer array).

### Why It Failed

Per-tx UnorderedMap rehash cost on a map growing from 0 to ~8 entries is
bounded at sub-millisecond per worker per ledger. After 8-way cluster
parallelism normalization, the critical-path saving is ~0.17% — three
orders of magnitude below the 3% Medium floor and well inside benchmark
noise. tcmalloc_minimal already amortizes the small-allocation cost
through its thread-local cache, further reducing the realistic saving.

### Lesson Learned

For per-tx small-container reserve hints on the parallel apply path, the
absolute ceiling is set by: `tx_count × rehashes_per_tx × per_rehash_ns
÷ cluster_count`. For soroswap (2000 × 3 × 500 ns ÷ 8) this is ~375 µs/
cluster/ledger ≈ 0.17%. Container reserve optimizations cannot reach
Medium severity on this workload without also addressing the dominant
per-tx host-execution time. Meta-pattern reinforced: small-allocation
elimination on the parallel-apply path is bounded by cluster parallelism
and tcmalloc thread-local cache efficiency, not by raw allocator-call
counts.
