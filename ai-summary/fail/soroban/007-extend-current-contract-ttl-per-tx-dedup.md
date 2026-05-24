# H007: Per-tx dedup of `extend_current_contract_instance_and_code_ttl`

**Date**: 2025-12-03
**Subsystem**: soroban (soroban-env-host p26)
**Severity**: Low (rejected: below objective Medium threshold)
**Impact**: redundant TTL extension work per Soroban host call
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When a single Soroban transaction invokes multiple host functions
against the same set of contract instances and code Wasms (e.g., a
soroswap router transaction that calls `swap` on a pair contract,
which in turn calls `transfer` on each token's SAC), the host SHOULD
extend the instance+code TTL **once per (contract, threshold,
extend_to)** tuple within a tx and skip subsequent extension calls
that would not actually change the on-ledger TTL.

The expected fast path: maintain a per-transaction set of
`(contract_id, code_hash, threshold, extend_to)` tuples already
extended; on a duplicate call, return immediately without re-touching
the TTL key, re-running the budget metering for hash recomputation, or
re-walking the storage map for the TTL entry.

## Mechanism

`extend_current_contract_instance_and_code_ttl` is observed at
**3.32% trace total / 2.07% self** with **15,770 calls** in the
soroswap trace. With ~28 txs/ledger × 71 ledgers = ~1988 txs and 8
calls per tx, this strongly suggests the function is invoked once per
host frame push for the active contract, even when the same contract
is re-entered repeatedly within a single tx (router→pair→SAC→pair→…).

Each call:
1. Resolves the `current contract` from the top frame.
2. Re-derives the instance TTL key and the code-hash TTL key.
3. Walks the host storage map (an `OrdMap`) for both keys.
4. Compares the existing TTL with `extend_to`.
5. Returns without mutation if no extension is needed.

Steps 2-4 dominate the self-time and are pure work even when the
extension is a no-op. The deviation from expected behavior: the
function repeats this work on every host-call frame, even for the
identical `(contract, code_hash, extend_to)` tuple already processed
earlier in the same tx.

## Trigger

Soroswap pair swap path: router→pair calls 1 swap; pair calls
2× SAC transfers; SAC transfers call out to balance/auth checks.
Multiple host-frame pushes within a single tx all hit
`extend_current_contract_instance_and_code_ttl`, deriving the same
keys and finding the same TTL.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs` —
  `extend_current_contract_instance_and_code_ttl` (search by name; in
  the lifecycle/TTL section)
- `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs` — TTL
  extension helpers
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs` — storage
  map TTL key lookup path

## Evidence

- 15,770 calls × 13,473ns mean = 212M ns = 2.07% trace self-time.
- Call count ratio (8/tx) matches expected router→pair→SAC nesting
  depth in soroswap workload.
- Per-tx dedup is a well-known idempotency pattern used elsewhere in
  the host (auth tracker, storage map).
- Function logic is a no-op past the first call within a tx (TTL is
  monotonic; once extended to `extend_to`, repeat calls cannot extend
  further).

## Anti-Evidence

- The function lives in `applySorobanStageClustersInParallel`
  (parallel apply). Effective parallelism = 4.18×, so 2.07% trace
  self-time × 0.239 = **0.49% wall apply impact** even if fully
  eliminated.
- Per-tx dedup state would need to be added to the host (or to a
  per-tx context), with its own setup/teardown cost.
- The TTL check itself is cheap (already a no-op past first call); the
  expensive part is the storage-map lookup, which would still need to
  happen at least once per tx anyway.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2025-12-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Parallel-normalized apply-time impact is below the objective Medium
threshold (3%):

1. **Parallel normalization caps the win.** The zone is inside
   `applySorobanStageClustersInParallel` (26.7% trace wall; 39.7s
   total CPU time across all threads, dividing by 9.5s wall yields
   effective parallelism = 4.18×). Multiplying the 2.07% trace
   self-time by 0.239 (wall/CPU ratio) gives **~0.49% apply-wall
   savings** as the absolute ceiling (full elimination). Realistic
   savings from dedup (40-60% of calls are redundant) drops to
   **~0.2-0.3% apply** — well below the 1% noise floor.

2. **Aligned with meta-pattern 16 / soroban-env success #2.** Prior
   success (`002-protocol-gated-host-metering-coalescing.md`) already
   coalesced host-side per-call metering charges from `charge` (17%
   self) down to ~1.43%. The same parallel-normalization argument that
   bounded `charge` cleanup to a tight Medium also bounds smaller-zone
   cleanups like TTL extension to sub-Low. The objective's meta-pattern
   16 explicitly notes "budget charge coalescing exhausted post-success
   #1"; the same exhaustion applies to per-call dedup at zones <3%
   trace self.

3. **Implementation cost vs benefit.** Per-tx dedup state requires
   either a `HashSet<(Hash, u32, u32)>` allocated per tx (introducing
   allocations into the hot path — meta-pattern 4) or a small inline
   cache on the host frame stack. Both add bookkeeping cost that eats
   into the already-tiny ~0.2-0.3% apply win.

4. **The "saved" work is largely no-op fast-path already.** Once a
   contract's instance TTL is extended to `extend_to`, the subsequent
   call returns after a single TTL-value comparison. The remaining
   work (storage map lookup) is bounded by `MeteredOrdMap` lookup
   speed, which is already optimized.

### Lesson Learned

Per-call dedup within a single tx for soroban-env-host zones must
clear two compounding deflators before it can be Medium-viable: (1)
parallel-apply effective-parallelism normalization (~4-5×) and (2)
the fast-path no-op fraction of the call. After both, any zone with
trace self-time <8% is structurally below the Medium floor regardless
of dedup quality. Future host-side hot-zone work should target either
the dispatch path itself (cross-cutting) or restructure the
per-frame work model, not localized per-call dedup.
