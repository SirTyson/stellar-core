# H037: Hash-Map-Accelerated O(1) rwKey Matching in `recordStorageChanges`

**Date**: 2026-05-25
**Subsystem**: soroban-env / transactions (InvokeHostFunctionOpFrame write-side)
**Severity**: Low (sub-Medium; below benchmark noise after parallelism)
**Impact**: Replace the O(R × E) nested loop in `recordStorageChanges`
(R = readWrite footprint size, E = host-returned modified entries) with a
two-key `flat_hash_map<Hash, size_t>` keyed on (a) `LedgerKey` hash and
(b) `getTTLKey(rwKeys[j]).ttl().keyHash`, built once in `addReads` and
consumed in `recordStorageChanges`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::recordStorageChanges`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:641-767`) should match
each post-invoke output entry to its originating readWrite-footprint slot
in amortized O(1) per output, with at most one SHA256 per readWrite key
across the whole operation. The match keys (the `LedgerKey` itself and
its corresponding TTL `keyHash`) are fully known when the footprint is
first walked in `addReads`, so a precomputed two-key index built there
and reused here yields the lower-bound work. Today the inner loop
re-walks the readWrite footprint linearly and recomputes
`getTTLKey(rwKeys[j])` for every TTL output, which is O(R × E) work
with an inner SHA256 per iteration.

## Mechanism

In `recordStorageChanges`, the per-output match loop
(`InvokeHostFunctionOpFrame.cpp:672-695`) does:

```cpp
for (size_t j = 0; j < rwKeys.size(); ++j)
{
    bool directMatch = rwKeys[j] == lk;
    if (directMatch) { ... }
    else if (lk.type() == TTL && isSorobanEntry(rwKeys[j]) &&
             getTTLKey(rwKeys[j]) == lk)
    {
        relatedRwKey = j;
    }
    ...
}
```

For every TTL output entry (typically one TTL output per modified
Soroban data entry — ~2-4 per op in the soroswap workload), the
`getTTLKey(rwKeys[j])` SHA256-of-XDR-bytes is recomputed for each
readWrite key probed until a match is found. With R ≈ 6-10 readWrite
keys and E ≈ 5-10 outputs per op, the inner loop performs
~R × E ≈ 30-100 iterations and ~R × W ≈ 12-40 SHA256s per op (W =
TTL outputs).

The deviation from expected behavior is that all needed match data is
deterministic at `addReads` time: the readWrite footprint is fixed for
the op, and TTL keyHashes are pure functions of the readWrite
`LedgerKey`s. A single precomputed `flat_hash_map<Hash, size_t>`
indexed by `xxhash(LedgerKey-bytes)` plus a second
`flat_hash_map<Hash, size_t>` indexed by `getTTLKey(rwKey).ttl().keyHash`
would give O(1) match per output and amortize the SHA256 work to one
call per readWrite key per op (matching the H033 lower bound).

This is distinct from H033 (`033-cache-rwkey-ttl-hash-in-recordstoragechanges.md`)
which only caches the SHA256 results across iterations within a single
op call; H037 additionally eliminates the inner linear scan over
`rwKeys` and shares the precomputed index with the unmatched-key erase
loop at line 751-765 (which also walks all rwKeys checking coverage).

## Trigger

Run the soroswap apply-load benchmark
(`scripts/run_apply_load_matrix.py`, soroswap TX=2000 T=8). Every
Soroban invoke that mutates persistent storage executes
`recordStorageChanges` with R ≈ 6-10 and E ≈ 5-10. Instrument
`recordStorageChanges` to count inner-loop iterations and `getTTLKey`
calls per op; expect ~6,000-12,000 SHA256s and ~50,000-100,000 inner
iterations per ledger.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:380-535` — `addReads`
  (build the precomputed key→index hash maps here).
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` —
  `recordStorageChanges` (consume the maps in the per-output match
  loop and the unmatched-key erase loop).
- `src/transactions/InvokeHostFunctionOpFrame.h` — add the two
  `flat_hash_map<Hash, size_t>` members alongside `mRwKeyExisted`.
- `src/ledger/LedgerTypeUtils.cpp:24-38` — `getTTLKey` SHA256 producer
  whose calls would be amortized.

## Evidence

- Source inspection confirms the O(R × E) nested loop and per-iteration
  `getTTLKey(rwKeys[j])` SHA256 (`InvokeHostFunctionOpFrame.cpp:684-685`).
- Trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`:
  `recordStorageChanges` 69,896,221 ns self / 8,705 events
  (~8.03 µs mean per op). `sha256,crypto/SHA.cpp:33` 712 ms / 497,544
  events (the recordStorageChanges share is a small fraction; most is
  contract-execution `Bytes::sha256`).
- The unmatched-key erase loop at line 751-765 also walks all rwKeys
  and would benefit from the precomputed coverage map; it
  additionally calls `getTTLKey(lk)` at line 761 once per uncovered
  rwKey, which the index could provide directly.

## Anti-Evidence (and Self-Rejection)

Quantifying the ceiling:

| component | aggregate | per-ledger wall (÷8 workers) | % of 207 ms |
|-----------|-----------|------------------------------|-------------|
| Inner-loop SHA256 elimination (H033 scope) | ~3,000 calls/ledger × 200 ns | ~55 µs/ledger ÷ 8 ≈ 7 µs | ~0.003% |
| Inner-loop iteration removal (R × E → 1) | ~50,000 iters/ledger × ~10 ns/iter (compare + branch) | ~500 µs/ledger ÷ 8 ≈ 63 µs | ~0.03% |
| Erase-loop coverage scan removal | ~10,000 iters/ledger × ~5 ns | ~50 µs/ledger ÷ 8 ≈ 6 µs | ~0.003% |
| Erase-loop `getTTLKey` amortization (rare; only on uncovered keys) | ~few/ledger × 1.5 µs | negligible | <0.001% |
| **Total** | | **~75-80 µs/ledger** | **~0.04%** |

The implementation overhead (per-op allocation of two
`flat_hash_map<Hash, size_t>` instances, computing the LedgerKey hash
+ TTL keyHash for each rwKey to populate the maps, hash-table probe
overhead for lookups) typically reclaims 30-50% of the theoretical
saving for footprints this small (R ≈ 6-10). Net wall-clock impact:
~40 µs/ledger ≈ 0.02% — two orders of magnitude below the 1%
benchmark-noise floor and 150× below the 3% Medium threshold.

The dominant cost of `recordStorageChanges` is the per-output
`xdr_from_opaque(buf.data, le)` deserialization at line 657 (mandatory
to recover the typed `LedgerEntry` from the host's emitted XDR
buffer) and the subsequent `upsertLedgerEntry(lk, le)` apply work at
line 720. These are unaffected by index-based matching and dominate
the 8 µs mean per call. The match-loop residual is at most a small
fraction of that 8 µs.

Per Meta-Pattern 14 in `summary.md`: per-op micro-optimizations
consistently fall below 0.1% wall-clock after 8-way parallelism on
the soroswap workload. This proposal sits firmly in that regime.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H033 (which caches per-iteration
SHA256 but keeps the linear scan) and from H035 (which proposes
per-ledger memoization across ops). H037 is the within-op two-key
hash-map index variant; not previously enumerated.

### Why It Failed

The full envelope of the proposed change — eliminating the inner SHA256
loop, the O(R × E) linear scan, and the erase-loop coverage scan —
is bounded by ~80 µs/ledger of serial work, which after 8-way parallel
apply normalization is ~10 µs/ledger or ~0.005% of the 207 ms soroswap
baseline. This is 600× below the 3% Medium threshold and 200× below
the 1% benchmark-noise floor. The dominant cost of
`recordStorageChanges` (per-output XDR deserialization and
`upsertLedgerEntry`) is untouched by the change.

Per the objective context ("Findings below 1% (within benchmark noise)
are not valid; do not produce slop PRs that don't actually improve
performance") and the established meta-pattern that per-op
bookkeeping micro-optimizations cannot clear the severity floor on
this workload, this proposal is below the objective severity bar at
the hypothesis stage.

### Lesson Learned

For C++ apply-path write-side bookkeeping loops, the saving ceiling
is `R × E × per_iter_ns × ops_per_ledger / parallelism / 1000` ms.
With R ≈ 8, E ≈ 8, per_iter ≈ 10 ns, ops ≈ 250/ledger, parallelism =
8: `8 × 8 × 10 × 250 / 8 / 1000 = 2 µs/ledger ≈ 0.001%`. Even adding
the inner-SHA256 cost (~40 µs/ledger), the total saving ceiling is
sub-0.1% wall-clock. Future "replace inner linear scan with hash map"
hypotheses targeting per-op footprint sizes need to first multiply
`R × E × per_iter × ops / parallelism` and confirm the ceiling clears
1% before promotion.
