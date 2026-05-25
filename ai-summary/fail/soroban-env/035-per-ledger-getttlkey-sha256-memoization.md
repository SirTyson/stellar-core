# H035: Per-Ledger Memoize `getTTLKey` SHA256 Across Ingress + Egress

**Date**: 2026-05-25
**Subsystem**: soroban-env / transactions (InvokeHostFunctionOpFrame)
**Severity**: Low (projected sub-Medium after parallelism)
**Impact**: Avoid redundant SHA256 evaluation when the same LedgerKey is
TTL-hashed by multiple ops across a single ledger close
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The C++ apply path SHOULD compute `getTTLKey(lk) = sha256(xdr_to_opaque(lk))`
at most once per *unique* `LedgerKey` per ledger close, since the function is
pure (same input → same SHA256 output). Soroswap apply repeatedly hashes the
same small set of footprint keys (router contract code, pair instance, SAC
instance, contract code, balance entries) across thousands of TXs in one
ledger.

## Mechanism

`InvokeHostFunctionOpFrame::addReads`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:406`) calls
`getTTLKey(lk)` for every Soroban footprint entry in every op. The same path
calls `getTTLKey(rwKeys[j])` again inside the
`InvokeHostFunctionOpFrame::recordStorageChanges` inner loop (line 685) and a
final `getTTLKey(lk)` on every uncovered RW erase (line 761). Each SHA256 of
a `LedgerKey` (~80–200 bytes XDR) costs ~1.0–1.5 µs of pure CPU on the apply
critical path. Across a soroswap ledger with ~250 ops and ~5 Soroban
footprint entries per op, this is ~3,500–7,500 SHA256 evaluations per
ledger close, on the parallel-apply worker threads. The deviation from
expected behavior is that a small per-thread (or per-ledger) `LedgerKey →
Hash` cache could collapse these into a few dozen unique computations.

H033 (`033-cache-rwkey-ttl-hash-in-recordstoragechanges.md`) covered only
the per-op inner-loop subset. H035 broadens the scope to span ingress
(`addReads`) + egress (`recordStorageChanges`) + erase across the entire
ledger close.

## Trigger

Run the soroswap apply-load benchmark. Profile `sha256` callers and confirm
that `getTTLKey` accounts for a meaningful share of the apply-window SHA256
work. Add a per-thread `flat_hash_map<LedgerKey, Hash>` (or a small LRU
keyed on the hash of the XDR bytes) inside the parallel apply worker scope,
and reuse it across all ops in the cluster.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:406` — `getTTLKey(lk)` in `addReads`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:685` — `getTTLKey(rwKeys[j])` in `recordStorageChanges` inner loop
- `src/transactions/InvokeHostFunctionOpFrame.cpp:761` — `getTTLKey(lk)` for uncovered RW erase
- `src/transactions/TransactionUtils.cpp` — `getTTLKey` definition

## Evidence

- Trace `f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy` shows
  `sha256,crypto/SHA.cpp:33` at 712 ms aggregate self-time (497,544 events
  at ~1431 ns mean), and `add,crypto/SHA.cpp:65` at 314 ms (1.6M events).
  These include the apply-path `getTTLKey` callers.
- `recordStorageChanges` Tracy zone alone is 69.8 ms aggregate self-time
  (8,705 events at ~8,029 ns mean), much of which is the inner SHA256 loop
  that H033 already identified.
- `addReads` Tracy zone is 262 ms aggregate self-time (17,504 events at
  ~14,977 ns mean), a fraction of which is `getTTLKey` per Soroban entry.

## Anti-Evidence (and Self-Rejection)

After 8-way parallel-apply worker parallelism and dividing by ~70 ledgers
in the captured benchmark window:

| component | aggregate | per-ledger wall (÷8 workers) |
|-----------|-----------|------------------------------|
| addReads getTTLKey (~3 per op × 17.5K ops × ~1.5 µs) | ~80 ms | ~0.14 ms |
| recordStorageChanges inner SHA256 (H033 zone) | ~30–40 ms (subset of 69.8 ms) | ~0.06–0.07 ms |
| RW erase getTTLKey | <5 ms | <0.01 ms |
| **Total apply-path getTTLKey** | **~115–125 ms** | **~0.2–0.22 ms / ledger** |

Soroswap apply baseline is ~207 ms/ledger, so the maximum theoretical
saving is ~0.10–0.11% of apply time — three orders of magnitude below the
3% Medium floor and an order of magnitude below the 1% noise floor.

Furthermore, a behavior-preserving cache must replicate the SHA256 result
exactly; the implementation cost (per-thread allocator pressure, cache
allocation/teardown per cluster, LedgerKey hash function for the cache key
itself, cache-miss handling) typically claims 20–40% of the theoretical
saving, leaving an even smaller net win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — broader scope than H033, not previously investigated

### Why It Failed

Apply-path `getTTLKey` SHA256 contributes ~0.1% of apply wall-clock time
after 8-way worker parallelism. This is far below the 3% Medium floor and
below the 1% benchmark-noise floor, even under an unrealistically perfect
cache that eliminates 100% of repeated SHA256 calls. The same
parallel-worker normalization rule that rejected H033's per-op scope also
rejects H035's broader per-ledger scope.

### Lesson Learned

C++-side SHA256 micro-optimizations in the apply path consistently fall
below Medium after parallel-worker normalization. The combined apply-path
`getTTLKey` envelope (addReads + recordStorageChanges + RW erase) is
~120 ms aggregate / 8 workers / 70 ledgers ≈ 0.2 ms/ledger ≈ 0.1% of the
207 ms baseline — three orders of magnitude below the objective's Medium
threshold. Future SHA256-elimination hypotheses targeting the C++ apply
path must pre-quantify aggregate-ns × 1/parallelism × 1/ledger_count and
confirm the ceiling clears the Medium floor before promotion.
