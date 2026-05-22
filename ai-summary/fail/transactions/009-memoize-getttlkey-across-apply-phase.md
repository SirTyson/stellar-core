# H009: Memoize getTTLKey SHA256 Hashes Per-Tx Across the Apply Phase

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-key SHA256 + XDR-to-opaque allocation in soroban footprint paths
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a single ledger close, the SHA256-derived TTL key for each Soroban
footprint `LedgerKey` is a pure function of that key. The minimum
work behavior is to compute the TTL key (XDR-serialize the key, hash
it) exactly once per distinct key per apply phase, then reuse the
cached `LedgerKey` for every subsequent lookup. Soroban entries in a
soroswap ledger are touched repeatedly:

1. `GlobalParallelApplyLedgerState` constructor / `addRoToInMemorySorobanState`
   (pre-loads RO TTLs).
2. `ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal`
   (serial cluster setup; calls `getTTLKey` per footprint key per tx).
3. `addReads` (`transactions/InvokeHostFunctionOpFrame.cpp:406`) — per
   tx, per footprint key, per op (RO+RW), called in workers.
4. `recordStorageChanges` matching loop
   (`transactions/InvokeHostFunctionOpFrame.cpp:670-695`) — calls
   `getTTLKey(rwKeys[j])` in the inner pairing branch.
5. `commitChangesFromThreads` → `commitChangeFromThread` for RO TTL bumps.

In an ideal scheme, each distinct `LedgerKey` would hash exactly once
per ledger and the result would be reused across all five call sites
above.

## Mechanism

Actual behavior: `getTTLKey` (`ledger/LedgerTypeUtils.cpp:31-38`)
performs `xdr::xdr_to_opaque(e)` (heap-allocates a serialized byte
vector) plus `sha256(...)` for every call. There is no per-tx,
per-cluster, or per-ledger cache. The same RW footprint key is
hashed once during cluster setup, again during `addReads` worker
execution, and a third time during `recordStorageChanges` matching;
RO footprint keys repeat the same pattern across multiple txs in the
same cluster.

Deviation: the apply path re-hashes the same `LedgerKey` multiple
times per ledger when a per-tx (or per-cluster) memo could make it
once. The work is small per call but multiplied by ~28 txs × ~10
footprint keys × 71 ledgers.

## Trigger

Run the soroswap apply-load benchmark; every Soroban tx repeats
TTL hashing across the cluster setup, worker `addReads`, and
`recordStorageChanges` paths described above.

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:31-38` — `getTTLKey` (the hot
  XDR-encode + SHA256 site).
- `src/transactions/ParallelApplyUtils.cpp:925-986` —
  `collectClusterFootprintEntriesFromGlobal`, the serial cluster
  setup callsite.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:404-438,670-695` —
  worker `addReads` + `recordStorageChanges` callsites.
- `src/transactions/ParallelApplyUtils.cpp:893-922` —
  `commitChangesFromThread` for RO TTL bump merge.

## Evidence

- Tracy `sha256` zone (`crypto/SHA.cpp:33`): 696,889,327 ns
  aggregate across 485,316 calls, mean 1,435 ns. A subset of these
  calls are `getTTLKey` SHA256 hashes (the rest are signature
  hashing, tx content hashing, etc.).
- For 71 ledgers, 28 txs/ledger, 10 footprint keys per tx (5
  soroban), and the call sites above, a conservative count is
  ~140 setup-thread hashes + ~280 worker hashes + ~100 recordChange
  hashes per ledger = ~520 hashes/ledger.
- Per-call cost ≈ 1.4 µs (mean from Tracy `sha256` zone) so the
  per-ledger aggregate TTL-hash work is roughly
  520 × 1.4 µs ≈ 0.73 ms/ledger.

## Anti-Evidence

- Worker hashes (~280/ledger × 1.4 µs ≈ 0.39 ms aggregate) are
  divided by T=8 cluster parallelism per Meta-Pattern 8; the
  critical-path worker savings are ~0.05 ms/ledger.
- Apply-thread (setup + commit) hashes are at most ~0.34 ms/ledger.
- Combined apply-critical-path savings ≈ 0.39 ms/ledger ≈ 0.6% of
  apply-time (`applyLedger` ≈ 64 ms/ledger). This is below the
  1% noise floor and far below the 3% Medium floor.
- Implementing a per-ledger TTL-key memo also pays a cost: an
  `unordered_map<LedgerKey, LedgerKey>` insert per first computation,
  plus a `LedgerKey ==` probe on every subsequent lookup. For
  small soroswap footprints the lookup overhead can wash out the
  hashing savings entirely.
- Prior fail records 005 (skip-xdrsize-for-inmemory-soroban-addreads),
  006 (fuse-ttl-and-entry-lookup-in-addreads), 007
  (recordstoragechanges-rwkey-linear-scan), 011
  (precompute-rwkey-ttl-hashes-in-recordstoragechanges), and
  Meta-Pattern 8 collectively bound `getTTLKey`-adjacent
  optimizations far below the Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — distinct from prior fails which each address one
single call site (addReads TTL fusion, recordStorageChanges rwKey
linear scan, precompute rwkey TTL hashes). This hypothesis explicitly
covers a full-apply-phase memo across all five call sites combined.

### Why It Failed

Combined apply-critical-path TTL-hash work is ≈ 0.6% of apply-time,
below the 1% noise floor and far below the 3% Medium severity floor.
Even with a perfect zero-cost memo, the savings cannot reach
Medium. The per-ledger TTL-hash budget is genuinely small because:
(1) worker hashes parallelize across T=8 clusters, shrinking the
critical-path slice by 8×; (2) cluster setup hashes only touch
footprint keys, not modified-entry TTL hashes; (3) a memo data
structure adds its own per-lookup cost that erodes the savings.
This is the same pattern Meta-Patterns 4 and 8 describe.

### Lesson Learned

Apply-path SHA256 work attributable to `getTTLKey` is distributed
across worker and apply-thread sites, but is bounded under 1% of
apply-time even when summed across all sites. Future TTL-hash
optimization hypotheses must isolate a single dominant call site
inside a Medium-tier parent zone before proposing a memo; "memo
across all sites" cannot clear Medium because the parent zones
themselves are already sub-Medium individually.
