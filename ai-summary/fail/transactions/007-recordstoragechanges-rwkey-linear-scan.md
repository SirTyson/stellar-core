# H007: Replace O(n*m) rwKey Linear Scan in recordStorageChanges with Hash Lookup

**Date**: 2026-05-22
**Subsystem**: transactions
**Severity**: Low
**Impact**: Per-tx parallel apply post-processing
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `InvokeHostFunctionApplyHelper::recordStorageChanges` (src/transactions/InvokeHostFunctionOpFrame.cpp:641) processes the host-returned `out.modified_ledger_entries`, it should map each modified entry to its position in the read-write footprint (`rwKeys`) in expected-amortized O(1) time per entry. Concretely, given M modified entries and N rwKeys, the matching pass should run in O(N + M) using a prebuilt `LedgerKey -> rwKey index` (and `TTLKey -> rwKey index`) hash map, not O(N * M).

## Mechanism

The current implementation at lines 672–695 executes a nested loop: for each entry in `out.modified_ledger_entries` (which contains both the modified ledger entries and their TTL siblings) it linearly scans the full `rwKeys` vector, doing both a `LedgerKey ==` comparison (XDR structural equality) and a `getTTLKey(rwKeys[j]) == lk` SHA256-based comparison for the TTL-pairing case. For a soroswap swap touching K rwKeys, each tx pays O(K * 2K) = O(K²) comparisons, of which the TTL-side requires a SHA256 hash. Hashing each rwKey once into a flat `unordered_map<LedgerKey, idx>` plus a `unordered_map<Hash, idx>` keyed by the TTL hash up front would reduce this to a single hash lookup per modified entry.

## Trigger

Run the soroswap apply-load benchmark; every Soroban tx executes `recordStorageChanges` once per operation. The cost is concentrated in the inner loop at lines 672–695.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-741` — `recordStorageChanges`
- `src/transactions/InvokeHostFunctionOpFrame.cpp:672-695` — the O(n*m) matching loop, including `getTTLKey(rwKeys[j])` SHA256 work in the TTL pairing branch
- `src/transactions/TransactionUtils.cpp` — `getTTLKey` (SHA256-keyed)

## Evidence

The Tracy zone `recordStorageChanges` (transactions/InvokeHostFunctionOpFrame.cpp:643) reports 101,190,837 ns total across 7000 calls in the current soroswap baseline trace (`2ff900fcd176-20260522-031343-02-soroswap-tx-2000-t-8.tracy`), mean 14,455 ns per call. Each call iterates modified entries against an O(|rwKeys|) inner loop including a SHA256-derived TTL key comparison.

## Anti-Evidence

The zone reports aggregate worker time. Dividing by T=8 cluster workers and 71 apply windows gives a critical-path cost of 101M / 8 / 71 ≈ 178 µs per ledger ≈ 0.07% of close time. Even completely eliminating the inner-loop matching work (which is impossible — at minimum, one hash lookup per modified entry remains) cannot reach the 1% Low floor, let alone the 3% Medium floor. The `getTTLKey` SHA256 call inside the inner branch is invoked only for TTL-typed entries (one per modified Soroban entry), and short-circuits as soon as both `matchedRwKey` and `relatedRwKey` are resolved, further bounding actual cost. The flat O(K²) is also negligible because soroswap footprints are tiny (K ≤ 6 rwKeys per swap), so the constant factor on K² is small in absolute terms.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; distinct from fail records 002-single-pass-ledger-change-map-diff (host-side `get_ledger_changes` extraction), 001-mutable-enforcing-storage-map-writes (storage map mutation), and the recent transaction-ledger fail 003-parallel-fold-commitchangesfromthreads.

### Why It Failed

The recordStorageChanges zone totals 101 ms aggregate worker time across the soroswap trace; the per-ledger critical-path cost (~178 µs/ledger after dividing by T=8 cluster parallelism and 71 ledger windows) is well below the 1% noise floor. The inner O(n*m) loop including the `getTTLKey` SHA256 call is real but its addressable share inside an already-small zone is negligible. Soroswap rwKey footprints are small (K ≤ 6), so the quadratic factor produces a small constant-time inner loop in practice. A hash-map-based replacement would itself pay per-tx setup cost (building two maps over K entries) that further erodes the savings.

### Lesson Learned

Apply Meta-Pattern 8 (Worker Aggregate Must Be Divided by Cluster Count) plus a footprint-size check before targeting quadratic loops in soroswap parallel-apply paths. When K (footprint size) is small and bounded — as it is for soroswap swaps — O(K²) inner loops are not a Medium-tier target even when they appear structurally suboptimal. Combine the parent zone's per-ledger critical-path bound with the inner-loop's share of that bound before proposing a replacement.
