# H052: Cache footprint TTL keys on `TransactionFrame` for cross-call reuse spanning serial setup + worker apply

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban apply call-site fan-out
**Severity**: Low
**Impact**: Sub-threshold — projected ≤ 1.5% apply-time (mixed serial + parallel)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban transaction, the footprint (read-only + read-write
`xdr::xvector<LedgerKey>`) is fixed at envelope-construction time. `getTTLKey(lk)`
— `SHA256(xdr_to_opaque(lk))` wrapped into a `LedgerKey` of type `TTL` — is
**deterministically derivable** from each footprint entry and never changes for
the lifetime of the `TransactionFrame`. The expected efficient path is to
compute the TTL key for each footprint entry **once at `TransactionFrame`
construction time** (or lazily on first access, memoized on the frame), and
have every downstream call site reuse that precomputed value:
`collectClusterFootprintEntriesFromGlobal` (serial, main thread),
`flushRoTTLBumpsInTxWriteFootprint` (worker), `addReads` (worker),
and the TTL-match inner loop in `recordStorageChanges` (worker).

## Mechanism

Today, `getTTLKey(lk)` is recomputed at every call site for every footprint
entry of every transaction:

- `ParallelApplyUtils.cpp:980` — per-footprint, per-tx, serial on main thread,
  inside `collectClusterFootprintEntriesFromGlobal`
- `ParallelApplyUtils.cpp:1017` — per RW footprint key, per tx, on worker,
  inside `flushRoTTLBumpsInTxWriteFootprint`
- `InvokeHostFunctionOpFrame.cpp:406` — per footprint key, per tx, on worker,
  inside `addReads`
- `InvokeHostFunctionOpFrame.cpp:685` — per RW key per modified-output entry,
  worker, inside the `recordStorageChanges` O(N×M) TTL-match loop

Each call performs `xdr::xdr_to_opaque(lk)` (allocates `std::vector<uint8_t>`,
serializes a small `LedgerKey`) and then `SHA256(bytes)` of that opaque blob.
For a soroswap tx with ~8 footprint keys touched at ~4 distinct sites, this
recomputes ~32 identical TTL keys. Memoizing on `TransactionFrame` (e.g., a
`mutable std::vector<LedgerKey> mFootprintTtlKeys` indexed parallel to the
footprint vectors, populated on first request) eliminates all but the first
SHA256 per footprint key, including the *serial main-thread* portion in
`collectClusterFootprintEntriesFromGlobal`.

This differs from existing fails:
- `fail/transaction-ledger/004-recordstoragechanges-on2-ttlmatch-loop.md` —
  only the inner loop in `recordStorageChanges`, narrower scope.
- `fail/transaction-ledger/005-ttl-key-memoization-shared-ro.md` — cross-cluster
  shared-RO entries via a separate global memo table; specifically did not
  cover the per-frame cross-call-site cache that also includes the serial
  main-thread `collectClusterFootprintEntriesFromGlobal` path.

## Trigger

Run the current soroswap apply-load benchmark
(`ai-summary/CURRENT_STATE.md`). Each ledger close enters
`collectClusterFootprintEntriesFromGlobal` on the main apply thread (serial
across ~250 txs per cluster), then each worker enters `addReads`,
`flushRoTTLBumpsInTxWriteFootprint`, and `recordStorageChanges` per tx.

## Target Code

- `src/transactions/TransactionFrame.h` — add `mutable std::vector<LedgerKey>` (or `std::vector<std::optional<Hash>>`) member for memoized TTL keys
- `src/transactions/TransactionFrame.cpp` — populate lazily, thread-safe (per-tx, after construction it is read-mostly)
- `src/transactions/ParallelApplyUtils.cpp:980` (`collectClusterFootprintEntriesFromGlobal`) — read precomputed TTL key
- `src/transactions/ParallelApplyUtils.cpp:1017` (`flushRoTTLBumpsInTxWriteFootprint`) — read precomputed TTL key
- `src/transactions/InvokeHostFunctionOpFrame.cpp:406` (`addReads`) — read precomputed TTL key
- `src/transactions/InvokeHostFunctionOpFrame.cpp:685` (`recordStorageChanges`) — read precomputed TTL key
- `src/ledger/LedgerTypeUtils.cpp` `getTTLKey()` — unchanged, still used for first compute

## Evidence

- Soroswap median apply time is 272 ms; the four call sites each recompute
  identical TTL keys per footprint entry per tx.
- `sha256` self-time aggregate (`crypto/SHA.cpp`) in the current Tracy trace
  is 647 ms aggregate across all sources (TX-set, validation, apply); the
  apply-window share is a fraction but non-zero.
- The serial portion in `collectClusterFootprintEntriesFromGlobal` runs on
  the main thread and is on the critical path before workers can start.

## Anti-Evidence

- Rough sizing: ~250 txs × 8 footprint keys × 4 sites = 8,000 `getTTLKey`
  invocations per ledger. SHA256 over a ~30-byte LedgerKey opaque blob plus
  `xdr_to_opaque` allocation is on the order of 1 µs per call. Total
  ~8 ms aggregate cost per ledger. The main-thread serial portion
  (`collectClusterFootprintEntriesFromGlobal`) is ~1/4 of this (~2 ms
  serial), and the remaining ~6 ms is divided across 8 parallel cluster
  workers (~0.75 ms each). Critical-path savings cap at roughly 2 ms (serial)
  + 0.75 ms (parallel) ≈ 2.75 ms/ledger ≈ ~1.0% of 272 ms.
- Prior fail `005-ttl-key-memoization-shared-ro.md` already concluded the
  total `getTTLKey` budget is ≤1% of soroswap apply time, with realistic
  savings well below the Low floor; per-frame memoization spans more call
  sites but cannot break that ceiling because the underlying SHA256 work
  is structurally cheap.
- Adding a `mutable std::vector` to `TransactionFrame` adds per-frame
  resident memory for cached TTL keys (~32 B per key × 8 keys × 250 txs ×
  multiple in-flight ledgers ≈ low hundreds of KB) — small but real cache
  pressure, similar to the regression observed in
  `fail/transaction-ledger/001-cache-serialized-soroban-entries-in-memory-state.md`
  where in-memory caches add L1/L2 pressure that offsets savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H004 (narrow recordStorageChanges loop) and
H005 (cross-cluster shared-RO memo); this targets per-frame cross-call-site
caching including the serial main-thread setup. The savings ceiling, however,
is bounded by the same `getTTLKey` total budget already documented in H005.

### Why It Failed

The total SHA256 + `xdr_to_opaque` budget for all `getTTLKey` invocations
across all four call sites is bounded at ~8 ms aggregate per ledger
(~250 txs × 8 footprint keys × ~4 call sites × ~1 µs each). After splitting
into the ~2 ms serial main-thread portion and ~6 ms aggregate parallel
worker portion (which divides to ~0.75 ms per cluster on the critical path),
the realized critical-path saving caps at ≈2.75 ms/ledger — about 1% of the
272 ms soroswap baseline, below the objective's 1% noise floor and far
below the 3% Medium threshold. The hypothesis is technically novel (per-frame
cache spanning both serial and parallel call sites) but cannot escape the
structural ceiling already established by H005. Per the objective's severity
scale, "Low" (1–3%) is not accepted at the hypothesis stage; only Medium
(3–10%) and High (>10%) qualify, and this hypothesis projects below even
the Low floor on the critical path.

### Lesson Learned

Per-frame memoization of cheap deterministic key derivations
(`getTTLKey`, `xdr_size`, etc.) is bounded by the underlying call's per-op
cost × call sites × tx count, and for SHA256-of-small-opaque the ceiling
sits around 1% of apply time even when all call sites are unified. Future
hypotheses around `getTTLKey` reuse must target a structural change that
reduces footprint size, eliminates entire call sites, or removes the need
for TTL key derivation in a sub-pass — not just cache the result.
